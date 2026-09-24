// SPDX-License-Identifier: EUPL-1.2

package smartid

import (
	"errors"
	"log"
	"path"
	"strings"
	"time"

	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/templates"

	"azugo.io/azugo"
	"azugo.io/azugo/token/nonce"
	"azugo.io/core/cache"
	"azugo.io/core/http"
	"azugo.io/templ"
	"github.com/lx-lib/lx-idauth"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/oklog/ulid/v2"
	"github.com/proDeveloperGuru/smartid"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

const (
	callbackPath = "/callback/smartid"
	loginPath    = "/smartid/login"
	verifyPath   = "/smartid/verifier"
)

const (
	Running  = "RUNNING"
	Complete = "COMPLETE"
	Canceled = "CANCELED"
)

type Metadata struct {
	RelayingPartyUUID string
	RelayingPartyName string
}

type SessionInfo struct {
	Code      string
	PK        string
	Country   string
	SessionID string
}

type Inst struct {
	idauth        *idauth.IDAuth
	client        smartid.Client
	config        *Configuration
	nonce         nonce.Store
	audit         audit.Audit
	authCodeStore *authorizationcode.Store
}

func Bind(app *azugo.App, auth *idauth.IDAuth, config *Configuration, audit audit.Audit, authCodeStore *authorizationcode.Store) (*Inst, error) {
	st, err := cache.Create[bool](app.Cache(), "smartid-nonce", cache.DefaultTTL(10*time.Minute))
	if err != nil {
		return nil, err
	}

	client := smartid.NewClient().
		WithRelyingPartyName(config.RelyingPartyName).
		WithRelyingPartyUUID(config.RelyingPartyUUID).
		WithCertificateLevel(config.CertificateLevel).
		WithHashType(config.HashType).
		WithInteractionType(config.InteractionType).
		WithDisplayText60(config.Text).
		WithURL(config.Endpoint)

	if err := client.Validate(); err != nil {
		log.Fatal("Invalid configuration:", err)
	}

	i := &Inst{
		client:        client,
		idauth:        auth,
		config:        config,
		nonce:         nonce.NewCacheNonceStore(st),
		audit:         audit,
		authCodeStore: authCodeStore,
	}

	auth.Register("smartid", i)

	return i, nil
}

func (i *Inst) Authorize(ctx *azugo.Context, sess *core.Correlation) error {
	verifyURL := path.Join(ctx.BasePath(), verifyPath)
	loginURL := path.Join(ctx.BasePath(), loginPath)

	callbackURL := path.Join(ctx.BasePath(), callbackPath)

	err := authorizationcode.ValidateAndSaveState(ctx, sess.ClientID, i.idauth.Clients(), i.authCodeStore, *sess.State)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrInvalidRequest)

		return err
	}

	templ.Render(ctx, templates.GenerateLogin(loginURL, verifyURL, callbackURL, i.config.PresentRetries, i.config.PresentWaitInSeconds))

	return nil
}

type LoginRequest struct {
	CountryCode      string `json:"countryCode"`
	PersonIdentifier string `json:"personIdentifier"`
}

type Response struct {
	Message   string `json:"message"`
	ErrorCode string `json:"errorCode"`
}

func (i *Inst) Login(ctx *azugo.Context) {
	req := &LoginRequest{}
	if err := ctx.Body.JSON(req); err != nil {
		ctx.Log().Error("Error parsing request:", zap.Error(err))
		ctx.JSON(Response{
			Message:   "Error parsing request" + err.Error(),
			ErrorCode: i.GetErrorCodes("parse error"),
		})
		ctx.StatusCode(fasthttp.StatusBadRequest)

		return
	}

	p := strings.ReplaceAll(req.PersonIdentifier, " ", "")

	for _, r := range p {
		if (r < '0' || r > '9') && r != '-' {
			ctx.Log().Warn("Invalid Latvian person identifier (non-digit characters)", zap.String("personIdentifier", maskPersonIdentifier(req.PersonIdentifier, 6)))
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(Response{
				Message:   "invalid person identifier",
				ErrorCode: i.GetErrorCodes("invalid person identifier"),
			})

			return
		}
	}

	if req.CountryCode == "LV" && !strings.Contains(p, "-") && len(p) == 11 {
		// accept identifiers like "12345611111" and convert to "123456-11111"
		req.PersonIdentifier = p[:6] + "-" + p[6:]
	}

	if len(req.PersonIdentifier) != 12 {
		ctx.Log().Warn("Invalid Latvian person identifier (wrong length)", zap.String("personIdentifier", maskPersonIdentifier(req.PersonIdentifier, 6)))
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(Response{
			Message:   "invalid Latvian person identifier, expected 11 digits",
			ErrorCode: i.GetErrorCodes("wrong length"),
		})

		return
	}

	identity := smartid.NewIdentity(smartid.TypePNO, req.CountryCode, req.PersonIdentifier)

	i.client.WithTimeout(time.Duration(i.config.CreateSessionTimeoutInSeconds) * time.Second)

	session, err := i.client.CreateSession(ctx, identity)
	if err != nil {
		ctx.Log().Error("Error creating session:", zap.Error(err))
		ctx.JSON(Response{
			Message:   err.Error(),
			ErrorCode: i.GetErrorCodes(err.Error()),
		})
		ctx.StatusCode(fasthttp.StatusBadRequest)

		return
	}

	// save presentID and session id

	ctx.Log().Info("session created", zap.String("sessionID", session.Id), zap.String("code", session.Code))

	ctx.StatusCode(fasthttp.StatusOK)
	ctx.JSON(session)
}

func (i *Inst) Verified(ctx *azugo.Context) {
	sessionID := ctx.Params.String("sessionID")

	i.client.WithTimeout(time.Duration(i.config.CheckSessionTimeoutInSeconds) * time.Second)

	person, err := i.client.FetchSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, smartid.ErrTimeout) ||
			errors.Is(err, smartid.ErrUserRefused) ||
			errors.Is(err, smartid.ErrSmartIdNoSuitableAccount) {
			ctx.Log().Error("unknown error code from wallet", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(Response{
				Message:   err.Error(),
				ErrorCode: i.GetErrorCodes(err.Error()),
			})

			return
		}

		if errors.Is(err, smartid.ErrSmartIdMaintenance) {
			ctx.Log().Error("unknown error code from wallet", zap.Error(err))
			ctx.StatusCode(fasthttp.StatusInternalServerError)
			ctx.JSON(Response{
				Message:   err.Error(),
				ErrorCode: i.GetErrorCodes(err.Error()),
			})

			return
		}

		ctx.StatusCode(fasthttp.StatusNoContent)
		ctx.JSON(Response{
			Message:   err.Error(),
			ErrorCode: i.GetErrorCodes(err.Error()),
		})

		return
	}

	if person == nil {
		ctx.StatusCode(fasthttp.StatusNoContent)

		return
	}

	ctx.StatusCode(fasthttp.StatusOK)
}

func (i *Inst) GetErrorCodes(message string) string {
	switch message {
	// local errors
	case "parse error":
		return "invalid_request"
	case "invalid person identifier":
		return "invalid_identifier"
	case "wrong length":
		return "invalid_length"
	// smart id responses
	case "authentication is still running":
		return "waiting_response"
	case "no suitable account of requested type found":
		return "no_account_found"
	case "system is under maintenance, retry again later":
		return "maintenance"
	case "user refused":
		return "user_refused"
	case "user didn't respond in time":
		return "user_did_not_response_in_time"
	default:
		return "server_error"
	}
}

func (i *Inst) Callback(ctx *azugo.Context, sess *core.Correlation) (*core.AuthRequest, error) {
	sessionID, err := ctx.Query.String("sessionID")
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, errors.New(sess.ErrorCode)
	}

	person, err := i.client.FetchSession(ctx, sessionID)
	if err != nil {
		code := auth.AuthErrCode(i.GetErrorCodes(err.Error()))

		ctx.Log().Warn("smart-id session fetch failed on callback",
			zap.String("sessionID", sessionID),
			zap.Error(err))

		sess.ErrorCode = string(code)

		return nil, &auth.AuthorizeError{Code: code}
	}

	if person == nil {
		ctx.Log().Error("smart-id session fetch returned no person data",
			zap.String("sessionID", sessionID))

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, &auth.AuthorizeError{Code: auth.AuthErrInvalidCallback}
	}

	userData := convertToUserData(*person)

	stateItem, _ := i.authCodeStore.PopState(ctx, *sess.State)
	if stateItem != nil && stateItem.ResponseType == "code" {
		callbackRes, err := authorizationcode.Callback(ctx, i.authCodeStore, *sess, *userData, *stateItem, nil)
		if err != nil {
			sess.ErrorCode = string(auth.AuthErrInvalidCallback)

			return nil, err
		}

		sess.ManagedByProvider = true

		return callbackRes, nil
	}

	if sess.ID == "" {
		sess.ID = ulid.Make().String()
	}

	now := time.Now().UTC()
	roles := []*core.RoleEntity{
		{
			ID:   "person",
			Code: "person",
			Name: "Person",
		},
	}

	_, err = i.idauth.Session().Create(ctx, &core.Session{
		ID:        sess.ID,
		Subject:   userData.UserID,
		FirstName: userData.FirstName,
		LastName:  userData.LastName,
		Rights: []*core.GrantedRightListEntity{
			{
				RoleID:    roles[0].ID,
				RightCode: "citizen",
			},
		},
		Code:         userData.PersonCode,
		LastAccessed: &now,
		State:        string(core.SessionStateAuthorized),
		Role:         roles[0],
		Roles:        roles,
	})
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, err
	}

	endpoint := ctx.RouterPath()
	ip := ctx.IP().String()
	userAgent := ctx.UserAgent()

	request := audit.AuditRequest{
		ClientID: "idauth",
		Endpoint: &endpoint,
		Action:   string(audit.ActionLoginSuccess),
		Person: &audit.Person{
			GivenName:  &userData.FirstName,
			FamilyName: &userData.LastName,
			Identifier: &userData.PersonCode,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
	}

	err = i.audit.PersonRequest(ctx, request, http.WithHeader(fasthttp.HeaderAuthorization, "Bearer "+sess.ID))
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrServer)

		return nil, err
	}

	sess.ManagedByProvider = true

	return nil, nil
}

// Helper extracted from the inline anonymous function to improve readability and reuse.
func maskPersonIdentifier(s string, maskDigits int) string {
	r := []rune(s)
	count := 0

	for i := len(r) - 1; i >= 0 && count < maskDigits; i-- {
		if r[i] >= '0' && r[i] <= '9' {
			r[i] = '*'
			count++
		}
	}

	return string(r)
}

func convertToUserData(person smartid.Person) *core.UserData {
	return &core.UserData{
		UserID:     person.IdentityNumber,
		PersonCode: person.PersonalCode,
		FirstName:  person.FirstName,
		LastName:   person.LastName,
	}
}
