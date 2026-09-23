// SPDX-License-Identifier: EUPL-1.2

package edim

import (
	"errors"
	"net/url"
	"path"
	"time"

	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/templates"
	idauth "github.com/lx-lib/lx-idauth"

	"azugo.io/azugo"
	"azugo.io/azugo/token/nonce"
	"azugo.io/core/http"
	"azugo.io/templ"
	"github.com/digimaks/go-verifier"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

const (
	callbackPath = "/callback/edim"
	verifyPath   = "/edim/verifier"

	// SameDeviceReturnPath is where the wallet redirects the browser back to
	// once a same_device presentation completes (tx + response_code query
	// params) - registered as a standalone route (routes/router.go), bypassing
	// the generic /callback/{id} dispatcher.
	SameDeviceReturnPath = "/edim/verifier/same-device/return"

	sameDeviceProviderID = "edim:same_device"

	// sameDeviceMetadataKey is the core.Client.Metadata key that opts a client
	// into the edim:same_device flow (mirrors the existing token_binding:dpop
	// convention, testdata/clients.yaml).
	sameDeviceMetadataKey = "same_device"

	// pidNamespace is the credential doctype/vct the verifier template requests
	// PID claims under.
	pidNamespace = "eu.europa.ec.eudi.pid.1"
)

type Inst struct {
	idauth         *idauth.IDAuth
	config         *verifier.Configuration
	nonce          nonce.Store
	audit          audit.Audit
	verifier       *verifier.Inst
	authCodeStore  *authorizationcode.Store
	providerConfig *core.AuthProviderConfig
}

// Bind registers one provider variant ("edim" or "edim:same_device", per
// providerConfig.ID) against a shared verifierInst - callers register both
// variants against the same verifierInst since a single *verifier.Inst
// already dispatches cross_device and same_device flows fine. Only the
// first ("edim") call should create the nonce cache; nonce is currently
// unused by Inst's own methods, so subsequent registrations pass a nil
// nonce.Store rather than double-registering the "edim-nonce" cache name.
func Bind(auth *idauth.IDAuth, verifierInst *verifier.Inst, config *verifier.Configuration, providerConfig *core.AuthProviderConfig, nonceStore nonce.Store, audit audit.Audit, authCodeStore *authorizationcode.Store) (*Inst, error) {
	i := &Inst{
		idauth:         auth,
		config:         config,
		nonce:          nonceStore,
		audit:          audit,
		verifier:       verifierInst,
		authCodeStore:  authCodeStore,
		providerConfig: providerConfig,
	}

	auth.Register(providerConfig.ID, i)

	return i, nil
}

func (i *Inst) Authorize(ctx *azugo.Context, sess *core.Correlation) error {
	if i.providerConfig.ID == sameDeviceProviderID {
		return i.authorizeSameDevice(ctx, sess)
	}

	return i.authorizeCrossDevice(ctx, sess)
}

func (i *Inst) authorizeCrossDevice(ctx *azugo.Context, sess *core.Correlation) error {
	offer, err := i.verifier.GenerateOffer(ctx, verifier.OfferRequest{Flow: "cross_device"})
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrServer)

		return err
	}

	verifyURL := path.Join(ctx.BasePath(), verifyPath, offer.TransactionID)
	queryParams := &url.Values{}

	err = authorizationcode.ValidateAndSaveState(ctx, sess.ClientID, i.idauth.Clients(), i.authCodeStore, *sess.State)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrInvalidRequest)

		return err
	}

	queryParams.Add("transaction_id", offer.TransactionID)
	callbackURL := path.Join(ctx.BasePath(), callbackPath) + "?" + queryParams.Encode()

	templ.Render(ctx, templates.GenerateCredentialOffer(offer.Link, verifyURL, callbackURL, i.config.V1.PresentRetries, i.config.V1.PresentWaitInSeconds))

	return nil
}

// clientAllowsSameDevice reports whether client has opted into the
// edim:same_device flow via its metadata bag (metadata: {same_device: "true"}).
func clientAllowsSameDevice(client *core.Client) bool {
	return client != nil && client.Metadata[sameDeviceMetadataKey] == "true"
}

func (i *Inst) authorizeSameDevice(ctx *azugo.Context, sess *core.Correlation) error {
	client, err := i.idauth.Clients().GetClient(sess.ClientID)
	if err != nil || !clientAllowsSameDevice(client) {
		sess.ErrorCode = string(auth.AuthErrInvalidRequest)

		return errors.New("client is not enabled for the edim:same_device flow")
	}

	err = authorizationcode.ValidateAndSaveState(ctx, sess.ClientID, i.idauth.Clients(), i.authCodeStore, *sess.State)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrInvalidRequest)

		return err
	}

	returnURL, err := url.JoinPath(ctx.BaseURL(), SameDeviceReturnPath)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrServer)

		return err
	}

	sessCopy := *sess

	offer, err := i.verifier.GenerateSameDeviceOffer(ctx, returnURL, &sessCopy)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrServer)

		return err
	}

	ctx.RedirectUnsafe(offer.Link)

	return nil
}

// SameDeviceReturn completes the edim:same_device flow: the wallet's own
// browser redirect lands here (not on the generic /callback/edim route)
// carrying a one-time tx/response_code pair, so this bypasses the library's
// generic callback dispatcher and finishes the OAuth redirect itself via
// idauth.RedirectToCaller.
func (i *Inst) SameDeviceReturn(ctx *azugo.Context) {
	var tx, responseCode string
	if v := ctx.Query.StringOptional("tx"); v != nil {
		tx = *v
	}

	if v := ctx.Query.StringOptional("response_code"); v != nil {
		responseCode = *v
	}

	sessionID, data, attrs, err := i.verifier.HandleWalletReturn(ctx, tx, responseCode)

	sess, ok := data.(*core.Correlation)
	if !ok || sess == nil {
		ctx.Log().Error("same-device return: unknown or expired tx, cannot redirect to caller", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusBadRequest)

		return
	}

	// The generic /callback/{id} dispatcher normally assigns sess.ID before
	// calling a provider's Callback (it becomes the authorization code both in
	// AuthCodeItem and in RedirectToCaller's final redirect); since this route
	// bypasses that dispatcher entirely, do the same assignment ourselves.
	if sess.ID == "" {
		sess.ID = ulid.Make().String()
	}

	if err != nil {
		ctx.Log().Error("same-device return: failed to redeem wallet response", zap.String("sessionID", sessionID), zap.Error(err))

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		_ = i.idauth.RedirectToCaller(ctx, sess)

		return
	}

	token, err := convertToUserData(attrs)
	if err != nil {
		ctx.Log().Error("same-device return: failed to convert attestation to user data", zap.String("sessionID", sessionID), zap.Error(err))

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		_ = i.idauth.RedirectToCaller(ctx, sess)

		return
	}

	_, _ = i.completeCallback(ctx, sess, sessionID, token)

	_ = i.idauth.RedirectToCaller(ctx, sess)
}

func (i *Inst) Verified(ctx *azugo.Context) {
	presentID := ctx.Params.String("presentID")

	status, err := i.verifier.Status(ctx, presentID)
	if err != nil {
		ctx.Log().Error("unknown error code from wallet", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusBadRequest)

		return
	}

	switch status {
	case "failed_attestation":
		ctx.StatusCode(fasthttp.StatusBadRequest)
	case "failed_wallet":
		ctx.StatusCode(fasthttp.StatusBadRequest)
	case "wallet_scanned":
		ctx.StatusCode(fasthttp.StatusAccepted)
	case "success_wallet":
		ctx.StatusCode(fasthttp.StatusOK)
	case "initialized":
		ctx.StatusCode(fasthttp.StatusNoContent)
	default:
		ctx.StatusCode(fasthttp.StatusNoContent)
	}
}

func (i *Inst) Callback(ctx *azugo.Context, sess *core.Correlation) (*core.AuthRequest, error) {
	presentID, err := ctx.Query.String("transaction_id")
	if err != nil {
		ctx.Log().Error("Missing presentID parameter in callback",
			zap.String("sessionID", sess.ID),
			zap.Error(err))

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, errors.New(sess.ErrorCode)
	}

	ctx.Log().Info("Processing EDIM callback",
		zap.String("presentID", presentID),
		zap.String("sessionID", sess.ID))

	attrs, err := i.verifier.Attributes(ctx, presentID)
	if err != nil {
		ctx.Log().Error("Failed to get attributes from verifier backend",
			zap.String("presentID", presentID),
			zap.String("sessionID", sess.ID),
			zap.Error(err))

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		status, statusErr := i.verifier.Status(ctx, presentID)
		if statusErr != nil {
			ctx.Log().Error("Could not get status",
				zap.String("presentID", presentID),
				zap.Error(statusErr))
		}

		return nil, &auth.AuthorizeError{Code: auth.AuthErrCode(status)}
	}

	ctx.Log().Info("Successfully retrieved attributes",
		zap.String("presentID", presentID),
		zap.Int("attributeCount", len(attrs)))

	token, err := convertToUserData(attrs)
	if err != nil {
		ctx.Log().Error("Failed to convert attestation to user data",
			zap.String("presentID", presentID),
			zap.String("sessionID", sess.ID),
			zap.Error(err))

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, err
	}

	return i.completeCallback(ctx, sess, presentID, token)
}

func (i *Inst) completeCallback(ctx *azugo.Context, sess *core.Correlation, presentID string, token *core.UserData) (*core.AuthRequest, error) {
	ctx.Log().Info("Successfully converted attestation to user data",
		zap.String("presentID", presentID),
		zap.String("userID", token.UserID),
		zap.String("firstName", token.FirstName),
		zap.String("lastName", token.LastName))

	stateItem, _ := i.authCodeStore.PopState(ctx, *sess.State)
	if stateItem != nil && stateItem.ResponseType == "code" {
		ctx.Log().Info("Processing authorization code flow",
			zap.String("presentID", presentID),
			zap.String("responseType", stateItem.ResponseType))

		callbackRes, err := authorizationcode.Callback(ctx, i.authCodeStore, *sess, *token, *stateItem, nil)
		if err != nil {
			ctx.Log().Error("Authorization code callback failed",
				zap.String("presentID", presentID),
				zap.String("sessionID", sess.ID),
				zap.Error(err))

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

	ctx.Log().Info("Creating new session",
		zap.String("presentID", presentID),
		zap.String("sessionID", sess.ID),
		zap.String("userID", token.UserID))

	_, err := i.idauth.Session().Create(ctx, &core.Session{
		ID:        sess.ID,
		Subject:   token.UserID,
		FirstName: token.FirstName,
		LastName:  token.LastName,
		Rights: []*core.GrantedRightListEntity{
			{
				RoleID:    roles[0].ID,
				RightCode: "citizen",
			},
		},
		Code:         token.PersonCode,
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
			GivenName:  &token.FirstName,
			FamilyName: &token.LastName,
			Identifier: &token.PersonCode,
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

func convertToUserData(attrs []verifier.Attribute) (*core.UserData, error) {
	values := make(map[string]string, len(attrs))

	for _, a := range attrs {
		if a.Namespace != pidNamespace {
			continue
		}

		if s, ok := a.Value.(string); ok {
			values[a.Key] = s
		}
	}

	personalNumber := values["personal_administrative_number"]
	if personalNumber == "" {
		return nil, errors.New("personal_administrative_number not found or empty")
	}

	givenName := values["given_name"]
	if givenName == "" {
		return nil, errors.New("given_name not found or empty")
	}

	familyName := values["family_name"]
	if familyName == "" {
		return nil, errors.New("family_name not found or empty")
	}

	return &core.UserData{
		UserID:     personalNumber,
		PersonCode: personalNumber,
		FirstName:  givenName,
		LastName:   familyName,
	}, nil
}
