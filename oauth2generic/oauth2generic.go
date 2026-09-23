// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/digimaks/idauth/authorizationcode"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/lx-lib/lx-idauth"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const callbackPathPrefix = "/callback/"

// extraClaimsMetadataKey is the core.Session.Metadata key holding the
// JSON-encoded raw userinfo claims not covered by ClaimFieldMap, for the
// interactive-login path (see Callback). Consumed by
// routes.buildIntrospectionResponse.
const extraClaimsMetadataKey = "extra_claims"

type inst struct {
	idauth         *idauth.IDAuth
	config         *ClientConfig
	audit          audit.Audit
	authCodeStore  *authorizationcode.Store
	providerConfig *core.AuthProviderConfig
	oauth2Config   oauth2.Config
	acrValues      string
}

// Bind registers a config-driven OAuth2 (non-OIDC) provider under
// providerConfig.ID, following the same auth.Register(id, provider) pattern
// idauth/eparaksts and idauth/smartid already use. acrValues is sent as-is
// on the authorize redirect when non-empty (empty for a client's base
// entry, set for each of its Variants — see idauth/auth.go and
// idauth/routes/router.go for how callers resolve which value to pass).
func Bind(app *azugo.App, auth *idauth.IDAuth, config *ClientConfig, providerConfig *core.AuthProviderConfig, acrValues string, auditClient audit.Audit, authCodeStore *authorizationcode.Store) error {
	if err := validateClaimFieldMap(config.ClaimFieldMap); err != nil {
		return err
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
			// AuthStyleAutoDetect doesn't reliably land on Basic auth for an
			// arbitrary token endpoint, and eParaksts's real server rejects
			// anything else ("Basic authentication required") — matching
			// what eparaksts/token.go used to send by hand
			// (base64(client_id:client_secret) in the Authorization header).
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	if config.Scope != "" {
		oauth2Config.Scopes = []string{config.Scope}
	}

	i := &inst{
		idauth:         auth,
		config:         config,
		audit:          auditClient,
		authCodeStore:  authCodeStore,
		providerConfig: providerConfig,
		oauth2Config:   oauth2Config,
		acrValues:      acrValues,
	}

	auth.Register(providerConfig.ID, i)

	return nil
}

// Authorize mirrors lx-idauth's OidcAuthProvider.Authorize: cor.State is
// used directly as the OAuth2 state param, no separate nonce store needed.
// ValidateAndSaveState mirrors eparaksts.Authorize: it is a no-op unless the
// current request is the OID4VCI pre-authorized_code flow's authorization
// leg (response_type=code), in which case it validates PKCE/redirect_uri
// and stashes the state for Callback to pick up via PopState.
func (i *inst) Authorize(ctx *azugo.Context, cor *core.Correlation) error {
	if err := authorizationcode.ValidateAndSaveState(ctx, cor.ClientID, i.idauth.Clients(), i.authCodeStore, *cor.State); err != nil {
		return err
	}

	i.oauth2Config.RedirectURL = ctx.BaseURL() + callbackPathPrefix + i.providerConfig.ID
	ctx.RedirectUnsafe(buildAuthorizeURL(i.oauth2Config, *cor.State, i.acrValues, i.config.Prompt, i.config.UILocales))

	return nil
}

// callbackErrorCode maps the IdP's error= query param to a structured
// AuthErrCode, mirroring eparaksts.Callback: access_denied is the only
// error code an IdP conventionally sends for a user-facing "denied"
// outcome, everything else is logged and treated as a malformed callback.
func callbackErrorCode(authError string) auth.AuthErrCode {
	if authError == "access_denied" {
		return auth.AuthErrNoRights
	}

	return auth.AuthErrInvalidCallback
}

// buildAuthorizeURL always sends acr_values, even empty — eparaksts.go's
// own Authorize does the same (url.Values always carries the key,
// Realm == "" for its base, non-variant entries), and eParaksts's real IdP
// rejects a request where acr_values is missing entirely ("Invalid
// acr_values"), not just one where it's empty. All three params go through
// oauth2.SetAuthURLParam for proper percent-encoding — matching what
// eparaksts.go's url.Values.Encode() already does in production, rather
// than the raw, unencoded string-append this used to do. Extracted as its
// own function so it's testable without an azugo.Context.
func buildAuthorizeURL(cfg oauth2.Config, state, acrValues, prompt, uiLocales string) string {
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("acr_values", acrValues)}

	if prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
	}

	if uiLocales != "" {
		opts = append(opts, oauth2.SetAuthURLParam("ui_locales", uiLocales))
	}

	return cfg.AuthCodeURL(state, opts...)
}

// Callback exchanges the authorization code and fetches userinfo, then
// either hands off to the OID4VCI pre-authorized_code flow (when the
// current state matches a pending response_type=code request, mirroring
// eparaksts.Callback) or creates an interactive session directly — bypassing
// lx-idauth's generic UserData path, which has no field to carry raw claims
// through to core.Session, so RawClaims would otherwise be dropped before
// reaching /introspection.
func (i *inst) Callback(ctx *azugo.Context, cor *core.Correlation) (*core.AuthRequest, error) {
	// Mirrors eparaksts.Callback: the IdP redirects back with error=... on
	// denial/failure instead of code, and never sends both.
	if authError, _ := ctx.Query.String("error"); authError != "" {
		errorCode := callbackErrorCode(authError)
		cor.ErrorCode = string(errorCode)

		if errorCode == auth.AuthErrInvalidCallback {
			ctx.Log().Error("unknown error code from oauth2generic provider",
				zap.String("provider", i.providerConfig.ID), zap.String("error", authError))
		}

		return nil, errors.New(cor.ErrorCode)
	}

	code, err := ctx.Query.String("code")
	if err != nil {
		cor.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, err
	}

	i.oauth2Config.RedirectURL = ctx.BaseURL() + callbackPathPrefix + i.providerConfig.ID

	req, err := i.exchangeAndFetchUserInfo(ctx, code)
	if err != nil {
		cor.ErrorCode = string(auth.AuthErrInvalidCallback)

		return nil, err
	}

	// ponytail: no "user_id" claim target exists in ClaimFieldMap today, so
	// UserID defaults to PersonCode. Add a target if a provider needs the
	// two to differ (e.g. eParaksts's SerialNumber vs. cleaned PersonCode).
	userData := &core.UserData{
		UserID:     req.PersonCode,
		PersonCode: req.PersonCode,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Email:      req.Email,
	}

	if stateItem, _ := i.authCodeStore.PopState(ctx, *cor.State); stateItem != nil && stateItem.ResponseType == "code" {
		callbackRes, err := authorizationcode.Callback(ctx, i.authCodeStore, *cor, *userData, *stateItem, req.RawClaims)
		if err != nil {
			cor.ErrorCode = string(auth.AuthErrInvalidCallback)

			return nil, err
		}

		cor.ManagedByProvider = true

		return callbackRes, nil
	}

	// AuthErrServer covers both a session-store failure and an audit-log
	// failure here (createSession does both) — eparaksts.Callback splits
	// these into AuthErrInvalidCallback vs AuthErrServer respectively; not
	// worth the extra error path for what's an internal-failure case either way.
	if err := i.createSession(ctx, cor, userData, req.RawClaims); err != nil {
		cor.ErrorCode = string(auth.AuthErrServer)

		return nil, err
	}

	cor.ManagedByProvider = true

	return nil, nil
}

func (i *inst) createSession(ctx *azugo.Context, cor *core.Correlation, userData *core.UserData, rawClaims map[string]any) error {
	if cor.ID == "" {
		cor.ID = ulid.Make().String()
	}

	metadata := map[string]string{}

	if len(rawClaims) > 0 {
		encoded, err := json.Marshal(rawClaims)
		if err != nil {
			return err
		}

		metadata[extraClaimsMetadataKey] = string(encoded)
	}

	now := time.Now().UTC()
	role := &core.RoleEntity{ID: "person", Code: "person", Name: "Person"}

	_, err := i.idauth.Session().Create(ctx, &core.Session{
		ID:        cor.ID,
		Subject:   userData.UserID,
		FirstName: userData.FirstName,
		LastName:  userData.LastName,
		Code:      userData.PersonCode,
		Rights: []*core.GrantedRightListEntity{
			{RoleID: role.ID, RightCode: "citizen"},
		},
		LastAccessed: &now,
		State:        string(core.SessionStateAuthorized),
		Role:         role,
		Roles:        []*core.RoleEntity{role},
		Metadata:     metadata,
	})
	if err != nil {
		return err
	}

	endpoint := ctx.RouterPath()
	ip := ctx.IP().String()
	userAgent := ctx.UserAgent()

	return i.audit.PersonRequest(ctx, audit.AuditRequest{
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
	}, http.WithHeader(fasthttp.HeaderAuthorization, "Bearer "+cor.ID))
}

func (i *inst) exchangeAndFetchUserInfo(ctx context.Context, code string) (*core.AuthRequest, error) {
	token, err := i.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	claims, err := i.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}

	return mapClaims(claims, i.config.ClaimFieldMap), nil
}

func (i *inst) fetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	client := http.NewClient(http.Context(ctx), http.BaseURL(i.config.UserInfoURL))

	buf, err := client.Get(
		"",
		http.WithHeader(fasthttp.HeaderAuthorization, "Bearer "+accessToken),
	)
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(buf, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}
