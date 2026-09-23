// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/digimaks/idauth/clientattestation"
	"github.com/digimaks/idauth/routes/request"
	"github.com/digimaks/idauth/routes/response"
	"github.com/digimaks/idauth/svcerrors"
	"go.uber.org/zap"

	"azugo.io/azugo"
	"azugo.io/core/http"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/lx-lib/lx-idauth"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
)

func HandleAuthorization(ctx *azugo.Context, idauth *idauth.IDAuth, store *Store, sessionTimeout time.Duration, auditInterface audit.Audit, jkt string, attest *clientattestation.Verifier) {
	var clientID string

	wia := ctx.Header.Get("OAuth-Client-Attestation")

	// attested is true only for the WIA/attest_jwt_client_auth path, where
	// the authenticated client IS the wallet instance that started the
	// /authorize request, so the code-to-client binding check below is
	// meaningful. Confidential clients (e.g. the wallet backend acting as
	// a BFF) legitimately redeem codes issued to a different client_id
	// than the one they authenticate as, so that check does not apply to
	// the Basic-auth branch.
	attested := wia != ""

	if wia != "" {
		// Public wallet client: attest_jwt_client_auth
		// (draft-ietf-oauth-attestation-based-client-auth).
		if attest == nil {
			svcerrors.SetHeader(ctx, svcerrors.AuthCodeInvalidClient)
			ctx.StatusCode(fasthttp.StatusUnauthorized)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_client",
				Description: "client attestation not supported",
			})

			return
		}

		res, err := attest.Verify(ctx, wia, ctx.Header.Get("OAuth-Client-Attestation-PoP"))
		if err != nil {
			svcerrors.SetHeader(ctx, svcerrors.AuthCodeInvalidClient)
			ctx.StatusCode(fasthttp.StatusUnauthorized)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_client",
				Description: "invalid client attestation",
			})

			return
		}

		// HAIP: attested wallet clients always get sender-constrained tokens.
		if jkt == "" {
			svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofMissing)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_dpop_proof",
				Description: "DPoP proof required for attested clients",
			})

			return
		}

		// WIA cnf/DPoP binding, rolled back in TS3 v1.5.2 — opt-in, off by default.
		if attest.RequireKeyBinding() && jkt != res.CnfJKT {
			svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofInvalid)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_dpop_proof",
				Description: "DPoP key does not match attested wallet key",
			})

			return
		}

		clientID = res.ClientID
	} else {
		// Confidential client: HTTP Basic auth.
		authHeader := ctx.Header.Get("Authorization")

		if authHeader == "" {
			svcerrors.SetHeader(ctx, svcerrors.AuthCodeMissingAuthHeader)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON("missing authorization header")

			return
		}

		// Decode the Basic Auth header
		decoded, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
		if err != nil {
			ctx.Error(pkerrors.NewProblem("err:token:authHeaderInvalid"))

			return
		}

		// Extract clientID and secret
		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			ctx.Error(pkerrors.NewProblem("err:token:authHeaderInvalid"))

			return
		}

		basicClientID, secret := credentials[0], credentials[1]

		client, err := idauth.Clients().GetClient(basicClientID)
		if err != nil {
			ctx.Log().Error("failed to look up client", zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:token:clientLookupFailed"))

			return
		}

		if client == nil || !slices.Contains(client.Secrets, secret) {
			svcerrors.SetHeader(ctx, svcerrors.AuthCodeInvalidClient)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON("invalid client")

			return
		}

		if client.Metadata["token_binding"] == "dpop" && jkt == "" {
			svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofMissing)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_dpop_proof",
				Description: "client requires DPoP-bound tokens",
			})

			return
		}

		clientID = basicClientID
	}

	req := &request.TokenRequest{}

	req.GrantType, _ = ctx.Form.String("grant_type")
	req.Code, _ = ctx.Form.String("code")
	req.CodeVerifier, _ = ctx.Form.String("code_verifier")
	req.RedirectURI, _ = ctx.Form.String("redirect_uri")

	// validate code verifier and get info from code
	tempData, err := store.GetItem(ctx, req.Code, req.CodeVerifier)
	if err != nil {
		svcerrors.SetHeader(ctx, svcerrors.AuthCodeInvalidOrExpiredCode)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: err.Error(),
		})

		return
	}

	if tempData.RedirectURI != req.RedirectURI {
		svcerrors.SetHeader(ctx, svcerrors.AuthCodeRedirectURIMismatch)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "redirect_uri mismatch",
		})

		return
	}

	// Verify the code was issued to the authenticated client — only
	// enforced for attested wallet instances (see the `attested` comment
	// above); confidential BFF-style clients may redeem on behalf of a
	// different client_id than the one used at /authorize.
	if attested && tempData.ClientID != clientID {
		svcerrors.SetHeader(ctx, svcerrors.AuthCodeInvalidClient)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "code was not issued to this client",
		})

		return
	}

	now := time.Now().UTC()
	tempData.Session.ID = ulid.Make().String()
	tempData.Session.LastAccessed = &now

	tokenType := "Bearer"

	if jkt != "" {
		tokenType = "DPoP"

		if tempData.Session.Metadata == nil {
			tempData.Session.Metadata = map[string]string{}
		}

		tempData.Session.Metadata["dpop_jkt"] = jkt
	}

	sess, err := idauth.Session().Create(ctx, &tempData.Session)
	if err != nil {
		ctx.Log().Error("failed to create session", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:sessionCreateFailed"))

		return
	}

	endpoint := ctx.RouterPath()
	ip := ctx.IP().String()
	userAgent := ctx.UserAgent()

	auditRequest := audit.AuditRequest{
		ClientID: "idauth",
		Endpoint: &endpoint,
		Action:   string(audit.ActionLoginSuccess),
		Person: &audit.Person{
			GivenName:  &tempData.Session.FirstName,
			FamilyName: &tempData.Session.LastName,
			Identifier: &tempData.UserID,
		},
		IPAddress: &ip,
		UserAgent: &userAgent,
	}

	err = auditInterface.PersonRequest(ctx, auditRequest, http.WithHeader(fasthttp.HeaderAuthorization, "Bearer "+sess.ID))
	if err != nil {
		// Audit failure is non-fatal: the session has already been created
		// and the token must be returned to the client. Log and continue.
		ctx.Log().Error("failed to record audit event", zap.Error(err))
	}

	// Only delete the temp session; log but do not abort if it is already gone
	if delErr := idauth.Session().Delete(ctx, req.Code); delErr != nil {
		ctx.Log().Warn("temp session cleanup skipped (authcode flow)", zap.Error(delErr))
	}

	err = store.DeleteItem(ctx, req.Code)
	if err != nil {
		ctx.Log().Error("failed to clean up authorization code", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:cleanupFailed"))

		return
	}

	var refreshToken string

	if tokenType == "DPoP" {
		rt, rtErr := store.IssueRefreshToken(ctx, RefreshTokenItem{
			ClientID: clientID,
			Scope:    tempData.Scope,
			JKT:      jkt,
			Session:  tempData.Session,
		})
		if rtErr != nil {
			// Non-fatal: the access token is already valid and must still
			// be returned. The wallet will simply need to re-authenticate
			// via /authorizationV3 once this access token expires instead
			// of silently refreshing.
			ctx.Log().Error("failed to issue refresh token", zap.Error(rtErr))
		} else {
			refreshToken = rt
		}
	}

	ctx.JSON(&response.TokenResponse{
		AccessToken:  sess.ID,
		TokenType:    tokenType,
		ExpiresIn:    core.GetSecondsToLive(sessionTimeout, sess.LastAccessed),
		Scope:        tempData.Scope,
		RefreshToken: refreshToken,
	})
}

// HandleRefreshToken implements grant_type=refresh_token: validates a
// fresh DPoP proof from the same key the refresh token was bound to,
// rotates the token, and mints a new access token/session.
func HandleRefreshToken(ctx *azugo.Context, idauthClient *idauth.IDAuth, store *Store, sessionTimeout time.Duration, jkt string) {
	if jkt == "" {
		svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofMissing)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&response.TokenResponseError{
			Type:        "invalid_dpop_proof",
			Description: "DPoP proof required for the refresh_token grant",
		})

		return
	}

	refreshToken, err := ctx.Form.String("refresh_token")
	if err != nil || refreshToken == "" {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&response.TokenResponseError{
			Type:        "invalid_request",
			Description: "refresh_token is required",
		})

		return
	}

	item, err := store.RedeemRefreshToken(ctx, refreshToken)
	if err != nil {
		svcerrors.SetHeader(ctx, svcerrors.RefreshTokenInvalidOrExpired)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&response.TokenResponseError{
			Type:        "invalid_grant",
			Description: "invalid or expired refresh_token",
		})

		return
	}

	if item.JKT != jkt {
		svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofInvalid)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&response.TokenResponseError{
			Type:        "invalid_dpop_proof",
			Description: "DPoP key does not match the key this refresh_token was bound to",
		})

		return
	}

	now := time.Now().UTC()
	sess := item.Session
	sess.ID = ulid.Make().String()
	sess.LastAccessed = &now

	if sess.Metadata == nil {
		sess.Metadata = map[string]string{}
	}

	sess.Metadata["dpop_jkt"] = jkt

	newSess, err := idauthClient.Session().Create(ctx, &sess)
	if err != nil {
		ctx.Log().Error("failed to create session for refresh_token grant", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:sessionCreateFailed"))

		return
	}

	newRefreshToken, err := store.IssueRefreshToken(ctx, RefreshTokenItem{
		ClientID: item.ClientID,
		Scope:    item.Scope,
		JKT:      jkt,
		Session:  item.Session,
	})
	if err != nil {
		// Non-fatal: the new access token is already valid. The wallet
		// will need to re-authenticate once it expires instead of
		// silently refreshing again.
		ctx.Log().Error("failed to rotate refresh token", zap.Error(err))
	}

	ctx.JSON(&response.TokenResponse{
		AccessToken:  newSess.ID,
		TokenType:    "DPoP",
		ExpiresIn:    core.GetSecondsToLive(sessionTimeout, newSess.LastAccessed),
		Scope:        item.Scope,
		RefreshToken: newRefreshToken,
	})
}

func HandlePreAuthorized(ctx *azugo.Context, idauth *idauth.IDAuth, store *Store, sessionTimeout time.Duration, jkt string, attest *clientattestation.Verifier, requireAttestation bool) {
	wia := ctx.Header.Get("OAuth-Client-Attestation")

	if wia == "" && requireAttestation {
		svcerrors.SetHeader(ctx, svcerrors.PreAuthAttestationRequired)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&response.TokenResponseError{
			Type:        "invalid_client",
			Description: "client attestation is required",
		})

		return
	}

	if wia != "" {
		// Public wallet client: attest_jwt_client_auth
		// (draft-ietf-oauth-attestation-based-client-auth). Mirrors the
		// authorization_code branch in HandleAuthorization: verify-if-present
		// today, enforced once requireAttestation is flipped on. Unlike that
		// branch, this grant is public (no client authentication), so
		// attestation failures are reported as invalid_request-style 400s
		// rather than 401.
		if attest == nil {
			svcerrors.SetHeader(ctx, svcerrors.PreAuthInvalidClient)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_client",
				Description: "client attestation not supported",
			})

			return
		}

		res, err := attest.Verify(ctx, wia, ctx.Header.Get("OAuth-Client-Attestation-PoP"))
		if err != nil {
			svcerrors.SetHeader(ctx, svcerrors.PreAuthInvalidClient)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_client",
				Description: "invalid client attestation",
			})

			return
		}

		// HAIP: attested wallet clients always get sender-constrained tokens.
		if jkt == "" {
			svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofMissing)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_dpop_proof",
				Description: "DPoP proof required for attested clients",
			})

			return
		}

		// WIA cnf/DPoP binding, rolled back in TS3 v1.5.2 — opt-in, off by default.
		if attest.RequireKeyBinding() && jkt != res.CnfJKT {
			svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofInvalid)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_dpop_proof",
				Description: "DPoP key does not match attested wallet key",
			})

			return
		}
	}

	preAuthCode, err := ctx.Form.String("pre-authorized_code")
	if err != nil || preAuthCode == "" {
		ctx.Error(pkerrors.NewProblem("err:session:preAuthCodeMissing",
			pkerrors.WithDetail("pre-authorized_code is required")))

		return
	}

	txCodeStr, _ := ctx.Form.String("tx_code")

	// Look up the pre-auth item
	item, err := store.GetPreAuthItem(ctx, preAuthCode)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:preAuthCodeInvalidOrExpired",
			pkerrors.WithDetail("Invalid or expired pre-authorized code")))

		return
	}

	// Validate tx_code unless the pre-auth code was issued without one
	// (offer generated with no_tx_code — test/dev flow).
	if !item.NoTXCode {
		if !store.ValidateTXCode(ctx, preAuthCode, txCodeStr) {
			ctx.Error(pkerrors.NewProblem("err:session:preAuthTXCodeInvalid",
				pkerrors.WithDetail("Invalid transaction code")))

			return
		}

		_ = store.DeleteTXCode(ctx, preAuthCode)
	}

	if clientID := ctx.Form.StringOptional("client_id"); clientID != nil && *clientID != "" && jkt == "" {
		if client, err := idauth.Clients().GetClient(*clientID); err == nil && client != nil &&
			client.Metadata["token_binding"] == "dpop" {
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(&response.TokenResponseError{
				Type:        "invalid_dpop_proof",
				Description: "client requires DPoP-bound tokens",
			})

			return
		}
	}

	// Build session
	now := time.Now().UTC()
	item.Session.ID = ulid.Make().String()
	item.Session.LastAccessed = &now

	tokenType := "Bearer"

	if jkt != "" {
		tokenType = "DPoP"

		if item.Session.Metadata == nil {
			item.Session.Metadata = map[string]string{}
		}

		item.Session.Metadata["dpop_jkt"] = jkt
	}

	sess, err := idauth.Session().Create(ctx, &item.Session)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:session:preAuthSessionCreateFailed",
			pkerrors.WithDetail("Failed to create session")))

		return
	}

	_ = store.DeleteItem(ctx, preAuthCode)

	// Build authorization_details if the token request included them (spec §6.2)
	var authDetails []map[string]interface{}

	if rawAD := ctx.Form.StringOptional("authorization_details"); rawAD != nil && *rawAD != "" {
		var requested []map[string]interface{}
		if json.Unmarshal([]byte(*rawAD), &requested) == nil {
			for _, ad := range requested {
				if adType, ok := ad["type"].(string); ok && adType == "openid_credential" {
					credConfID, _ := ad["credential_configuration_id"].(string)
					credIdentifier := item.Session.Subject + ":" + credConfID
					authDetails = append(authDetails, map[string]interface{}{
						"type":                        "openid_credential",
						"credential_configuration_id": credConfID,
						"credential_identifiers":      []string{credIdentifier},
					})
				}
			}
		}
	}

	resp := map[string]interface{}{
		"access_token": sess.ID,
		"token_type":   tokenType,
		"expires_in":   core.GetSecondsToLive(sessionTimeout, sess.LastAccessed),
		"scope":        item.Scope,
	}
	if len(authDetails) > 0 {
		resp["authorization_details"] = authDetails
	}

	ctx.JSON(resp)
}
