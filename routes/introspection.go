// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/digimaks/idauth/svcerrors"

	"azugo.io/azugo"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

func (r *router) introspection(ctx *azugo.Context) {
	ctx.Header.Set("Cache-Control", "no-store")

	if authHeader := ctx.Header.Get("Authorization"); isBasicAuthScheme(authHeader) {
		clientID, secret, ok := parseBasicAuth(authHeader)
		if !ok {
			svcerrors.SetHeader(ctx, svcerrors.IntrospectionInvalidClient)
			ctx.StatusCode(fasthttp.StatusUnauthorized)
			ctx.JSON(map[string]string{"error": "invalid_client"})

			return
		}

		client, err := r.IDAuth().Clients().GetClient(clientID)
		if err != nil || client == nil || !slices.Contains(client.Secrets, secret) {
			svcerrors.SetHeader(ctx, svcerrors.IntrospectionInvalidClient)
			ctx.StatusCode(fasthttp.StatusUnauthorized)
			ctx.JSON(map[string]string{"error": "invalid_client"})

			return
		}
	} else if r.Config().RequireIntrospectionAuth {
		svcerrors.SetHeader(ctx, svcerrors.IntrospectionAuthRequired)
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		ctx.JSON(map[string]string{"error": "invalid_client", "error_description": "client authentication required"})

		return
	}

	token, err := ctx.Form.String("token")
	if err != nil || token == "" {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(map[string]string{"error": "invalid_request", "error_description": "token is required"})

		return
	}

	sess, err := r.IDAuth().Session().GetSessionByID(ctx, token)
	if err != nil {
		ctx.Log().Warn("introspection session lookup failed", zap.Error(err))
		ctx.JSON(map[string]bool{"active": false})

		return
	}

	if sess == nil {
		ctx.Log().Warn("introspection session not found", zap.Int("length", len(token)))
		ctx.JSON(map[string]bool{"active": false})

		return
	}

	if !sess.IsActive() {
		ctx.Log().Warn("introspection session inactive", zap.String("state", sess.State), zap.String("ID", sess.ID))
		ctx.JSON(map[string]bool{"active": false})

		return
	}

	ctx.JSON(buildIntrospectionResponse(sess, r.Config().IdauthPublicURL, r.Config().SessionTimeout))
}

// buildIntrospectionResponse builds the RFC 7662 introspection response for
// an active session. claims carries identity attributes (given_name,
// family_name, personal_administrative_number, ...) as a generic bag so
// consumers can map any document type without idauth hardcoding per-document
// fields — populated only when the session actually carries them
// (interactive user sessions); machine/client-credentials sessions have none.
func buildIntrospectionResponse(sess *core.Session, issuerPublicURL string, sessionTimeout time.Duration) map[string]interface{} {
	exp := int64(0)
	if sess.LastAccessed != nil {
		exp = sess.LastAccessed.Add(sessionTimeout).Unix()
	}

	resp := map[string]interface{}{
		"active":     true,
		"iss":        issuerPublicURL,
		"sub":        sess.Subject,
		"username":   sess.Subject,
		"scope":      sess.Scope,
		"client_id":  sess.ID,
		"exp":        exp,
		"token_type": "Bearer",
	}

	claims := map[string]interface{}{}

	if sess.FirstName != "" {
		claims["given_name"] = sess.FirstName
	}

	if sess.LastName != "" {
		claims["family_name"] = sess.LastName
	}

	if sess.Code != "" {
		claims["personal_administrative_number"] = sess.Code
	}

	// extra_claims carries userinfo fields a generic OAuth2 provider's
	// ClaimFieldMap didn't map to a named field above (see
	// oauth2generic.createSession) — merged in without overwriting the
	// named claims already set.
	if raw := sess.Metadata["extra_claims"]; raw != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err == nil {
			for k, v := range extra {
				if _, exists := claims[k]; !exists {
					claims[k] = v
				}
			}
		}
	}

	if len(claims) > 0 {
		resp["claims"] = claims
	}

	if jkt := sess.Metadata["dpop_jkt"]; jkt != "" {
		resp["token_type"] = "DPoP"
		resp["cnf"] = map[string]string{"jkt": jkt}
	}

	return resp
}

const basicAuthPrefix = "Basic "

func isBasicAuthScheme(header string) bool {
	return len(header) >= len(basicAuthPrefix) && strings.EqualFold(header[:len(basicAuthPrefix)], basicAuthPrefix)
}

func parseBasicAuth(header string) (clientID, secret string, ok bool) {
	if !isBasicAuthScheme(header) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(header[len(basicAuthPrefix):])
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}
