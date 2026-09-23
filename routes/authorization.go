// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"net/url"
	"slices"
	"strings"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// authorizeDelegatePath is the browser authorize route mounted by the
// lx/idauth library (confirmed against lx/idauth v0.5.4 source — Task 3
// of the Phase 2 plan).
const authorizeDelegatePath = "/authorize"

// authorizationV3 is the OAuth 2.0 authorization endpoint advertised to
// wallets. It validates the request strictly (exact redirect_uri match,
// mandatory PKCE S256, registered scopes), then delegates to the library
// authorize flow, which authenticates the user against an IdP at LoA High
// and mints the code via authorizationcode.Callback.
func (r *router) authorizationV3(ctx *azugo.Context) {
	ctx.Header.Set("Cache-Control", "no-store")

	if requestURI := ctx.Query.StringOptional("request_uri"); requestURI != nil && *requestURI != "" {
		r.authorizationV3FromPAR(ctx, *requestURI)
		return
	}

	if r.Config().AuthorizationCode.RequirePAR {
		badAuthRequest(ctx, "pushed authorization requests are required")
		return
	}

	clientID := ctx.Query.StringOptional("client_id")
	if clientID == nil || *clientID == "" {
		badAuthRequest(ctx, "client_id is required")
		return
	}

	client, err := r.IDAuth().Clients().GetClient(*clientID)
	if err != nil || client == nil {
		badAuthRequest(ctx, "unknown client")
		return
	}

	redirectURI := ctx.Query.StringOptional("redirect_uri")
	if redirectURI == nil || !slices.Contains(client.RedirectURI, *redirectURI) {
		badAuthRequest(ctx, "invalid redirect_uri")
		return
	}

	// redirect_uri is validated: report further errors by redirect
	// (RFC 6749 §4.1.2.1).
	state := ctx.Query.StringOptional("state")

	if rt := ctx.Query.StringOptional("response_type"); rt == nil || *rt != "code" {
		redirectAuthError(ctx, *redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}

	challenge := ctx.Query.StringOptional("code_challenge")
	if challenge == nil || len(*challenge) < 43 || len(*challenge) > 128 {
		redirectAuthError(ctx, *redirectURI, state, "invalid_request", "code_challenge is required (43-128 chars)")
		return
	}

	if m := ctx.Query.StringOptional("code_challenge_method"); m == nil || *m != "S256" {
		redirectAuthError(ctx, *redirectURI, state, "invalid_request", "code_challenge_method must be S256")
		return
	}

	scope := ctx.Query.StringOptional("scope")
	if scope == nil || !r.AuthCodeStore().IsScopeSupported(*scope) {
		redirectAuthError(ctx, *redirectURI, state, "invalid_scope", "unsupported scope")
		return
	}

	ctx.RedirectUnsafe(authorizeDelegatePath + "?" + string(ctx.Request().URI().QueryString()))
}

func badAuthRequest(ctx *azugo.Context, msg string) {
	ctx.StatusCode(fasthttp.StatusBadRequest)
	ctx.JSON(map[string]string{
		"error":             "invalid_request",
		"error_description": msg,
	})
}

func redirectAuthError(ctx *azugo.Context, redirectURI string, state *string, code, desc string) {
	v := url.Values{}
	v.Set("error", code)
	v.Set("error_description", desc)

	if state != nil && *state != "" {
		v.Set("state", *state)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	ctx.RedirectUnsafe(redirectURI + sep + v.Encode())
}

const parURNPrefix = "urn:ietf:params:oauth:request_uri:"

func (r *router) authorizationV3FromPAR(ctx *azugo.Context, requestURI string) {
	clientID := ctx.Query.StringOptional("client_id")
	if clientID == nil || *clientID == "" {
		badAuthRequest(ctx, "client_id is required alongside request_uri")
		return
	}

	if !strings.HasPrefix(requestURI, parURNPrefix) {
		badAuthRequest(ctx, "invalid request_uri")
		return
	}

	id := strings.TrimPrefix(requestURI, parURNPrefix)

	item, err := r.AuthCodeStore().PopPAR(ctx, id)
	if err != nil {
		badAuthRequest(ctx, "invalid or expired request_uri")
		return
	}

	if item.ClientID != *clientID {
		badAuthRequest(ctx, "client_id does not match pushed request")
		return
	}

	ctx.RedirectUnsafe(authorizeDelegatePath + "?" + item.RawQuery)
}
