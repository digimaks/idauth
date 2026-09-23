// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"net/url"
	"slices"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	"github.com/digimaks/idauth/authorizationcode"
)

// par implements POST /par (RFC 9126): wallets push the full authorization
// request over an authenticated back-channel call and get back a
// short-lived request_uri to present at /authorizationV3 instead of the
// individual parameters. Requires attest_jwt_client_auth — this endpoint
// is wallet-only, there is no confidential-client / Basic-auth path.
func (r *router) par(ctx *azugo.Context) {
	ctx.Header.Set("Cache-Control", "no-store")

	if r.attest == nil {
		parError(ctx, fasthttp.StatusUnauthorized, "invalid_client", "client attestation not supported")
		return
	}

	wia := ctx.Header.Get("OAuth-Client-Attestation")
	pop := ctx.Header.Get("OAuth-Client-Attestation-PoP")

	res, err := r.attest.Verify(ctx, wia, pop)
	if err != nil {
		parError(ctx, fasthttp.StatusUnauthorized, "invalid_client", "invalid client attestation")
		return
	}

	clientID := ctx.Form.StringOptional("client_id")
	if clientID == nil || *clientID == "" {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	if res.ClientID != *clientID {
		parError(ctx, fasthttp.StatusUnauthorized, "invalid_client", "attestation does not match client_id")
		return
	}

	client, err := r.IDAuth().Clients().GetClient(*clientID)
	if err != nil || client == nil {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_client", "unknown client")
		return
	}

	redirectURI := ctx.Form.StringOptional("redirect_uri")
	if redirectURI == nil || !slices.Contains(client.RedirectURI, *redirectURI) {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_request", "invalid redirect_uri")
		return
	}

	if rt := ctx.Form.StringOptional("response_type"); rt == nil || *rt != "code" {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_request", "only response_type=code is supported")
		return
	}

	challenge := ctx.Form.StringOptional("code_challenge")
	if challenge == nil || len(*challenge) < 43 || len(*challenge) > 128 {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_request", "code_challenge is required (43-128 chars)")
		return
	}

	if m := ctx.Form.StringOptional("code_challenge_method"); m == nil || *m != "S256" {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}

	scope := ctx.Form.StringOptional("scope")
	if scope == nil || !r.AuthCodeStore().IsScopeSupported(*scope) {
		parError(ctx, fasthttp.StatusBadRequest, "invalid_scope", "unsupported scope")
		return
	}

	form := url.Values{}

	for k, v := range ctx.Request().PostArgs().All() {
		form.Add(string(k), string(v))
	}

	rawQuery := form.Encode()

	id, err := r.AuthCodeStore().SetPAR(ctx, authorizationcode.PARItem{
		ClientID: *clientID,
		RawQuery: rawQuery,
	})
	if err != nil {
		ctx.Log().Error("failed to store pushed authorization request")
		parError(ctx, fasthttp.StatusInternalServerError, "server_error", "failed to store request")

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:" + id,
		"expires_in":  int(r.Config().AuthorizationCode.PARTTL.Seconds()),
	})
}

func parError(ctx *azugo.Context, status int, code, desc string) {
	ctx.StatusCode(status)
	ctx.JSON(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
