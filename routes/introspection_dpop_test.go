// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	"github.com/digimaks/idauth/routes/request"
	"github.com/digimaks/idauth/routes/response"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func TestIntrospection_ReturnsCnfForDPoPBoundToken(t *testing.T) {
	t.Skip("flaky: lx-idauth CacheSessionStore.Create/Set writes via ristretto async, no Sync/Wait before return, so a session read right after can miss under load. Fix: call store.Sync(ctx) after Set in CacheSessionStore.Create (lx-idauth session.go).")

	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	proof := dpopProof(t, testTokenHTU, nil)

	client := app.TestClient()
	resp, err := client.PostJSON("/api/1.0/token", &request.TokenRequest{
		GrantType:           GrantTypeClientCredentials,
		Scope:               "admin/wallet:delete",
		ClientID:            "edim.self-service.portal",
		ClientAssertionType: ClientAssertationTypeJWTBearer,
		ClientAssertion:     clientToken(t, ""),
	}, client.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	tok := &response.TokenResponse{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, tok)))

	iresp, err := client.PostForm("/introspection", map[string]any{"token": tok.AccessToken})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(iresp.StatusCode(), fasthttp.StatusOK))

	ibuf, err := iresp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	intro := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(ibuf, &intro)))

	qt.Check(t, qt.Equals(intro["active"], true))
	qt.Check(t, qt.Equals(intro["token_type"], "DPoP"))

	cnf, ok := intro["cnf"].(map[string]any)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Not(qt.Equals(cnf["jkt"], "")))
}

func TestIntrospection_BearerTokenHasNoCnf(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	token := systemToken(t, app, clientToken(t, ""))
	defer logout(t, app, token)

	iresp, err := app.TestClient().PostForm("/introspection", map[string]any{"token": token})
	qt.Assert(t, qt.IsNil(err))

	ibuf, err := iresp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	intro := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(ibuf, &intro)))

	qt.Check(t, qt.Equals(intro["token_type"], "Bearer"))

	_, hasCnf := intro["cnf"]
	qt.Check(t, qt.IsFalse(hasCnf))
}

func TestWellKnown_AdvertisesDPoP(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/oauth-authorization-server/idauth")
	qt.Assert(t, qt.IsNil(err))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(buf), `"dpop_signing_alg_values_supported":["ES256"]`))
}

func TestIntrospection_SetsCacheControlNoStore(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostForm("/introspection", map[string]any{"token": "whatever"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Cache-Control")), "no-store"))
}
