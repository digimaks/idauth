// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"strconv"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"

	"azugo.io/azugo"

	"github.com/digimaks/idauth/routes/response"
)

// seedPreAuthCode generates a pre-auth code + tx_code via /preauth_generate,
// mirroring what issuer-go does server-to-server.
func seedPreAuthCode(t testing.TB, app *azugo.TestApp, scope string) (code, txCode string) {
	t.Helper()

	resp, err := app.TestClient().PostForm("/preauth_generate", map[string]any{
		"scope": scope,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	code, _ = body["preauth_code"].(string)
	txCodeNum, _ := body["tx_code"].(float64)

	return code, strconv.Itoa(int(txCodeNum))
}

func TestToken_PreAuthWithAttestationAndDPoP_Succeeds(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	code, txCode := seedPreAuthCode(t, app, "openid")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":          GrantTypePreAuthorizedCode,
			"pre-authorized_code": code,
			"tx_code":             txCode,
		},
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "preauth-jti-ok")),
		client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, wk, nil)),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	tok := &response.TokenResponse{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, tok)))
	qt.Check(t, qt.Equals(tok.TokenType, "DPoP"))
	qt.Check(t, qt.Not(qt.Equals(tok.AccessToken, "")))
}

func TestToken_PreAuthWithAttestation_MissingDPoPRejected(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	code, txCode := seedPreAuthCode(t, app, "openid")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":          GrantTypePreAuthorizedCode,
			"pre-authorized_code": code,
			"tx_code":             txCode,
		},
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "preauth-jti-2")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_dpop_proof"))
}

func TestToken_PreAuthWithAttestation_DPoPKeyMismatchRejected(t *testing.T) {
	// TS3 v1.5.1 key binding, opt-in since v1.5.2 rollback (default off).
	t.Setenv("CLIENT_ATTESTATION_REQUIRE_KEY_BINDING", "true")

	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	otherKey := walletKey(t)
	code, txCode := seedPreAuthCode(t, app, "openid")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":          GrantTypePreAuthorizedCode,
			"pre-authorized_code": code,
			"tx_code":             txCode,
		},
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "preauth-jti-3")),
		client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, otherKey, nil)),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_dpop_proof"))
}

func TestToken_PreAuthWithInvalidAttestationRejected401(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	code, txCode := seedPreAuthCode(t, app, "openid")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":          GrantTypePreAuthorizedCode,
			"pre-authorized_code": code,
			"tx_code":             txCode,
		},
		client.WithHeader("OAuth-Client-Attestation", "not-a-jwt"),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "preauth-jti-4")),
		client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, wk, nil)),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestToken_PreAuthWithoutAttestation_StillSucceeds(t *testing.T) {
	// Verify-if-present rollout state (default): no attestation header means
	// no attestation checks are applied, and the request proceeds as before.
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	code, txCode := seedPreAuthCode(t, app, "openid")

	resp, err := app.TestClient().PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": code,
		"tx_code":             txCode,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}

func TestToken_PreAuthRequiredAttestation_MissingHeaderRejected(t *testing.T) {
	t.Setenv("IDAUTH_REQUIRE_CLIENT_ATTESTATION_PREAUTH", "true")

	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	code, txCode := seedPreAuthCode(t, app, "openid")

	resp, err := app.TestClient().PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": code,
		"tx_code":             txCode,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_client"))
}
