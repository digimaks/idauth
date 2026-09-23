// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func parForm(overrides map[string]string) map[string]any {
	v := map[string]any{
		"client_id":             "edim.wallet.test",
		"redirect_uri":          "https://wallet.example.com/cb",
		"response_type":         "code",
		"code_challenge":        strings.Repeat("a", 43),
		"code_challenge_method": "S256",
		"scope":                 "openid",
		"state":                 "xyz",
		"issuer_state":          "offer-123",
	}
	for k, val := range overrides {
		if val == "" {
			delete(v, k)
		} else {
			v[k] = val
		}
	}

	return v
}

func TestPAR_ValidRequest_ReturnsRequestURI(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	client := app.TestClient()

	resp, err := client.PostForm(
		"/par", parForm(nil),
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "par-jti-1")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Cache-Control")), "no-store"))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	reqURI, _ := body["request_uri"].(string)
	qt.Check(t, qt.IsTrue(strings.HasPrefix(reqURI, "urn:ietf:params:oauth:request_uri:")))

	expiresIn, _ := body["expires_in"].(float64)
	qt.Check(t, qt.IsTrue(expiresIn > 0))
}

func TestPAR_MissingAttestation_Rejected401(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/par", parForm(nil))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestPAR_AttestedClientIDMismatch_Rejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	client := app.TestClient()

	resp, err := client.PostForm(
		"/par", parForm(map[string]string{"client_id": "edim.self-service.portal"}),
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "par-jti-2")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestPAR_InvalidRedirectURI_Rejected400(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	client := app.TestClient()

	resp, err := client.PostForm(
		"/par", parForm(map[string]string{"redirect_uri": "https://evil.example.com/cb"}),
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "par-jti-3")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_request"))
}

func TestPAR_MissingPKCE_Rejected400(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	client := app.TestClient()

	resp, err := client.PostForm(
		"/par", parForm(map[string]string{"code_challenge": ""}),
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "par-jti-4")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestPAR_UnsupportedScope_Rejected400(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	client := app.TestClient()

	resp, err := client.PostForm(
		"/par", parForm(map[string]string{"scope": "not-a-real-scope"}),
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "par-jti-5")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_scope"))
}
