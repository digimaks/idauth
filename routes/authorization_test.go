// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func authzQuery(overrides map[string]string) string {
	v := url.Values{
		"client_id":             {"edim.wallet.test"},
		"redirect_uri":          {"https://wallet.example.com/cb"},
		"response_type":         {"code"},
		"code_challenge":        {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"},
		"scope":                 {"openid"},
		"state":                 {"xyz"},
		"issuer_state":          {"offer-123"},
	}
	for k, val := range overrides {
		if val == "" {
			v.Del(k)
		} else {
			v.Set(k, val)
		}
	}
	return v.Encode()
}

func TestAuthorizationV3_UnknownClientReturns400(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(map[string]string{"client_id": "nope"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestAuthorizationV3_UnregisteredRedirectURIReturns400(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(map[string]string{"redirect_uri": "https://evil.example.com/cb"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestAuthorizationV3_PrefixRedirectURIDoesNotMatch(t *testing.T) {
	// Guards against the library's substring-match weakness: a registered
	// URI must not validate a longer attacker-controlled URI containing it.
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(map[string]string{"redirect_uri": "https://wallet.example.com/cb/../evil"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestAuthorizationV3_BadResponseTypeRedirectsWithError(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(map[string]string{"response_type": "token"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))

	loc := string(resp.Header.Peek("Location"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(loc, "https://wallet.example.com/cb?")))
	qt.Check(t, qt.StringContains(loc, "error=unsupported_response_type"))
	qt.Check(t, qt.StringContains(loc, "state=xyz"))
}

func TestAuthorizationV3_UnsupportedScopeRedirectsWithError(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(map[string]string{"scope": "eu.europa.ec.eudi.pid_vc_sd_jwt"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("Location")), "error=invalid_scope"))
}

func TestAuthorizationV3_MissingPKCERedirectsWithError(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(map[string]string{"code_challenge": ""}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("Location")), "error=invalid_request"))
}

func TestAuthorizationV3_ValidRequestDelegatesToLibraryAuthorize(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/authorizationV3?" + authzQuery(nil))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))

	loc := string(resp.Header.Peek("Location"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(loc, authorizeDelegatePath+"?")))
	qt.Check(t, qt.StringContains(loc, "issuer_state=offer-123"))
	qt.Check(t, qt.StringContains(loc, "client_id=edim.wallet.test"))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Cache-Control")), "no-store"))
}
