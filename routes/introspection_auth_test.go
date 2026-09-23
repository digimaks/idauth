// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/base64"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func basicAuthHeader(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func TestIntrospection_ValidBasicAuth_Succeeds(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/introspection", map[string]any{"token": "whatever"},
		client.WithHeader("Authorization", basicAuthHeader("edim.self-service.portal", "test-introspection-secret")))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["active"], false)) // "whatever" isn't a real token, but auth passed
}

func TestIntrospection_InvalidBasicAuth_Rejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/introspection", map[string]any{"token": "whatever"},
		client.WithHeader("Authorization", basicAuthHeader("edim.self-service.portal", "wrong-secret")))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestIntrospection_UnknownClientBasicAuth_Rejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/introspection", map[string]any{"token": "whatever"},
		client.WithHeader("Authorization", basicAuthHeader("no-such-client", "anything")))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestIntrospection_NonBasicScheme_TreatedAsAbsent_WhenNotRequired(t *testing.T) {
	// Simulates an un-upgraded issuer-go client that still sends the legacy
	// "Authorization: Bearer <client-secret>" header on every introspection
	// call. When IDAUTH_REQUIRE_INTROSPECTION_AUTH is unset/false, this must
	// be treated the same as an absent Authorization header (i.e. allowed),
	// not hard-rejected as malformed Basic auth. This is the property that
	// makes the staged rollout safe to deploy in either order relative to
	// issuer-go's paired change.
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/introspection", map[string]any{"token": "whatever"},
		client.WithHeader("Authorization", "Bearer some-legacy-secret"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}

func TestIntrospection_MissingAuth_AllowedWhenNotRequired(t *testing.T) {
	// Default rollout state (IDAUTH_REQUIRE_INTROSPECTION_AUTH unset/false):
	// unauthenticated calls still work, matching every pre-existing test in
	// introspection_dpop_test.go that doesn't send an Authorization header.
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostForm("/introspection", map[string]any{"token": "whatever"})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}

func TestParseBasicAuth_BareScheme_ReturnsError(t *testing.T) {
	// Unit test: a header that is exactly "Basic " (no credentials) must be detected
	// as claiming the Basic scheme, then parseBasicAuth must reject it.
	header := "Basic "

	// First, verify isBasicAuthScheme returns true
	qt.Check(t, qt.Equals(isBasicAuthScheme(header), true))

	// Then, verify parseBasicAuth returns false (malformed)
	clientID, secret, ok := parseBasicAuth(header)
	qt.Check(t, qt.Equals(ok, false))
	qt.Check(t, qt.Equals(clientID, ""))
	qt.Check(t, qt.Equals(secret, ""))
}

func TestIntrospection_BareBasicScheme_Rejected(t *testing.T) {
	// A header that claims the Basic auth scheme (starts with "Basic ") but has no valid
	// credentials MUST be hard-rejected with 401 invalid_client, regardless of RequireIntrospectionAuth flag.
	// This test verifies that any header starting with "Basic " is treated as a Basic auth attempt,
	// and rejected if the credentials are invalid/missing.
	// Note: The HTTP client in tests strips trailing spaces, so we test with invalid base64
	// characters after the scheme, which effectively creates a malformed Basic auth header.
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()

	// Test 1: Just the scheme without credentials (HTTP client strips trailing space,
	// turning "Basic " into "Basic", which doesn't claim the scheme per HTTP spec).
	// We verify it's treated as no-auth and passes through to token introspection.
	t.Run("scheme_only_no_space", func(t *testing.T) {
		resp, err := client.PostForm("/introspection", map[string]any{"token": "whatever"},
			client.WithHeader("Authorization", "Basic"))
		qt.Assert(t, qt.IsNil(err))
		// Treated as no auth → token introspection returns {"active": false}
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	})

	// Test 2: Single invalid base64 char after the scheme. "Basic a" has "a" which is valid
	// base64 but decodes to a single byte without a colon, so parseBasicAuth fails → 401.
	t.Run("single_char_base64", func(t *testing.T) {
		resp, err := client.PostForm("/introspection", map[string]any{"token": "whatever"},
			client.WithHeader("Authorization", "Basic a"))
		qt.Assert(t, qt.IsNil(err))
		buf, _ := resp.BodyUncompressed()
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))

		body := map[string]any{}
		qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
		qt.Check(t, qt.Equals(body["error"], "invalid_client"))
	})
}
