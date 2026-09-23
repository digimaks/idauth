// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func TestOAuthServerMeta_AdvertisesAuthCodeCapabilities(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/oauth-authorization-server/idauth")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	meta := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &meta)))

	issuer, _ := meta["issuer"].(string)
	authzEndpoint, _ := meta["authorization_endpoint"].(string)
	qt.Check(t, qt.Equals(authzEndpoint, issuer+"/authorizationV3"))

	methods, _ := meta["token_endpoint_auth_methods_supported"].([]any)
	found := false

	for _, m := range methods {
		if m == "attest_jwt_client_auth" {
			found = true
		}
	}

	qt.Check(t, qt.IsTrue(found))

	attestAlgs, _ := meta["client_attestation_signing_alg_values_supported"].([]any)
	qt.Check(t, qt.DeepEquals(attestAlgs, []any{"ES256"}))

	popAlgs, _ := meta["client_attestation_pop_signing_alg_values_supported"].([]any)
	qt.Check(t, qt.DeepEquals(popAlgs, []any{"ES256"}))
}

func TestOAuthServerMeta_AdvertisesPAR(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/oauth-authorization-server/idauth")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	meta := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &meta)))

	issuer, _ := meta["issuer"].(string)
	qt.Check(t, qt.Equals(meta["pushed_authorization_request_endpoint"], any(issuer+"/par")))
	qt.Check(t, qt.Equals(meta["require_pushed_authorization_requests"], any(false)))
}

func TestOAuthServerMeta_AdvertisesRefreshTokenGrant(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/oauth-authorization-server/idauth")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	meta := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &meta)))

	grants, _ := meta["grant_types_supported"].([]any)
	found := false

	for _, g := range grants {
		if g == "refresh_token" {
			found = true
		}
	}

	qt.Check(t, qt.IsTrue(found))
}

func TestOAuthServerMeta_StandardPathMatchesIdauthAlias(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	standard, err := app.TestClient().Get("/.well-known/oauth-authorization-server")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(standard.StatusCode(), fasthttp.StatusOK))

	aliased, err := app.TestClient().Get("/.well-known/oauth-authorization-server/idauth")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(aliased.StatusCode(), fasthttp.StatusOK))

	standardBody, err := standard.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	aliasedBody, err := aliased.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(string(standardBody), string(aliasedBody)))
}

func TestOAuthServerMeta_AdvertisesIntrospectionEndpoint(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/.well-known/oauth-authorization-server/idauth")
	qt.Assert(t, qt.IsNil(err))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	meta := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &meta)))

	issuer, _ := meta["issuer"].(string)
	qt.Check(t, qt.Equals(meta["introspection_endpoint"], any(issuer+"/introspection")))

	methods, _ := meta["introspection_endpoint_auth_methods_supported"].([]any)
	qt.Check(t, qt.IsTrue(len(methods) > 0))
}
