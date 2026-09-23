// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"net/http"

	"azugo.io/azugo"
)

func (r *router) oauthAuthorizationServerMeta(ctx *azugo.Context) {
	ctx.JSON(map[string]interface{}{
		"issuer":                 r.Config().IdauthPublicURL,
		"authorization_endpoint": r.Config().IdauthPublicURL + "/authorizationV3",
		"token_endpoint":         r.Config().IdauthPublicURL + "/api/1.0/token",
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		},
		"pre-authorized_grant_anonymous_access_supported":     true,
		"response_types_supported":                            []string{"code"},
		"code_challenge_methods_supported":                    []string{"S256"},
		"token_endpoint_auth_methods_supported":               []string{"none", "private_key_jwt", "attest_jwt_client_auth"},
		"client_attestation_signing_alg_values_supported":     []string{"ES256"},
		"client_attestation_pop_signing_alg_values_supported": []string{"ES256"},
		"pushed_authorization_request_endpoint":               r.Config().IdauthPublicURL + "/par",
		"require_pushed_authorization_requests":               r.Config().AuthorizationCode.RequirePAR,
		"dpop_signing_alg_values_supported":                   []string{"ES256"},
		"introspection_endpoint":                              r.Config().IdauthPublicURL + "/introspection",
		"introspection_endpoint_auth_methods_supported":       []string{"client_secret_basic"},
	})
}

// assetLinks serves /.well-known/assetlinks.json for Android App Links verification.
func (r *router) assetLinks(ctx *azugo.Context) {
	pkg := r.Config().AndroidAppPackage
	fingerprints := r.Config().AndroidAppFingerprints

	if pkg == "" || len(fingerprints) == 0 {
		ctx.StatusCode(http.StatusNotFound)
		return
	}

	ctx.JSON([]map[string]interface{}{
		{
			"relation": []string{"delegate_permission/common.handle_all_urls"},
			"target": map[string]interface{}{
				"namespace":                "android_app",
				"package_name":             pkg,
				"sha256_cert_fingerprints": fingerprints,
			},
		},
	})
}

// appleAppSiteAssociation serves /.well-known/apple-app-site-association for Apple Universal Links.
func (r *router) appleAppSiteAssociation(ctx *azugo.Context) {
	appIDs := r.Config().AppleAppIDs

	if len(appIDs) == 0 {
		ctx.StatusCode(http.StatusNotFound)
		return
	}

	ctx.JSON(map[string]interface{}{
		"applinks": map[string]interface{}{
			"details": []map[string]interface{}{
				{
					"appIDs": appIDs,
					"components": []map[string]interface{}{
						{"/": "/*"},
					},
				},
			},
		},
	})
}
