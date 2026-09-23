// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"

	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/routes/response"
)

func trustAnchorKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	buf, err := os.ReadFile("../testdata/attestation_trust_key.pem")
	qt.Assert(t, qt.IsNil(err))

	block, _ := pem.Decode(buf)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	qt.Assert(t, qt.IsNil(err))

	return key
}

// trustAnchorCert loads the self-signed test root, also used as the WIA's
// x5c leaf since the fixture root/leaf are the same certificate.
func trustAnchorCert(t testing.TB) *x509.Certificate {
	t.Helper()

	buf, err := os.ReadFile("../testdata/attestation_trust.pem")
	qt.Assert(t, qt.IsNil(err))

	block, _ := pem.Decode(buf)
	cert, err := x509.ParseCertificate(block.Bytes)
	qt.Assert(t, qt.IsNil(err))

	return cert
}

func walletKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	return k
}

func walletJWK(k *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(k.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(k.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

func testWIA(t testing.TB, wk *ecdsa.PrivateKey) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://wallet-provider.example.com",
		"sub": "edim.wallet.test",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": walletJWK(wk)},
	})
	tok.Header["typ"] = "oauth-client-attestation+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(trustAnchorCert(t).Raw)}

	s, err := tok.SignedString(trustAnchorKey(t))
	qt.Assert(t, qt.IsNil(err))

	return s
}

func testWIAPoP(t testing.TB, wk *ecdsa.PrivateKey, jti string) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "edim.wallet.test",
		"aud": testTokenHTU,
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
	})
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"

	s, err := tok.SignedString(wk)
	qt.Assert(t, qt.IsNil(err))

	return s
}

// seedAuthCode plants a redeemable auth code for the wallet test client.
func seedAuthCode(t testing.TB, app interface {
	AuthCodeStore() *authorizationcode.Store
}, code, verifier string,
) {
	t.Helper()

	err := app.AuthCodeStore().SetItem(context.Background(), authorizationcode.AuthCodeItem{
		Code:                code,
		ClientID:            "edim.wallet.test",
		RedirectURI:         "https://wallet.example.com/cb",
		CodeChallenge:       authorizationcode.GenerateCodeChallenge(verifier),
		CodeChallengeMethod: "S256",
		Scope:               "openid",
		IssuerState:         "offer-123",
	})
	qt.Assert(t, qt.IsNil(err))
}

func TestToken_AuthCodeWithAttestationAndDPoP_Succeeds(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	seedAuthCode(t, idapp, "code-1", "verifier-verifier-verifier-verifier-verifier")

	// DPoP proof signed with the SAME key as the WIA cnf key (TS3).
	proof := dpopProofWithKey(t, testTokenHTU, wk, nil)

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":    "authorization_code",
			"code":          "code-1",
			"code_verifier": "verifier-verifier-verifier-verifier-verifier",
			"redirect_uri":  "https://wallet.example.com/cb",
		},
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "jti-ok")),
		client.WithHeader("DPoP", proof),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	tok := &response.TokenResponse{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, tok)))
	qt.Check(t, qt.Equals(tok.TokenType, "DPoP"))
	qt.Check(t, qt.Not(qt.Equals(tok.AccessToken, "")))
	qt.Check(t, qt.Not(qt.Equals(tok.RefreshToken, "")))
}

func TestToken_AuthCodeWithAttestation_MissingDPoPRejected(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	seedAuthCode(t, idapp, "code-2", "verifier-verifier-verifier-verifier-verifier")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":    "authorization_code",
			"code":          "code-2",
			"code_verifier": "verifier-verifier-verifier-verifier-verifier",
			"redirect_uri":  "https://wallet.example.com/cb",
		},
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "jti-2")),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_dpop_proof"))
}

func TestToken_AuthCodeWithAttestation_DPoPKeyMismatchRejected(t *testing.T) {
	// TS3 v1.5.1 key binding, opt-in since v1.5.2 rollback (default off).
	t.Setenv("CLIENT_ATTESTATION_REQUIRE_KEY_BINDING", "true")

	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	otherKey := walletKey(t)
	seedAuthCode(t, idapp, "code-3", "verifier-verifier-verifier-verifier-verifier")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":    "authorization_code",
			"code":          "code-3",
			"code_verifier": "verifier-verifier-verifier-verifier-verifier",
			"redirect_uri":  "https://wallet.example.com/cb",
		},
		client.WithHeader("OAuth-Client-Attestation", testWIA(t, wk)),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "jti-3")),
		client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, otherKey, nil)),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_dpop_proof"))
}

func TestToken_AuthCodeWithInvalidAttestationRejected401(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	seedAuthCode(t, idapp, "code-4", "verifier-verifier-verifier-verifier-verifier")

	client := app.TestClient()
	resp, err := client.PostForm(
		"/api/1.0/token", map[string]any{
			"grant_type":    "authorization_code",
			"code":          "code-4",
			"code_verifier": "verifier-verifier-verifier-verifier-verifier",
			"redirect_uri":  "https://wallet.example.com/cb",
		},
		client.WithHeader("OAuth-Client-Attestation", "not-a-jwt"),
		client.WithHeader("OAuth-Client-Attestation-PoP", testWIAPoP(t, wk, "jti-4")),
		client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, wk, nil)),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}
