// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/digimaks/idauth/routes/request"
	"github.com/digimaks/idauth/routes/response"
	"github.com/digimaks/idauth/svcerrors"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
)

func dpopProof(t testing.TB, htu string, mutate func(claims jwt.MapClaims)) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	return dpopProofWithKey(t, htu, key, mutate)
}

// dpopProofWithKey generates a DPoP proof signed with the provided key.
func dpopProofWithKey(t testing.TB, htu string, key *ecdsa.PrivateKey, mutate func(jwt.MapClaims)) string {
	t.Helper()

	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}

	if mutate != nil {
		mutate(claims)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

// The TestApp public URL is https://sso.example.com/auth (testing.go), so the
// default accepted htu is https://sso.example.com/auth/api/1.0/token.
const testTokenHTU = "https://sso.example.com/auth/api/1.0/token"

func TestToken_DPoP_MalformedProofRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": "whatever",
	}, client.WithHeader("DPoP", "not-a-jwt"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(svcerrors.HeaderErrorCode)), string(svcerrors.TokenDPoPProofInvalid)))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"error":"invalid_dpop_proof"`))
}

func TestToken_DPoP_WrongHTURejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	proof := dpopProof(t, "https://evil.example.com/token", nil)

	client := app.TestClient()
	resp, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": "whatever",
	}, client.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(svcerrors.HeaderErrorCode)), string(svcerrors.TokenDPoPProofInvalid)))
}

func TestToken_DPoP_ValidProofPassesThroughToGrant(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	proof := dpopProof(t, testTokenHTU, nil)

	client := app.TestClient()
	resp, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": "nonexistent-code-12345",
	}, client.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))

	// A valid proof must NOT be rejected as invalid_dpop_proof; the request
	// proceeds into the grant handler and fails on the bogus pre-auth code.
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), "err:session:preAuthCodeInvalidOrExpired"))
}

func clientTokenFor(t testing.TB, clientID string) string {
	t.Helper()

	now := time.Now().UTC()

	tok := &jwt.RegisteredClaims{
		ID:        ulid.Make().String(),
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{"http://test/api/1.0/token"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, tok).SignedString(privateKey(t))
	qt.Assert(t, qt.IsNil(err))

	return token
}

func TestToken_DPoP_ClientCredentialsBindsSession(t *testing.T) {
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
	qt.Check(t, qt.Equals(tok.TokenType, "DPoP"))
}

func TestToken_DPoP_RequiredClientWithoutProofRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/api/1.0/token", &request.TokenRequest{
		GrantType:           GrantTypeClientCredentials,
		Scope:               "admin/wallet:delete",
		ClientID:            "edim.dpop-required",
		ClientAssertionType: ClientAssertationTypeJWTBearer,
		ClientAssertion:     clientTokenFor(t, "edim.dpop-required"),
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(svcerrors.HeaderErrorCode)), string(svcerrors.TokenDPoPProofMissing)))
}
