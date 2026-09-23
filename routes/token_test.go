// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/digimaks/idauth/routes/request"
	"github.com/digimaks/idauth/routes/response"
	"github.com/digimaks/idauth/svcerrors"
	"github.com/lx-lib/lx-idauth/core"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
)

func privateKey(t testing.TB) *rsa.PrivateKey {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`))

	qt.Assert(t, qt.IsNil(err))

	return key
}

func clientToken(t testing.TB, id string) string {
	if id == "" {
		id = ulid.Make().String()
	}

	now := time.Now().UTC()

	tok := &jwt.RegisteredClaims{
		ID:        id,
		Issuer:    "edim.self-service.portal",
		Subject:   "edim.self-service.portal",
		Audience:  jwt.ClaimStrings{"http://test/api/1.0/token"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, tok).SignedString(privateKey(t))
	qt.Assert(t, qt.IsNil(err))

	return token
}

func systemToken(t testing.TB, app *azugo.TestApp, token string) string {
	resp, err := app.TestClient().PostJSON("/api/1.0/token", &request.TokenRequest{
		GrantType:           GrantTypeClientCredentials,
		Scope:               "admin/wallet:delete",
		ClientID:            "edim.self-service.portal",
		ClientAssertionType: ClientAssertationTypeJWTBearer,
		ClientAssertion:     token,
	})

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	tok := &response.TokenResponse{}

	err = json.Unmarshal(buf, tok)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Not(qt.Equals(tok.AccessToken, "")))
	qt.Check(t, qt.Equals(tok.TokenType, "Bearer"))

	return tok.AccessToken
}

func logout(t testing.TB, app *azugo.TestApp, token string) {
	client := app.TestClient()
	resp, err := client.Delete("/api/1.0/session", client.WithHeader("Authorization", "Bearer "+token))

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
}

func TestSystemToken(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	token := systemToken(t, app, clientToken(t, ""))

	logout(t, app, token)
}

func TestSystemToken_PreventReplyAttack(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	ct := clientToken(t, "")

	token := systemToken(t, app, ct)
	defer logout(t, app, token)

	resp, err := app.TestClient().PostJSON("/api/1.0/token", &request.TokenRequest{
		GrantType:           "client_credentials",
		Scope:               "admin/wallet:delete",
		ClientID:            "edim.self-service.portal",
		ClientAssertionType: ClientAssertationTypeJWTBearer,
		ClientAssertion:     ct,
	})

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestSystemToken_UnsupportedAssertionType(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/api/1.0/token", &request.TokenRequest{
		GrantType:           GrantTypeClientCredentials,
		Scope:               "admin/wallet:delete",
		ClientID:            "edim.self-service.portal",
		ClientAssertionType: "not-jwt-bearer",
		ClientAssertion:     "irrelevant",
	})

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(string(resp.Header.Peek(svcerrors.HeaderErrorCode)), string(svcerrors.ClientCredentialsUnsupportedAssertionType)))
}

func TestSystemToken_UserInfo(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	token := systemToken(t, app, clientToken(t, ""))
	defer logout(t, app, token)

	resp, err := app.TestClient().Get("/api/1.0/session", app.TestClient().WithHeader("Authorization", "Bearer "+token))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	user := &core.SessionResponse{}

	err = json.Unmarshal(buf, user)
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(user.State, "authorized"))
	qt.Check(t, qt.IsTrue(user.Active))
	qt.Check(t, qt.Equals(user.Subject, "SYSTEM"))
	qt.Check(t, qt.ContentEquals(user.Scope, []string{"admin/wallet:delete"}))
}

func TestToken_SetsCacheControlNoStore(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/api/1.0/token", &request.TokenRequest{
		GrantType:           GrantTypeClientCredentials,
		Scope:               "admin/wallet:delete",
		ClientID:            "edim.self-service.portal",
		ClientAssertionType: ClientAssertationTypeJWTBearer,
		ClientAssertion:     clientToken(t, ""),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Cache-Control")), "no-store"))
}
