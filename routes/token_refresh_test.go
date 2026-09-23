// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"

	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/dpop"
	"github.com/digimaks/idauth/routes/response"
	"github.com/lx-lib/lx-idauth/core"
)

// waitSet gives Ristretto's async buffer time to process a set operation.
func waitSet() {
	time.Sleep(10 * time.Millisecond)
}

// thumbprintFor computes the RFC 7638 SHA-256 thumbprint of key's public part.
func thumbprintFor(t testing.TB, k *ecdsa.PrivateKey) string {
	t.Helper()

	_, jkt, err := dpop.ParseECJWK(walletJWK(k))
	qt.Assert(t, qt.IsNil(err))

	return jkt
}

// seedRefreshToken plants a redeemable refresh token bound to wk's key thumbprint.
func seedRefreshToken(t testing.TB, app interface {
	AuthCodeStore() *authorizationcode.Store
}, wk *ecdsa.PrivateKey, jkt string,
) string {
	t.Helper()

	token, err := app.AuthCodeStore().IssueRefreshToken(t.Context(), authorizationcode.RefreshTokenItem{
		ClientID: "edim.wallet.test",
		Scope:    "eu.europa.ec.eudi.pid_vc_sd_jwt",
		JKT:      jkt,
		Session:  core.Session{Subject: "10345678902"},
	})
	qt.Assert(t, qt.IsNil(err))

	return token
}

func TestToken_RefreshGrant_ValidProof_Succeeds(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	jkt := thumbprintFor(t, wk)
	refreshToken := seedRefreshToken(t, idapp, wk, jkt)
	waitSet()

	client := app.TestClient()
	resp, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, wk, nil)))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	tok := &response.TokenResponse{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, tok)))
	qt.Check(t, qt.Equals(tok.TokenType, "DPoP"))
	qt.Check(t, qt.Not(qt.Equals(tok.AccessToken, "")))
	qt.Check(t, qt.Not(qt.Equals(tok.RefreshToken, "")))
	qt.Check(t, qt.Not(qt.Equals(tok.RefreshToken, refreshToken))) // rotated, not reused
}

func TestToken_RefreshGrant_MissingDPoPRejected(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	jkt := thumbprintFor(t, wk)
	refreshToken := seedRefreshToken(t, idapp, wk, jkt)
	waitSet()

	client := app.TestClient()
	resp, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestToken_RefreshGrant_KeyMismatchRejected(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	otherKey := walletKey(t)
	jkt := thumbprintFor(t, wk)
	refreshToken := seedRefreshToken(t, idapp, wk, jkt)
	waitSet()

	client := app.TestClient()
	resp, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, otherKey, nil)))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	buf, _ := resp.BodyUncompressed()
	body := map[string]string{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["error"], "invalid_dpop_proof"))
}

func TestToken_RefreshGrant_ReuseAfterRotationRejected(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	wk := walletKey(t)
	jkt := thumbprintFor(t, wk)
	refreshToken := seedRefreshToken(t, idapp, wk, jkt)
	waitSet()

	client := app.TestClient()
	first, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, wk, nil)))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(first.StatusCode(), fasthttp.StatusOK))

	// Use a distinct JTI so the DPoP replay check doesn't shadow the refresh
	// token rotation check — we want to test that the token itself was consumed.
	second, err := client.PostForm("/api/1.0/token", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}, client.WithHeader("DPoP", dpopProofWithKey(t, testTokenHTU, wk, func(c jwt.MapClaims) {
		c["jti"] = "jti-reuse-" + t.Name()
	})))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(second.StatusCode(), fasthttp.StatusBadRequest))
}
