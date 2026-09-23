// SPDX-License-Identifier: EUPL-1.2

package clientattestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

const tokenEndpoint = "https://sso.example.com/auth/api/1.0/token"

// caChain is a self-signed root CA plus a leaf certificate issued by it,
// used to build the WIA's x5c chain (RFC 7515 §4.1.6).
type caChain struct {
	rootCert *x509.Certificate
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func (c caChain) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)

	return pool
}

func (c caChain) x5c() []string {
	return []string{
		base64.StdEncoding.EncodeToString(c.leafCert.Raw),
	}
}

func newCAChain(t *testing.T) caChain {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	qt.Assert(t, qt.IsNil(err))

	rootCert, err := x509.ParseCertificate(rootDER)
	qt.Assert(t, qt.IsNil(err))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test wallet provider"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	qt.Assert(t, qt.IsNil(err))

	leafCert, err := x509.ParseCertificate(leafDER)
	qt.Assert(t, qt.IsNil(err))

	return caChain{rootCert: rootCert, leafCert: leafCert, leafKey: leafKey}
}

func testKeys(t *testing.T) (anchor caChain, walletKey *ecdsa.PrivateKey) {
	t.Helper()

	anchor = newCAChain(t)

	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	return anchor, walletKey
}

func b64Coord(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func cnfJWK(k *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64Coord(k.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   b64Coord(k.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

func wiaToken(t *testing.T, chain caChain, walletKey *ecdsa.PrivateKey, mutate func(jwt.MapClaims)) string {
	t.Helper()

	claims := jwt.MapClaims{
		"iss": "https://wallet-provider.example.com",
		"sub": "edim.wallet.instance",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": cnfJWK(walletKey)},
	}
	if mutate != nil {
		mutate(claims)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation+jwt"
	tok.Header["x5c"] = chain.x5c()

	s, err := tok.SignedString(chain.leafKey)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func popToken(t *testing.T, key *ecdsa.PrivateKey, mutate func(jwt.MapClaims)) string {
	t.Helper()

	claims := jwt.MapClaims{
		"iss": "edim.wallet.instance",
		"aud": tokenEndpoint,
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": "pop-jti-1",
	}
	if mutate != nil {
		mutate(claims)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func testVerifier(anchor caChain, seen map[string]bool) *Verifier {
	v, _ := NewVerifier(Config{
		TrustAnchors: anchor.pool(),
		Audiences:    []string{tokenEndpoint},
		IATWindow:    time.Minute,
		ReplayCheck: func(_ context.Context, jti string) (bool, error) {
			if seen[jti] {
				return true, nil
			}

			seen[jti] = true

			return false, nil
		},
	})

	return v
}

func TestVerify_ValidWIAAndPoP(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	res, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), popToken(t, walletKey, nil))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.ClientID, "edim.wallet.instance"))
	qt.Check(t, qt.Not(qt.Equals(res.CnfJKT, "")))
}

func TestVerify_RejectsUntrustedWIASigner(t *testing.T) {
	anchor, walletKey := testKeys(t)
	rogue, _ := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	_, err := v.Verify(context.Background(), wiaToken(t, rogue, walletKey, nil), popToken(t, walletKey, nil))
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestVerify_RejectsPoPSignedByWrongKey(t *testing.T) {
	anchor, walletKey := testKeys(t)
	_, otherKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	_, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), popToken(t, otherKey, nil))
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	pop := popToken(t, walletKey, func(c jwt.MapClaims) { c["aud"] = "https://evil.example.com/token" })
	_, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), pop)
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestVerify_RejectsReplayedPoPJTI(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{"pop-jti-1": true})

	_, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), popToken(t, walletKey, nil))
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestVerify_RejectsMissingCnf(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	wia := wiaToken(t, anchor, walletKey, func(c jwt.MapClaims) { delete(c, "cnf") })
	_, err := v.Verify(context.Background(), wia, popToken(t, walletKey, nil))
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestVerify_AcceptsPoPWithoutExp(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	pop := popToken(t, walletKey, func(c jwt.MapClaims) {
		delete(c, "exp")
		c["nbf"] = time.Now().Unix()
		c["jti"] = "pop-jti-noexp"
	})

	res, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), pop)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(res.ClientID, "edim.wallet.instance"))
}

func TestVerify_RejectsPoPWithoutExpAndIat(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	pop := popToken(t, walletKey, func(c jwt.MapClaims) {
		delete(c, "exp")
		delete(c, "iat")
		c["jti"] = "pop-jti-nofreshness"
	})

	_, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), pop)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidAttestation))
}

func TestVerify_RejectsPoPWithStaleIatNoExp(t *testing.T) {
	anchor, walletKey := testKeys(t)
	v := testVerifier(anchor, map[string]bool{})

	pop := popToken(t, walletKey, func(c jwt.MapClaims) {
		delete(c, "exp")
		c["iat"] = time.Now().Add(-time.Hour).Unix()
		c["jti"] = "pop-jti-stale"
	})

	_, err := v.Verify(context.Background(), wiaToken(t, anchor, walletKey, nil), pop)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidAttestation))
}
