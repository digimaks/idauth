// SPDX-License-Identifier: EUPL-1.2

package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

const testHTU = "https://as.example.com/api/1.0/token"

func signProof(t *testing.T, key *ecdsa.PrivateKey, raw map[string]any, mutate func(header map[string]any, claims jwt.MapClaims)) string {
	t.Helper()

	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}
	header := map[string]any{"typ": "dpop+jwt", "jwk": raw}

	if mutate != nil {
		mutate(header, claims)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func mapReplayChecker() ReplayChecker {
	seen := map[string]bool{}

	return func(_ context.Context, jti string) (bool, error) {
		if seen[jti] {
			return true, nil
		}

		seen[jti] = true

		return false, nil
	}
}

func testValidator() *Validator {
	return NewValidator(Config{
		AcceptedHTUs: []string{testHTU},
		IATWindow:    time.Minute,
		ReplayCheck:  mapReplayChecker(),
	})
}

func TestValidate_ValidProof(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	jkt, err := v.Validate(context.Background(), signProof(t, key, raw, nil), "POST", "")
	qt.Assert(t, qt.IsNil(err))

	_, wantJKT, err := ParseECJWK(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(jkt, wantJKT))
}

func TestValidate_RejectsWrongTyp(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(h map[string]any, _ jwt.MapClaims) { h["typ"] = "JWT" })

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsMissingJWK(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(h map[string]any, _ jwt.MapClaims) { delete(h, "jwk") })

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsStaleIAT(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["iat"] = time.Now().Add(-5 * time.Minute).Unix()
	})

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsFutureIAT(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["iat"] = time.Now().Add(5 * time.Minute).Unix()
	})

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsWrongHTM(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	_, err := v.Validate(context.Background(), signProof(t, key, raw, nil), "GET", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsUnknownHTU(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["htu"] = "https://evil.example.com/token"
	})

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsMissingJTI(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) { delete(c, "jti") })

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsReplayedJTI(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()
	proof := signProof(t, key, raw, nil)

	_, err := v.Validate(context.Background(), proof, "POST", "")
	qt.Assert(t, qt.IsNil(err))

	_, err = v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrReplay))
}

func TestValidate_ATHRequiredAndMatching(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	sum := sha256.Sum256([]byte("the-access-token"))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) { c["ath"] = ath })

	_, err := v.Validate(context.Background(), proof, "POST", "the-access-token")
	qt.Check(t, qt.IsNil(err))
}

func TestValidate_RejectsATHMismatch(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	_, err := v.Validate(context.Background(), signProof(t, key, raw, nil), "POST", "the-access-token")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsNoneAlg(t *testing.T) {
	_, raw := testJWK(t)
	v := testValidator()

	header := map[string]any{"typ": "dpop+jwt", "alg": "none", "jwk": raw}
	claims := map[string]any{
		"htm": "POST",
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}

	headerJSON, err := json.Marshal(header)
	qt.Assert(t, qt.IsNil(err))
	claimsJSON, err := json.Marshal(claims)
	qt.Assert(t, qt.IsNil(err))

	proof := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "."

	_, err = v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsRS256Alg(t *testing.T) {
	_, raw := testJWK(t)
	v := testValidator()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = raw

	proof, err := tok.SignedString(rsaKey)
	qt.Assert(t, qt.IsNil(err))

	_, err = v.Validate(context.Background(), proof, "POST", "")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}
