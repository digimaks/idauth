// SPDX-License-Identifier: EUPL-1.2

// Package dpop validates OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449) proof JWTs.
package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const HeaderName = "DPoP"

var (
	ErrInvalidProof = errors.New("dpop: invalid proof")
	ErrReplay       = errors.New("dpop: jti already used")
)

// ReplayChecker reports whether jti was already seen and records it as seen.
type ReplayChecker func(ctx context.Context, jti string) (bool, error)

type Config struct {
	// AcceptedHTUs are exact request URLs (no query/fragment) proofs may be
	// bound to. Must include externally visible proxy URLs when requests are
	// forwarded (RFC 9449 section 4.3 checks the URL the client used).
	AcceptedHTUs []string
	IATWindow    time.Duration
	ReplayCheck  ReplayChecker
}

type Validator struct {
	htus      map[string]struct{}
	iatWindow time.Duration
	replay    ReplayChecker
}

type proofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	ATH string `json:"ath"`
	jwt.RegisteredClaims
}

func NewValidator(cfg Config) *Validator {
	htus := make(map[string]struct{}, len(cfg.AcceptedHTUs))
	for _, u := range cfg.AcceptedHTUs {
		htus[u] = struct{}{}
	}

	w := cfg.IATWindow
	if w <= 0 {
		w = time.Minute
	}

	return &Validator{htus: htus, iatWindow: w, replay: cfg.ReplayCheck}
}

// Validate checks proof and returns the RFC 7638 thumbprint of the proof key.
// A non-empty accessToken additionally requires a matching ath claim
// (resource-server usage per RFC 9449 section 4.3 step 12).
func (v *Validator) Validate(ctx context.Context, proof, method, accessToken string) (string, error) {
	var jkt string

	claims := &proofClaims{}

	_, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != "dpop+jwt" {
			return nil, fmt.Errorf("%w: typ must be dpop+jwt", ErrInvalidProof)
		}

		raw, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: missing jwk header", ErrInvalidProof)
		}

		pub, tp, err := ParseECJWK(raw)
		if err != nil {
			return nil, err
		}

		jkt = tp

		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Name}))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}

	if claims.IssuedAt == nil {
		return "", fmt.Errorf("%w: iat is required", ErrInvalidProof)
	}

	if d := time.Since(claims.IssuedAt.Time); d > v.iatWindow || d < -v.iatWindow {
		return "", fmt.Errorf("%w: iat outside acceptance window", ErrInvalidProof)
	}

	if claims.HTM != method {
		return "", fmt.Errorf("%w: htm mismatch", ErrInvalidProof)
	}

	if _, ok := v.htus[claims.HTU]; !ok {
		return "", fmt.Errorf("%w: htu not accepted", ErrInvalidProof)
	}

	if claims.ID == "" {
		return "", fmt.Errorf("%w: jti is required", ErrInvalidProof)
	}

	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if claims.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return "", fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
		}
	}

	if v.replay != nil {
		seen, err := v.replay(ctx, claims.ID)
		if err != nil {
			return "", err
		}

		if seen {
			return "", ErrReplay
		}
	}

	return jkt, nil
}
