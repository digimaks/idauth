// SPDX-License-Identifier: EUPL-1.2

// Package clientattestation verifies OAuth 2.0 attestation-based client
// authentication (attest_jwt_client_auth): the OAuth-Client-Attestation
// header carries the Wallet Instance Attestation (WIA) signed by the wallet
// provider, and OAuth-Client-Attestation-PoP proves possession of the WIA
// cnf key.
package clientattestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/digimaks/idauth/dpop"
)

const (
	typWIA = "oauth-client-attestation+jwt"
	typPoP = "oauth-client-attestation-pop+jwt"
)

// ErrInvalidAttestation is returned when WIA or PoP validation fails.
var ErrInvalidAttestation = errors.New("clientattestation: invalid attestation")

// ReplayChecker reports whether jti was already seen and records it as seen.
type ReplayChecker func(ctx context.Context, jti string) (bool, error)

// Config holds the verifier configuration.
type Config struct {
	// TrustAnchors are the root CA certificates trusted to anchor the WIA's
	// x5c certificate chain (RFC 7515 §4.1.6, RFC 5280 §6).
	TrustAnchors *x509.CertPool
	Audiences    []string
	IATWindow    time.Duration
	ReplayCheck  ReplayChecker
	// RequireKeyBinding enforces c-rr TS3 (DPoP key == WIA cnf key) at the
	// token endpoints. Disabled for EUDI reference wallet interop (it mints
	// an ephemeral DPoP key per request).
	RequireKeyBinding bool
}

// Verifier checks OAuth-Client-Attestation + OAuth-Client-Attestation-PoP headers.
type Verifier struct {
	trustAnchors      *x509.CertPool
	audiences         map[string]struct{}
	iatWindow         time.Duration
	replay            ReplayChecker
	requireKeyBinding bool
}

// RequireKeyBinding reports whether the DPoP proof key must equal the WIA cnf key.
func (v *Verifier) RequireKeyBinding() bool { return v.requireKeyBinding }

// Result is the outcome of a successful attestation check.
type Result struct {
	// ClientID is the WIA subject — the wallet client identifier.
	ClientID string
	// CnfJKT is the RFC 7638 thumbprint of the WIA cnf.jwk key. Per the
	// c-rr TS3 profile it must equal the DPoP proof key thumbprint.
	CnfJKT string
}

// NewVerifier creates a Verifier from cfg.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.TrustAnchors == nil {
		return nil, errors.New("clientattestation: at least one trust anchor is required")
	}

	aud := make(map[string]struct{}, len(cfg.Audiences))
	for _, a := range cfg.Audiences {
		aud[a] = struct{}{}
	}

	window := cfg.IATWindow
	if window <= 0 {
		window = time.Minute
	}

	return &Verifier{
		trustAnchors:      cfg.TrustAnchors,
		audiences:         aud,
		iatWindow:         window,
		replay:            cfg.ReplayCheck,
		requireKeyBinding: cfg.RequireKeyBinding,
	}, nil
}

// leafKeyFromX5C validates the WIA's x5c certificate chain (RFC 7515
// §4.1.6) against the configured trust anchors per RFC 5280 §6 and returns
// the leaf certificate's public key, which the caller then uses to verify
// the JWT signature. T3 requires x5c specifically — kid/jwk headers are
// never consulted.
func (v *Verifier) leafKeyFromX5C(header map[string]any) (*ecdsa.PublicKey, error) {
	raw, ok := header["x5c"].([]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("clientattestation: WIA header missing x5c")
	}

	certs := make([]*x509.Certificate, 0, len(raw))

	for i, entry := range raw {
		s, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("clientattestation: x5c[%d] is not a string", i)
		}

		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("clientattestation: x5c[%d] base64: %w", i, err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("clientattestation: x5c[%d] parse: %w", i, err)
		}

		certs = append(certs, cert)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	leaf := certs[0]

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.trustAnchors,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("clientattestation: x5c chain: %w", err)
	}

	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("clientattestation: x5c leaf key is %T, want EC", leaf.PublicKey)
	}

	return key, nil
}

type wiaClaims struct {
	Cnf struct {
		JWK map[string]any `json:"jwk"`
	} `json:"cnf"`
	jwt.RegisteredClaims
}

// Verify checks wia (WIA JWT) and pop (PoP JWT), returning the attested client ID and cnf key thumbprint.
func (v *Verifier) Verify(ctx context.Context, wia, pop string) (*Result, error) {
	if wia == "" || pop == "" {
		return nil, fmt.Errorf("%w: missing attestation or PoP", ErrInvalidAttestation)
	}

	claims := &wiaClaims{}

	tok, err := jwt.ParseWithClaims(
		wia, claims,
		func(tok *jwt.Token) (any, error) { return v.leafKeyFromX5C(tok.Header) },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil || tok == nil || !tok.Valid {
		return nil, fmt.Errorf("%w: WIA signature: %w", ErrInvalidAttestation, err)
	}

	if typ, _ := tok.Header["typ"].(string); typ != typWIA {
		return nil, fmt.Errorf("%w: WIA typ %q", ErrInvalidAttestation, typ)
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: WIA sub missing", ErrInvalidAttestation)
	}

	if claims.Cnf.JWK == nil {
		return nil, fmt.Errorf("%w: WIA cnf.jwk missing", ErrInvalidAttestation)
	}

	cnfKey, jkt, err := dpop.ParseECJWK(claims.Cnf.JWK)
	if err != nil {
		return nil, fmt.Errorf("%w: WIA cnf.jwk: %w", ErrInvalidAttestation, err)
	}

	popClaims := &jwt.RegisteredClaims{}

	// exp is not required: the EUDI reference wallet's PoP carries only
	// iss/aud/jti/iat/nbf. Freshness is enforced below via iat when exp is
	// absent (exp/nbf are still validated by the parser when present).
	popTok, err := jwt.ParseWithClaims(
		pop, popClaims,
		func(*jwt.Token) (any, error) { return cnfKey, nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithLeeway(v.iatWindow),
	)
	if err != nil || !popTok.Valid {
		return nil, fmt.Errorf("%w: PoP: %w", ErrInvalidAttestation, err)
	}

	if popClaims.ExpiresAt == nil {
		if popClaims.IssuedAt == nil {
			return nil, fmt.Errorf("%w: PoP must carry exp or iat", ErrInvalidAttestation)
		}

		if d := time.Since(popClaims.IssuedAt.Time); d > v.iatWindow || d < -v.iatWindow {
			return nil, fmt.Errorf("%w: PoP iat outside acceptance window", ErrInvalidAttestation)
		}
	}

	if typ, _ := popTok.Header["typ"].(string); typ != typPoP {
		return nil, fmt.Errorf("%w: PoP typ %q", ErrInvalidAttestation, typ)
	}

	if popClaims.Issuer != claims.Subject {
		return nil, fmt.Errorf("%w: PoP iss != WIA sub", ErrInvalidAttestation)
	}

	audOK := false

	for _, a := range popClaims.Audience {
		if _, ok := v.audiences[a]; ok {
			audOK = true
			break
		}
	}

	if !audOK {
		return nil, fmt.Errorf("%w: PoP aud not accepted", ErrInvalidAttestation)
	}

	if popClaims.ID == "" {
		return nil, fmt.Errorf("%w: PoP jti missing", ErrInvalidAttestation)
	}

	if v.replay != nil {
		seen, err := v.replay(ctx, popClaims.ID)
		if err == nil && seen {
			return nil, fmt.Errorf("%w: PoP jti replayed", ErrInvalidAttestation)
		}
	}

	return &Result{ClientID: claims.Subject, CnfJKT: jkt}, nil
}
