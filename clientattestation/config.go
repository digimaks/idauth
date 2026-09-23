// SPDX-License-Identifier: EUPL-1.2

package clientattestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration holds the viper-bound configuration for client attestation.
type Configuration struct {
	// TrustAnchorsFile is a PEM file with the wallet-provider public keys
	// or certificates trusted to sign WIAs.
	TrustAnchorsFile string `mapstructure:"trust_anchors_file" validate:"omitempty"`
	// AcceptedAudiences lists additional PoP `aud` values accepted besides
	// idauth's own token endpoint (e.g. the wallet-facing proxy /token URL
	// during the transition period).
	AcceptedAudiences []string      `mapstructure:"accepted_aud" validate:"omitempty,dive,url"`
	IATWindow         time.Duration `mapstructure:"iat_window" validate:"required,gt=0"`
	// RequireKeyBinding enforces the WIA cnf/DPoP key binding added in TS3
	// v1.5.1 and rolled back in TS3 v1.5.2 (2026-05-26, §2.2.1.1) — no
	// longer normative. Kept as an opt-in for environments that still want
	// it; default is off.
	RequireKeyBinding bool `mapstructure:"require_key_binding"`
}

// Bind configuration section.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".iat_window", time.Minute)
	v.SetDefault(prefix+".require_key_binding", false)
	_ = v.BindEnv(prefix+".trust_anchors_file", "CLIENT_ATTESTATION_TRUST_ANCHORS_FILE")
	_ = v.BindEnv(prefix+".accepted_aud", "CLIENT_ATTESTATION_ACCEPTED_AUD")
	_ = v.BindEnv(prefix+".iat_window", "CLIENT_ATTESTATION_IAT_WINDOW")
	_ = v.BindEnv(prefix+".require_key_binding", "CLIENT_ATTESTATION_REQUIRE_KEY_BINDING")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	return validate.Struct(c)
}

// LoadTrustAnchors reads root CA certificates from the configured PEM file.
// These anchor the x5c certificate chain carried in the WIA JOSE header
// (RFC 7515 §4.1.6); only CERTIFICATE blocks are accepted, since a bare
// public key cannot anchor an x509 chain (RFC 5280 §6).
func (c *Configuration) LoadTrustAnchors() (*x509.CertPool, error) {
	if c.TrustAnchorsFile == "" {
		return nil, nil
	}

	buf, err := os.ReadFile(c.TrustAnchorsFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()

	var found bool

	for {
		var block *pem.Block

		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			// Skip anything that isn't a certificate — in particular
			// private-key blocks (EC PRIVATE KEY, PRIVATE KEY, ENCRYPTED
			// PRIVATE KEY, ...), which must never be loaded as a trust
			// anchor.
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("clientattestation: parsing certificate block: %w", err)
		}

		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("clientattestation: trust anchor is not an EC key (%T)", cert.PublicKey)
		}

		pool.AddCert(cert)

		found = true
	}

	if !found {
		return nil, errors.New("clientattestation: no certificates found in trust anchors file")
	}

	return pool, nil
}
