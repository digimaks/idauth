// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/clientattestation"
	"github.com/digimaks/idauth/dpop"
	"github.com/digimaks/idauth/oauth2generic"
	"github.com/digimaks/idauth/smartid"
	"github.com/digimaks/idauth/store"
	idauth "github.com/lx-lib/lx-idauth"

	"azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"azugo.io/opentelemetry"
	"github.com/digimaks/go-verifier"
	"github.com/lx-lib/lx-idauth/app"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/spf13/viper"
)

// Configuration represents the configuration for the application.
type Configuration struct {
	*app.Configuration `mapstructure:",squash"`
	Telemetry          *opentelemetry.Configuration           `mapstructure:"telemetry" validate:"omitempty"`
	Store              *store.Configuration                   `mapstructure:"store" validate:"omitempty"`
	Audit              *audit.Configuration                   `mapstructure:"audit" validate:"omitempty"`
	Verifier           *verifier.Configuration                `mapstructure:"verifier"`
	SmartID            *smartid.Configuration                 `mapstructure:"smartid"`
	OAuth2Generic      map[string]*oauth2generic.ClientConfig `mapstructure:"oauth2_generic" validate:"omitempty,dive"`
	// OAuth2GenericConfigFile, when set, is loaded separately (see
	// loadOAuth2GenericConfig) into OAuth2Generic above, since providers are
	// keyed by operator-chosen client ID rather than a fixed config path.
	OAuth2GenericConfigFile string                           `mapstructure:"oauth2_generic_config_file" validate:"omitempty"`
	AuthorizationCode       *authorizationcode.Configuration `mapstructure:"auth_code"`
	DPoP                    *dpop.Configuration              `mapstructure:"dpop"`
	ClientAttestation       *clientattestation.Configuration `mapstructure:"client_attestation"`
	IdauthPublicURL         string                           `mapstructure:"idauth_api_public_url" validate:"required,url"`
	AndroidAppPackage       string                           `mapstructure:"android_app_package" validate:"omitempty"`
	AndroidAppFingerprints  []string                         `mapstructure:"android_app_fingerprints" validate:"omitempty"`
	AppleAppIDs             []string                         `mapstructure:"apple_app_ids" validate:"omitempty"`

	// RequireIntrospectionAuth, when true, rejects /introspection calls
	// that don't carry valid client Basic auth. When false (default),
	// Basic auth is validated if present but not required — this is the
	// staged-rollout state until all introspecting clients (today, only
	// issuer-go) are confirmed sending it.
	RequireIntrospectionAuth bool `mapstructure:"require_introspection_auth"`

	// RequireClientAttestationPreauth, when true, rejects pre-authorized_code
	// token requests that don't carry a valid OAuth-Client-Attestation (WIA) +
	// OAuth-Client-Attestation-PoP pair. When false (default), the attestation
	// is verified if present but not required — this is the staged-rollout
	// state until all mobile app versions are confirmed sending it.
	RequireClientAttestationPreauth bool `mapstructure:"require_client_attestation_preauth"`
}

func (c *Configuration) ExposedConfig() *idauth.Configuration {
	return c.Configuration.ExposedConfig()
}

// NewConfiguration returns a new configuration.
func NewConfiguration() *Configuration {
	return &Configuration{
		Configuration: app.NewConfiguration(),
	}
}

// ServerCore returns the core configuration.
func (c *Configuration) ServerCore() *config.Configuration {
	return c.Configuration.Configuration
}

func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.Configuration.Bind("", v)

	c.Telemetry = config.Bind(c.Telemetry, "telemetry", v)
	c.Store = config.Bind(c.Store, "store", v)
	c.Audit = config.Bind(c.Audit, "audit", v)
	c.Verifier = config.Bind(c.Verifier, "verifier", v)
	c.SmartID = config.Bind(c.SmartID, "smartid", v)
	c.AuthorizationCode = config.Bind(c.AuthorizationCode, "auth_code", v)
	c.DPoP = config.Bind(c.DPoP, "dpop", v)
	c.ClientAttestation = config.Bind(c.ClientAttestation, "client_attestation", v)

	_ = v.BindEnv("oauth2_generic_config_file", "IDAUTH_OAUTH2_GENERIC_CONFIG_FILE")
	_ = v.BindEnv("idauth_api_public_url", "IDAUTH_API_PUBLIC_URL")
	_ = v.BindEnv("android_app_package", "ANDROID_APP_PACKAGE")

	androidAppFingerprints, _ := corecfg.LoadRemoteSecret("ANDROID_APP_FINGERPRINTS")
	v.SetDefault("android_app_fingerprints", androidAppFingerprints)
	_ = v.BindEnv("android_app_fingerprints", "ANDROID_APP_FINGERPRINTS")
	_ = v.BindEnv("apple_app_ids", "APPLE_APP_IDS")
	_ = v.BindEnv("require_introspection_auth", "IDAUTH_REQUIRE_INTROSPECTION_AUTH")
	_ = v.BindEnv("require_client_attestation_preauth", "IDAUTH_REQUIRE_CLIENT_ATTESTATION_PREAUTH")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if err := c.Telemetry.Validate(validate); err != nil {
		return err
	}

	// Validate core configuration
	if err := c.Configuration.Configuration.Validate(validate); err != nil {
		return err
	}

	// Only validate Postgres if session store type is postgres
	if c.SessionStoreType == "postgres" {
		if c.Postgres != nil {
			if err := validate.Struct(c.Postgres); err != nil {
				return err
			}
		}
	}

	if err := c.Store.Validate(validate); err != nil {
		return err
	}

	if err := c.Audit.Validate(validate); err != nil {
		return err
	}

	if err := c.Verifier.Validate(validate); err != nil {
		return err
	}

	if err := c.SmartID.Validate(validate); err != nil {
		return err
	}

	if err := c.AuthorizationCode.Validate(validate); err != nil {
		return err
	}

	if err := c.DPoP.Validate(validate); err != nil {
		return err
	}

	if err := c.ClientAttestation.Validate(validate); err != nil {
		return err
	}

	// Validate this struct but exclude the embedded Configuration to avoid postgres validation
	if err := validate.StructExcept(c, "Configuration"); err != nil {
		return err
	}

	return nil
}
