// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"time"

	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is the configuration with private key for the auth system middleware.
type Configuration struct {
	StateTTL    time.Duration `mapstructure:"state_ttl" validate:"required,gt=0"`
	AuthCodeTTL time.Duration `mapstructure:"auth_code_ttl" validate:"required,gt=0"`
	PreAuthTTL  time.Duration `mapstructure:"pre_auth_ttl" validate:"required,gt=0"`
	// PARTTL is how long a pushed authorization request stays redeemable.
	PARTTL time.Duration `mapstructure:"par_ttl" validate:"required,gt=0"`
	// RequirePAR, when true, makes /authorizationV3 reject any request
	// that does not carry a request_uri from a prior POST /par.
	RequirePAR bool `mapstructure:"require_par"`
	// Scopes lists the scope values accepted at the authorization endpoint.
	// Empty means the built-in defaults (openid, profile).
	Scopes []string `mapstructure:"scopes" validate:"omitempty,dive,min=1"`
	// RefreshTokenTTL is how long a rotating refresh token stays valid
	// without being used. Each successful grant_type=refresh_token
	// redemption resets this window by issuing a new token with a fresh
	// TTL, so an actively-used wallet never hits it.
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl" validate:"required,gt=0"`
}

// Bind configuration section.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".state_ttl", 5*time.Minute)
	v.SetDefault(prefix+".auth_code_ttl", 1*time.Minute)
	v.SetDefault(prefix+".pre_auth_ttl", 5*time.Minute)
	v.SetDefault(prefix+".par_ttl", 90*time.Second)

	_ = v.BindEnv(prefix+".state_ttl", "IDAUTH_CODE_STATE_TTL")
	_ = v.BindEnv(prefix+".auth_code_ttl", "IDAUTH_CODE_TTL")
	_ = v.BindEnv(prefix+".pre_auth_ttl", "PRE_AUTH_TTL")
	_ = v.BindEnv(prefix+".par_ttl", "IDAUTH_PAR_TTL")
	_ = v.BindEnv(prefix+".require_par", "IDAUTH_REQUIRE_PAR")
	_ = v.BindEnv(prefix+".scopes", "IDAUTH_CODE_SCOPES")

	v.SetDefault(prefix+".refresh_token_ttl", 720*time.Hour)
	_ = v.BindEnv(prefix+".refresh_token_ttl", "IDAUTH_REFRESH_TOKEN_TTL")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	return validate.Struct(c)
}
