// SPDX-License-Identifier: EUPL-1.2

package dpop

import (
	"time"

	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration for DPoP proof validation at the token endpoint.
type Configuration struct {
	// AcceptedHTU lists additional accepted proof htu URLs, e.g. the
	// wallet-facing api-wallet-digimaks /token URL that proxies here.
	AcceptedHTU []string      `mapstructure:"accepted_htu" validate:"omitempty,dive,url"`
	IATWindow   time.Duration `mapstructure:"iat_window" validate:"required,gt=0"`
}

// Bind configuration section.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".iat_window", time.Minute)

	_ = v.BindEnv(prefix+".accepted_htu", "DPOP_ACCEPTED_HTU")
	_ = v.BindEnv(prefix+".iat_window", "DPOP_IAT_WINDOW")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	return validate.Struct(c)
}
