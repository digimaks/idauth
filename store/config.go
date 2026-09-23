// SPDX-License-Identifier: EUPL-1.2

package store

import (
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

type Configuration struct {
	ClientPath string `mapstructure:"clients_file"`
}

// Validate OpenTracing configuration section.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}

// Bind OpenTracing configuration section.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".clients_file", "config/clients.yaml")

	_ = v.BindEnv(prefix+".clients_file", "IDAUTH_STORE_CLIENTS_FILE")
}
