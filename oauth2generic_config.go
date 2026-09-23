// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"strings"

	"github.com/digimaks/idauth/oauth2generic"

	corecfg "azugo.io/core/config"
	"github.com/spf13/viper"
)

// loadOAuth2GenericConfig reads config.OAuth2GenericConfigFile (if set) and
// decodes its "oauth2_generic" key into config.OAuth2Generic. Uses viper
// (not a plain YAML decoder) so the same mapstructure tags already on
// oauth2generic.ClientConfig (auth_url, client_id, ...) apply here too —
// a plain yaml.Unmarshal would instead match yaml.v3's default lowercased
// field names (authurl, clientid, ...), silently leaving every field empty.
func loadOAuth2GenericConfig(config *Configuration) error {
	if config.OAuth2GenericConfigFile == "" {
		return nil
	}

	v := viper.New()
	v.SetConfigFile(config.OAuth2GenericConfigFile)

	if err := v.ReadInConfig(); err != nil {
		return err
	}

	var clients map[string]*oauth2generic.ClientConfig
	if err := v.UnmarshalKey("oauth2_generic", &clients); err != nil {
		return err
	}

	// Since each client is keyed by an operator-chosen ID in a map (rather
	// than a fixed config path like eparaksts.Configuration.Bind has), the
	// remote-secret lookup key is derived per client ID:
	// OAUTH2_GENERIC_<CLIENT_ID>_CLIENT_SECRET. Falls back to the YAML value
	// (config.LoadRemoteSecret returns "" when unset) if no override exists.
	for id, client := range clients {
		envKey := "OAUTH2_GENERIC_" + strings.ToUpper(id) + "_CLIENT_SECRET"

		if secret, _ := corecfg.LoadRemoteSecret(envKey); secret != "" {
			client.ClientSecret = secret
		}
	}

	config.OAuth2Generic = clients

	return nil
}
