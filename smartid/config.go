// SPDX-License-Identifier: EUPL-1.2

package smartid

import (
	"time"

	"azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

type Configuration struct {
	Endpoint                      string        `mapstructure:"endpoint" validate:"required"`
	RelyingPartyName              string        `mapstructure:"relying_party_name" validate:"required"`
	RelyingPartyUUID              string        `mapstructure:"relying_party_uuid" validate:"required"`
	CertificateLevel              string        `mapstructure:"certificate_level" validate:"required"`
	HashType                      string        `mapstructure:"hash_type" validate:"required"`
	InteractionType               string        `mapstructure:"interaction_type" validate:"required"`
	Text                          string        `mapstructure:"text" validate:"required"`
	CreateSessionTimeoutInSeconds int           `mapstructure:"create_session_timeout_in_seconds" validate:"required"`
	CheckSessionTimeoutInSeconds  int           `mapstructure:"check_session_timeout_in_seconds" validate:"required"`
	PresentRetries                int           `mapstructure:"present_retries"`
	PresentWaitInSeconds          int           `mapstructure:"present_wait_in_seconds"`
	PresentTTL                    time.Duration `mapstructure:"present_ttl" validate:"required,gt=0"`
}

func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	relying_party_uuid, _ := config.LoadRemoteSecret("SMARTID_RELYING_PARTY_UUID")

	v.SetDefault(prefix+".endpoint", "https://sid.demo.sk.ee/smart-id-rp/v2")
	v.SetDefault(prefix+".relying_party_name", "DEMO")
	v.SetDefault(prefix+".relying_party_uuid", relying_party_uuid)
	v.SetDefault(prefix+".certificate_level", "QUALIFIED")
	v.SetDefault(prefix+".hash_type", "SHA512")
	v.SetDefault(prefix+".interaction_type", "displayTextAndPIN")
	v.SetDefault(prefix+".text", "Custom text")
	v.SetDefault(prefix+".create_session_timeout_in_seconds", 90)
	v.SetDefault(prefix+".check_session_timeout_in_seconds", 1)

	v.SetDefault(prefix+".present_retries", 24)
	v.SetDefault(prefix+".present_wait_in_seconds", 5)
	v.SetDefault(prefix+".present_ttl", 10*time.Minute)

	_ = v.BindEnv(prefix+".endpoint", "SMARTID_ENDPOINT")
	_ = v.BindEnv(prefix+".relying_party_name", "SMARTID_RELYING_PARTY_NAME")
	_ = v.BindEnv(prefix+".relying_party_uuid", "SMARTID_RELYING_PARTY_UUID")
	_ = v.BindEnv(prefix+".certificate_level", "SMARTID_CERT_LEVEL")
	_ = v.BindEnv(prefix+".hash_type", "SMARTID_HASH_TYPE")
	_ = v.BindEnv(prefix+".interaction_type", "SMARTID_INTERACTION")
	_ = v.BindEnv(prefix+".text", "SMARTID_TEXT")
	_ = v.BindEnv(prefix+".create_session_timeout_in_seconds", "SMARTID_CREATE_TIMEOUT")
	_ = v.BindEnv(prefix+".check_session_timeout_in_seconds", "SMARTID_CHECK_TIMEOUT")
	_ = v.BindEnv(prefix+".present_retries", "SMARTID_PRESENT_RETRIES")
	_ = v.BindEnv(prefix+".present_wait_in_seconds", "SMARTID_WAIT_IN_SECONDS")
	_ = v.BindEnv(prefix+".present_ttl", "SMARTID_CACHE_TTL")
}

func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
