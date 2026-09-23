// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestLoadOAuth2GenericConfig_NoFileConfigured(t *testing.T) {
	config := &Configuration{}

	err := loadOAuth2GenericConfig(config)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNil(config.OAuth2Generic))
}

func TestLoadOAuth2GenericConfig_ReadsYAMLAndAppliesRemoteSecretOverride(t *testing.T) {
	dir := t.TempDir()

	secretPath := filepath.Join(dir, "secret")
	qt.Assert(t, qt.IsNil(os.WriteFile(secretPath, []byte("secret-from-file\n"), 0o600)))
	t.Setenv("OAUTH2_GENERIC_TESTCLIENT_CLIENT_SECRET_FILE", secretPath)

	configPath := filepath.Join(dir, "oauth2_generic.yaml")
	yaml := `
oauth2_generic:
  testclient:
    auth_url: https://idp.example/authorize
    token_url: https://idp.example/token
    userinfo_url: https://idp.example/userinfo
    client_id: test-client
    client_secret: secret-from-yaml
`
	qt.Assert(t, qt.IsNil(os.WriteFile(configPath, []byte(yaml), 0o600)))

	config := &Configuration{OAuth2GenericConfigFile: configPath}

	err := loadOAuth2GenericConfig(config)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(config.OAuth2Generic, 1))

	client, ok := config.OAuth2Generic["testclient"]
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(client.AuthURL, "https://idp.example/authorize"))
	qt.Check(t, qt.Equals(client.ClientSecret, "secret-from-file"))
}
