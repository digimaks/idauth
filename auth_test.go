// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"testing"

	"github.com/digimaks/idauth/oauth2generic"
	"github.com/go-quicktest/qt"
)

func TestNewAuthProvider_IncludesConfiguredOAuth2GenericClients(t *testing.T) {
	cfg := &Configuration{
		OAuth2Generic: map[string]*oauth2generic.ClientConfig{
			"acme": {AuthURL: "https://acme.example/authorize", TokenURL: "https://acme.example/token", UserInfoURL: "https://acme.example/userinfo", ClientID: "id"},
		},
	}

	ap := newAuthProvider(cfg)

	provider, err := ap.GetProvider("acme")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(provider.ID, "acme"))
	qt.Check(t, qt.Equals(provider.Type, "oauth2generic"))

	// Existing static providers (edim, smartid) must still be present.
	_, err = ap.GetProvider("smartid")
	qt.Check(t, qt.IsNil(err))
}

func TestNewAuthProvider_IncludesOAuth2GenericVariants(t *testing.T) {
	cfg := &Configuration{
		OAuth2Generic: map[string]*oauth2generic.ClientConfig{
			"eparaksts": {
				AuthURL: "https://eparaksts.example/authorize", TokenURL: "https://eparaksts.example/token", UserInfoURL: "https://eparaksts.example/userinfo", ClientID: "id",
				Variants: []oauth2generic.Variant{
					{ID: "mobileid", AcrValues: "urn:eparaksts:authentication:flow:mobileid"},
					{ID: "sc_plugin", AcrValues: "urn:eparaksts:authentication:flow:sc_plugin"},
				},
			},
		},
	}

	ap := newAuthProvider(cfg)

	base, err := ap.GetProvider("eparaksts")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(base.Type, "oauth2generic"))

	mobileid, err := ap.GetProvider("eparaksts:mobileid")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(mobileid.ID, "eparaksts:mobileid"))
	qt.Check(t, qt.Equals(mobileid.Type, "oauth2generic"))

	scPlugin, err := ap.GetProvider("eparaksts:sc_plugin")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(scPlugin.ID, "eparaksts:sc_plugin"))
}
