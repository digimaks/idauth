// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"azugo.io/azugo"
	"github.com/lx-lib/lx-idauth/core"
)

type authProvider struct {
	providers map[string]*core.AuthProviderConfig
}

func newAuthProvider(cfg *Configuration) *authProvider {
	providers := map[string]*core.AuthProviderConfig{
		"edim": {
			ID:    "edim",
			Type:  "edim",
			Realm: "",
		},
		"edim:same_device": {
			ID:    "edim:same_device",
			Type:  "edim",
			Realm: "",
		},
		"smartid": {
			ID:    "smartid",
			Type:  "smartid",
			Realm: "",
		},
	}

	for id, clientCfg := range cfg.OAuth2Generic {
		id := strings.ToLower(id)
		providers[id] = &core.AuthProviderConfig{
			ID:   id,
			Type: "oauth2generic",
		}

		for _, variant := range clientCfg.Variants {
			variantID := id + ":" + strings.ToLower(variant.ID)
			providers[variantID] = &core.AuthProviderConfig{
				ID:   variantID,
				Type: "oauth2generic",
			}
		}
	}

	return &authProvider{
		providers: providers,
	}
}

func (a *authProvider) GetAllProviders() ([]*core.AuthProviderConfig, error) {
	return slices.Collect(maps.Values(a.providers)), nil
}

// GetUserData returns the user data for the given request.
func (a *authProvider) GetUserData(_ *azugo.Context, data *core.GetUserDataRequest) (*core.UserData, error) {
	return &core.UserData{
		UserID:     data.Code,
		PersonCode: data.Code,
		FirstName:  data.FirstName,
		LastName:   data.LastName,
	}, nil
}

func (a *authProvider) GetAvailableProviders(_ string) ([]*core.AuthProviderConfig, error) {
	return slices.Collect(maps.Values(a.providers)), nil
}

func (a *authProvider) GetProvider(id string) (*core.AuthProviderConfig, error) {
	if provider, ok := a.providers[id]; ok {
		return provider, nil
	}

	return nil, errors.New("provider not found")
}
