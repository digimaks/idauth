// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

// ClientConfig describes one client's OAuth2-shaped (but not OIDC) identity
// provider: a redirect-based authorization-code flow followed by a REST
// userinfo call, with no signed ID token involved.
type ClientConfig struct {
	AuthURL     string `mapstructure:"auth_url" validate:"required,url"`
	TokenURL    string `mapstructure:"token_url" validate:"required,url"`
	UserInfoURL string `mapstructure:"userinfo_url" validate:"required,url"`
	ClientID    string `mapstructure:"client_id" validate:"required"`
	// ClientSecret defaults from YAML, but is overridden by a remote-secret
	// file when present at OAUTH2_GENERIC_<CLIENT_ID>_CLIENT_SECRET_FILE
	// (see loadOAuth2GenericConfig in the parent idauth package), since
	// ClientConfig instances are keyed by operator-chosen client ID in a
	// map rather than a fixed config path like eparaksts.Configuration has.
	ClientSecret string `mapstructure:"client_secret" validate:"required"`
	Scope        string `mapstructure:"scope"`
	// Prompt and UILocales are sent as-is on the authorize redirect when
	// set (e.g. prompt: login, ui_locales: lv), matching what
	// eparaksts.Configuration hardcodes per-instance today.
	Prompt    string `mapstructure:"prompt"`
	UILocales string `mapstructure:"ui_locales"`
	// AcrValues is sent on the authorize redirect for this client's base
	// (non-variant) provider entry — e.g. eParaksts's real IdP requires an
	// acr_values value identifying the flow (urn:eparaksts:...:sc_plugin);
	// always sent even when empty (see buildAuthorizeURL). Each Variant
	// below carries its own AcrValues instead, for that variant's entry.
	AcrValues string `mapstructure:"acr_values"`
	// ClaimFieldMap maps a target core.AuthRequest field name
	// (person_code, first_name, last_name, email) to a source claim in the
	// client's userinfo response, with an optional ordered list of named
	// transforms applied to the value. Fields not listed here are still
	// available downstream via RawClaims (the full decoded response).
	ClaimFieldMap map[string]ClaimMapping `mapstructure:"claim_field_map"`
	// Variants lists additional acr_values-distinguished flows of this same
	// client (e.g. eParaksts's mobileid/sc_plugin variants). Each variant
	// registers as its own provider ID (<base-id>:<variant-id>).
	Variants []Variant `mapstructure:"variants"`
}

// ClaimMapping maps a target field to a source claim key, with an ordered
// list of transforms applied to the claim's value before assignment.
type ClaimMapping struct {
	Source     string          `mapstructure:"source" validate:"required"`
	Transforms []TransformStep `mapstructure:"transforms"`
}

// TransformStep names one transform from the registry in transforms.go,
// plus its arguments.
type TransformStep struct {
	Name string   `mapstructure:"name" validate:"required"`
	Args []string `mapstructure:"args"`
}

// Variant is one acr_values-distinguished flow of the same underlying
// OAuth2 client (same AuthURL/TokenURL/UserInfoURL/ClientID/ClientSecret).
type Variant struct {
	ID        string `mapstructure:"id" validate:"required"`
	AcrValues string `mapstructure:"acr_values"`
}
