// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package response

// TokenResponse is a response for token request.
type TokenResponse struct {
	// AccessToken is the token to access the requested resource.
	AccessToken string `json:"access_token" example:"01JEV9YKN41Q1QX6Y2VX69VNJM"`
	// TokenType is the type of the token.
	TokenType string `json:"token_type" example:"Bearer"`
	// ExpiresIn is the time in seconds until the token expires.
	ExpiresIn int `json:"expires_in,omitempty" example:"3600"`
	// Scope is the scope of the token.
	Scope string `json:"scope,omitempty" example:"api:read api:write api:read api:write"`
	// RefreshToken is issued alongside DPoP-bound access tokens on the
	// authorization_code grant, for silent re-issuance (ARF ISSU_63/65).
	// Absent for non-DPoP (BFF-style) redemptions.
	RefreshToken string `json:"refresh_token,omitempty" example:"01JEV9YKN41Q1QX6Y2VX69VNJM.7hN2..."`
}

// TokenResponseError is a response for token request error.
type TokenResponseError struct {
	// Type of the error.
	Type string `json:"error" example:"invalid_client"`
	// Description of the error.
	Description string `json:"error_description" example:"assertion has expired"`
}

func (t *TokenResponseError) Error() string {
	return t.Type
}
