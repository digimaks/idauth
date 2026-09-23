// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package request

// TokenRequest is a request to get a token.
type TokenRequest struct {
	// GrantType is the grant type of the token request
	GrantType string `json:"grant_type" validate:"required" example:"client_credentials"`
	// Scope to request for the token
	Scope string `json:"scope" example:"admin/wallet:delete"`
	// ClientID is the ID of the client requesting the token
	ClientID string `json:"client_id"`
	// ClientAssertionType is the type of the client assertion
	ClientAssertionType string `json:"client_assertion_type" example:"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
	// ClientAssertion is the assertion of the client
	ClientAssertion string `json:"client_assertion" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdW..."`
	// added for authorization_code grant type

	// Code is the authorization code
	Code string `json:"code"`
	// RedirectURI is the URI to redirect to
	RedirectURI string `json:"redirect_uri"`
	// ClientSecret is the secret of the client
	ClientSecret string `json:"client_secret"`
	// CodeVerifier is the verifier of the code
	CodeVerifier string `json:"code_verifier"`
}
