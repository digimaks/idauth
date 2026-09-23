// SPDX-License-Identifier: EUPL-1.2

// Package svcerrors provides fine-grained, service-local error codes for
// idauth's HTTP responses. Codes are carried on the X-Error-Code response
// header so the token endpoint's spec-mandated JSON body ({error,
// error_description}) stays unchanged while still letting a caller identify
// exactly which internal check failed. Codes are also attached as an
// OpenTelemetry span attribute for APM-side filtering.
package svcerrors

import (
	"azugo.io/azugo"
	"azugo.io/opentelemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Code identifies a specific failure point. Values are added incrementally,
// one per meaningful failure site.
type Code string

// HeaderErrorCode is the response header carrying the Code on a failed request.
const HeaderErrorCode = "X-Error-Code"

// client_credentials grant failure codes (idauth/routes/token.go, handleClientCredentials).
// Only the codes for paths that still write the RFC 6749 {error, error_description}
// body remain here; paths that go through ctx.Error use pkerrors.NewProblem instead
// (see errors_taxonomy.go).
const (
	ClientCredentialsUnsupportedAssertionType Code = "client_credentials_unsupported_assertion_type"
	ClientCredentialsAssertionInvalid         Code = "client_credentials_assertion_invalid"
)

// authorization_code grant failure codes (idauth/authorizationcode/token.go, HandleAuthorization).
// Only the codes for paths that still write the RFC 6749 {error, error_description}
// body remain here; paths that go through ctx.Error use pkerrors.NewProblem instead
// (see errors_taxonomy.go).
const (
	AuthCodeMissingAuthHeader    Code = "auth_code_missing_auth_header"
	AuthCodeInvalidClient        Code = "auth_code_invalid_client"
	AuthCodeInvalidOrExpiredCode Code = "auth_code_invalid_or_expired_code"
	AuthCodeRedirectURIMismatch  Code = "auth_code_redirect_uri_mismatch"
)

// DPoP proof failure codes (idauth/routes/token.go, dpopJKT).
const (
	TokenDPoPProofMissing Code = "token_dpop_proof_missing"
	TokenDPoPProofInvalid Code = "token_dpop_proof_invalid"
)

// refresh_token grant failure codes (idauth/authorizationcode/token.go, HandleRefreshToken).
const (
	RefreshTokenInvalidOrExpired Code = "refresh_token_invalid_or_expired"
)

// pre-authorized_code grant client attestation failure codes
// (idauth/authorizationcode/token.go, HandlePreAuthorized).
const (
	PreAuthAttestationRequired Code = "preauth_attestation_required"
	PreAuthInvalidClient       Code = "preauth_invalid_client"
)

// /introspection auth failure codes (idauth/routes/introspection.go).
const (
	IntrospectionInvalidClient Code = "introspection_invalid_client"
	IntrospectionAuthRequired  Code = "introspection_auth_required"
)

// SetHeader attaches code to the response as X-Error-Code, and to the
// current OpenTelemetry span as an "error_code" attribute for APM filtering.
// Call it immediately before writing the error status/body.
func SetHeader(ctx *azugo.Context, code Code) {
	ctx.Header.Set(HeaderErrorCode, string(code))

	span := trace.SpanFromContext(opentelemetry.FromContext(ctx))
	span.SetAttributes(attribute.String("error_code", string(code)))
}
