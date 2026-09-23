// SPDX-License-Identifier: EUPL-1.2

// Package idauth registers idauth's error taxonomy reasons for the
// pre-authorized_code grant (see authorizationcode/token.go,
// HandlePreAuthorized) with go-platform-kit, so pkerrors.NewProblem derives
// status and title without WithStatus at every call site.
package idauth

import (
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/valyala/fasthttp"
)

func init() {
	pkerrors.RegisterReason("preAuthCodeMissing", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Missing pre-authorized code"})
	pkerrors.RegisterReason("preAuthCodeInvalidOrExpired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid or expired pre-authorized code"})
	pkerrors.RegisterReason("preAuthTXCodeInvalid", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid transaction code"})
	pkerrors.RegisterReason("preAuthSessionCreateFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Failed to create session"})

	// /token domain — client_credentials and authorization_code grants
	// (idauth/routes/token.go, idauth/authorizationcode/token.go). Registered
	// only for the internal-error paths that don't need to preserve the
	// RFC 6749 {error, error_description} body shape.
	pkerrors.RegisterReason("invalidRequestBody", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid request body"})
	pkerrors.RegisterReason("audienceBuildFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("assertionParseFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("sessionCreateFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("authHeaderInvalid", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid authorization header"})
	pkerrors.RegisterReason("clientLookupFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("auditFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("cleanupFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// /preauth_generate domain (idauth/routes/preauth.go).
	pkerrors.RegisterReason("scopeRequired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Missing scope"})
	pkerrors.RegisterReason("itemStoreFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("txCodeStoreFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// /callback/{provider} domain — correlation lookup (idauth/correlation.go,
	// correlationStore wrapper). Vendored github.com/lx-lib/lx-idauth's own
	// callback handler treats a missing/expired correlation as a bare
	// errors.New("no session"), which falls through to err:internal:unexpected.
	// The wrapper below turns that into this coded reason before it reaches
	// the vendored handler.
	pkerrors.RegisterReason("correlationNotFound", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Session expired or not found"})
}
