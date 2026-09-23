// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestApp for unit testing.
func TestApp(t testing.TB) *App {
	_, b, _, _ := runtime.Caller(1)

	t.Setenv("METRICS_ENABLED", "false")

	// Find the testdata directory. If the test is in a subdirectory (e.g., routes/),
	// go up one level; otherwise use the current directory.
	testdir := filepath.Dir(b)
	if filepath.Base(filepath.Dir(testdir)) == "idauth" {
		// Test is in a subdirectory of idauth (e.g., routes/token_test.go)
		testdir = filepath.Dir(testdir)
	}

	clientsFile := filepath.Join(testdir, "testdata", "clients.yaml")
	t.Setenv("IDAUTH_STORE_CLIENTS_FILE", clientsFile)

	attestFile := filepath.Join(testdir, "testdata", "attestation_trust.pem")
	t.Setenv("CLIENT_ATTESTATION_TRUST_ANCHORS_FILE", attestFile)

	// Postgres config (required even for cache-based tests due to validation)
	t.Setenv("POSTGRES_HOST", "localhost")
	t.Setenv("POSTGRES_PORT", "5432")
	t.Setenv("POSTGRES_USER", "test")
	t.Setenv("POSTGRES_PASSWORD", "test")
	t.Setenv("POSTGRES_DB", "test")

	t.Setenv("VERIFIER_BACKEND_URL", "https://sso.example.com/verifier")
	t.Setenv("VERIFIER_CACHE_TTL", "10m")
	t.Setenv("EDIM_TEMPLATE_PATH", filepath.Join(testdir, "edim", "pid-template.json"))
	t.Setenv("VERIFIER_ENGINE", "v2")
	t.Setenv("VERIFIER_V2_URL", "https://sso.example.com/verifier-v2")
	t.Setenv("VERIFIER_V2_API_KEY", "test-key")

	t.Setenv("SMARTID_RELYING_PARTY_UUID", "00000000-0000-0000-0000-000000000000")

	t.Setenv("AUDIT_ENDPOINT", "https://sso.example.com/audit")
	t.Setenv("IDAUTH_API_PUBLIC_URL", "https://sso.example.com/auth")

	app, err := New(nil, "", "1.0.0-test")
	qt.Assert(t, qt.IsNil(err))

	return app
}
