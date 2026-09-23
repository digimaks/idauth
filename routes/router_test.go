// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	"github.com/digimaks/idauth"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
)

// testApp returns a fully started azugo.TestApp for route-level tests.
func testApp(t testing.TB) *azugo.TestApp {
	app := idauth.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

// testAppRaw returns the *idauth.App before wrapping it in azugo.TestApp.
// Use this when the test needs to call App methods (e.g. AuthCodeStore) directly.
func testAppRaw(t testing.TB) *idauth.App {
	app := idauth.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return app
}

// azugoTestApp wraps an already-initialised *idauth.App in azugo.TestApp.
func azugoTestApp(t testing.TB, app *idauth.App) *azugo.TestApp {
	return azugo.NewTestApp(app.App)
}
