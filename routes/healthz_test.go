// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestHealthz(t *testing.T) {
	app := testApp(t)

	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
}
