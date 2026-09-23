// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestPreAuthorizedCode_ProblemJSON_MissingCode(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostForm("/api/1.0/token", map[string]any{
		"grant_type": GrantTypePreAuthorizedCode,
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(string(resp.Header.ContentType()), pkerrors.ContentTypeProblemJSON))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:session:preAuthCodeMissing"`))
}

func TestPreAuthorizedCode_ProblemJSON_InvalidOrExpired(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": "nonexistent-code-12345",
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:session:preAuthCodeInvalidOrExpired"`))
}
