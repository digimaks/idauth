// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func generatePreauth(t *testing.T, app *azugo.TestApp, form map[string]any) map[string]any {
	t.Helper()

	resp, err := app.TestClient().PostForm("/preauth_generate", form)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	return body
}

func TestPreAuthorizedCode_NoTXCode_TokenIssuedWithoutCode(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	preauth := generatePreauth(t, app, map[string]any{
		"scope":      "openid",
		"no_tx_code": "true",
	})

	_, hasTXCode := preauth["tx_code"]
	qt.Check(t, qt.IsFalse(hasTXCode))

	resp, err := app.TestClient().PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": preauth["preauth_code"].(string),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	token := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &token)))
	qt.Check(t, qt.Not(qt.Equals(token["access_token"].(string), "")))
}

func TestPreAuthorizedCode_TXCodeStillRequiredByDefault(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	preauth := generatePreauth(t, app, map[string]any{
		"scope": "openid",
	})

	qt.Check(t, qt.IsTrue(preauth["tx_code"] != nil))

	resp, err := app.TestClient().PostForm("/api/1.0/token", map[string]any{
		"grant_type":          GrantTypePreAuthorizedCode,
		"pre-authorized_code": preauth["preauth_code"].(string),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:session:preAuthTXCodeInvalid"`))
}
