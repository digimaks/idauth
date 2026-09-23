// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/digimaks/idauth/authorizationcode"
)

func TestAuthorizationV3_RequestURI_DelegatesWithStoredParams(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	id, err := idapp.AuthCodeStore().SetPAR(t.Context(), authorizationcode.PARItem{
		ClientID: "edim.wallet.test",
		RawQuery: "client_id=edim.wallet.test&redirect_uri=https%3A%2F%2Fwallet.example.com%2Fcb&response_type=code&state=xyz",
	})
	qt.Assert(t, qt.IsNil(err))

	q := url.Values{
		"client_id":   {"edim.wallet.test"},
		"request_uri": {"urn:ietf:params:oauth:request_uri:" + id},
	}
	resp, err := app.TestClient().Get("/authorizationV3?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusFound))

	loc := string(resp.Header.Peek("Location"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(loc, authorizeDelegatePath+"?")))
	qt.Check(t, qt.StringContains(loc, "state=xyz"))
}

func TestAuthorizationV3_RequestURI_SingleUse(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	id, err := idapp.AuthCodeStore().SetPAR(t.Context(), authorizationcode.PARItem{
		ClientID: "edim.wallet.test",
		RawQuery: "client_id=edim.wallet.test",
	})
	qt.Assert(t, qt.IsNil(err))

	q := url.Values{"client_id": {"edim.wallet.test"}, "request_uri": {"urn:ietf:params:oauth:request_uri:" + id}}

	first, err := app.TestClient().Get("/authorizationV3?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(first.StatusCode(), fasthttp.StatusFound))

	second, err := app.TestClient().Get("/authorizationV3?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(second.StatusCode(), fasthttp.StatusBadRequest))
}

func TestAuthorizationV3_RequestURI_ClientIDMismatchRejected(t *testing.T) {
	idapp := testAppRaw(t)
	app := azugoTestApp(t, idapp)
	app.Start(t)
	defer app.Stop()

	id, err := idapp.AuthCodeStore().SetPAR(t.Context(), authorizationcode.PARItem{
		ClientID: "edim.wallet.test",
		RawQuery: "client_id=edim.wallet.test",
	})
	qt.Assert(t, qt.IsNil(err))

	q := url.Values{"client_id": {"edim.self-service.portal"}, "request_uri": {"urn:ietf:params:oauth:request_uri:" + id}}
	resp, err := app.TestClient().Get("/authorizationV3?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

func TestAuthorizationV3_RequestURI_UnknownIDRejected(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	q := url.Values{"client_id": {"edim.wallet.test"}, "request_uri": {"urn:ietf:params:oauth:request_uri:does-not-exist"}}
	resp, err := app.TestClient().Get("/authorizationV3?" + q.Encode())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}
