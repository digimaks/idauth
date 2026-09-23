// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"
	"golang.org/x/oauth2"
)

func TestCallback_ExchangesCodeAndMapsUserInfo(t *testing.T) {
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.Header.Get("Authorization"), "Bearer test-access-token"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":        "12345",
			"given_name": "Arturs",
			"surname":    "Testeris",
		})
	}))
	defer userInfoServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	cfg := &ClientConfig{
		AuthURL:     "http://unused.invalid/authorize",
		TokenURL:    tokenServer.URL,
		UserInfoURL: userInfoServer.URL,
		ClientID:    "test-client",
		ClaimFieldMap: map[string]ClaimMapping{
			"person_code": {Source: "sub"},
			"first_name":  {Source: "given_name"},
			"last_name":   {Source: "surname"},
		},
	}

	i := &inst{
		config:         cfg,
		providerConfig: &core.AuthProviderConfig{ID: "test-provider"},
		oauth2Config: oauth2.Config{
			ClientID: cfg.ClientID,
			Endpoint: oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL},
		},
	}

	req, err := i.exchangeAndFetchUserInfo(t.Context(), "test-code")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(req.PersonCode, "12345"))
	qt.Check(t, qt.Equals(req.FirstName, "Arturs"))
	qt.Check(t, qt.Equals(req.LastName, "Testeris"))
}

func TestCallbackErrorCode_AccessDeniedMapsToNoRights(t *testing.T) {
	qt.Check(t, qt.Equals(callbackErrorCode("access_denied"), auth.AuthErrNoRights))
}

func TestCallbackErrorCode_UnknownMapsToInvalidCallback(t *testing.T) {
	qt.Check(t, qt.Equals(callbackErrorCode("server_error"), auth.AuthErrInvalidCallback))
	qt.Check(t, qt.Equals(callbackErrorCode(""), auth.AuthErrInvalidCallback))
}

func TestBuildAuthorizeURL_AppendsAcrValuesWhenSet(t *testing.T) {
	cfg := oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"},
	}

	url := buildAuthorizeURL(cfg, "test-state", "urn:example:acr:mobileid", "", "")

	// acr_values goes through oauth2.SetAuthURLParam like prompt/ui_locales
	// — so it IS percent-encoded (colons become %3A), matching what
	// eparaksts.go's url.Values.Encode() already produces in production.
	qt.Check(t, qt.StringContains(url, "acr_values=urn%3Aexample%3Aacr%3Amobileid"))
}

func TestBuildAuthorizeURL_SendsAcrValuesEvenWhenEmpty(t *testing.T) {
	cfg := oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"},
	}

	url := buildAuthorizeURL(cfg, "test-state", "", "", "")

	// eParaksts's real IdP rejects a request with acr_values missing
	// entirely ("Invalid acr_values"), so the base (non-variant) provider
	// entry must still send the param, just empty — never omit it.
	qt.Check(t, qt.StringContains(url, "acr_values="))
}

func TestBuildAuthorizeURL_AppendsPromptAndUILocalesWhenSet(t *testing.T) {
	cfg := oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"},
	}

	url := buildAuthorizeURL(cfg, "test-state", "", "login", "lv")

	qt.Check(t, qt.StringContains(url, "prompt=login"))
	qt.Check(t, qt.StringContains(url, "ui_locales=lv"))
}

func TestBuildAuthorizeURL_OmitsPromptAndUILocalesWhenEmpty(t *testing.T) {
	cfg := oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"},
	}

	url := buildAuthorizeURL(cfg, "test-state", "", "", "")

	qt.Check(t, qt.Not(qt.StringContains(url, "prompt")))
	qt.Check(t, qt.Not(qt.StringContains(url, "ui_locales")))
}
