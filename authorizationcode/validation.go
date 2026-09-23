// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"errors"
	"slices"
	"strings"

	"azugo.io/azugo"
	"github.com/lx-lib/lx-idauth/core"
)

// ValidateAndSaveState validates the authorization code flow request.
func ValidateAndSaveState(ctx *azugo.Context, clientID string, clientStore core.ClientStore, store *Store, state string) error {
	responseType := ctx.Query.StringOptional("response_type")

	if responseType == nil || *responseType != "code" {
		return nil
	}

	client, err := clientStore.GetClient(clientID)
	if err != nil {
		return err
	}

	if client == nil {
		return errors.New("client not found")
	}

	redirectURI, err := ctx.Query.String("redirect_uri")
	if err != nil {
		return err
	}

	if !slices.Contains(client.RedirectURI, redirectURI) {
		return errors.New("invalid redirect_uri")
	}

	codeChallenge, err := ctx.Query.String("code_challenge")
	if err != nil {
		return err
	}

	if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
		return errors.New("invalid code_challenge")
	}

	codeChallengeMethod, err := ctx.Query.String("code_challenge_method")
	if err != nil {
		return err
	}

	if codeChallengeMethod != "S256" {
		return errors.New("invalid code_challenge_method")
	}

	if _, err = ctx.Query.String("code_challenge_method"); err != nil {
		return err
	}

	scope := ctx.Query.StringOptional("scope")

	if scope == nil {
		return nil
	}

	if !store.IsScopeSupported(*scope) {
		return errors.New("invalid scope")
	}

	issuerState := ctx.Query.StringOptional("issuer_state")

	item := StateItem{
		State:        state,
		ResponseType: *responseType,
		Scope:        *scope,
	}
	if issuerState != nil {
		item.IssuerState = *issuerState
	}

	err = store.SetState(ctx, item)
	if err != nil {
		return err
	}

	return nil
}

type scopeSet map[string]struct{}

func newScopeSet(scopes []string) scopeSet {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile"}
	}

	s := make(scopeSet, len(scopes))
	for _, scope := range scopes {
		s[scope] = struct{}{}
	}

	return s
}

func (s scopeSet) Supported(scope string) bool {
	scopes := strings.Split(scope, " ")

	any := false

	for _, sc := range scopes {
		if sc == "" {
			continue
		}

		if _, ok := s[sc]; !ok {
			return false
		}

		any = true
	}

	return any
}
