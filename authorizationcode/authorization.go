// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"encoding/json"
	"time"

	"azugo.io/azugo"
	"github.com/lx-lib/lx-idauth/core"
)

// extraClaimsMetadataKey is the Session.Metadata key holding JSON-encoded
// raw provider claims not covered by a provider's own field mapping (see
// oauth2generic.Callback). Consumed by routes.buildIntrospectionResponse.
const extraClaimsMetadataKey = "extra_claims"

// Callback saves the pre-authorized_code flow's pending AuthCodeItem.
// rawClaims, when non-nil, is JSON-encoded into Session.Metadata so it
// survives to /introspection once the code is redeemed (see token.go's
// three call sites that create the final Session from AuthCodeItem.Session)
// — most providers (eParaksts, Smart-ID, edim) have no unmapped claims to
// carry and pass nil.
func Callback(ctx *azugo.Context, store *Store, sess core.Correlation, token core.UserData, stateItem StateItem, rawClaims map[string]any) (*core.AuthRequest, error) {
	scope := stateItem.Scope

	roles := []*core.RoleEntity{
		{
			ID:   "person",
			Code: "person",
			Name: "Person",
		},
	}

	rights := make([]string, len(token.Rights))
	for i, right := range token.Rights {
		rights[i] = right.RightCode // Assuming RightCode is the string you need
	}

	now := time.Now().UTC()
	// save session id, client_id, user_id, scope, redirect_uri, code_challenge

	var metadata map[string]string

	if len(rawClaims) > 0 {
		encoded, err := json.Marshal(rawClaims)
		if err != nil {
			return nil, err
		}

		metadata = map[string]string{extraClaimsMetadataKey: string(encoded)}
	}

	err := store.SetItem(ctx, AuthCodeItem{
		Code:                sess.ID,
		ClientID:            sess.ClientID,
		UserID:              token.UserID,
		RedirectURI:         sess.RedirectURI,
		CodeChallenge:       *sess.CodeChallenge,
		CodeChallengeMethod: *sess.CodeChallengeMethod,
		Scope:               scope,
		IssuerState:         stateItem.IssuerState,
		Session: core.Session{
			Subject:   token.UserID,
			FirstName: token.FirstName,
			LastName:  token.LastName,
			Code:      token.PersonCode,
			Rights: []*core.GrantedRightListEntity{
				{
					RoleID:    roles[0].ID,
					RightCode: "citizen",
				},
			},
			LastAccessed: &now,
			State:        string(core.SessionStateAuthorized),
			Role:         roles[0],
			Roles:        roles,
			Metadata:     metadata,
		},
	})
	if err != nil {
		return nil, err
	}

	return &core.AuthRequest{
		IPAddress: ctx.IP().String(),
	}, nil
}
