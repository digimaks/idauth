// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"math/rand"

	"azugo.io/azugo"
	"github.com/digimaks/idauth/authorizationcode"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

func (r *router) preauthGenerate(ctx *azugo.Context) {
	scope, err := ctx.Form.String("scope")
	if err != nil || scope == "" {
		ctx.Error(pkerrors.NewProblem("err:preauth:scopeRequired", pkerrors.WithDetail("scope is required")))

		return
	}

	// sessionID becomes the OIDC subject - used as the key in issuer-py SessionManager
	sessionID := ctx.Form.StringOptional("session_id")
	if sessionID == nil || *sessionID == "" {
		s := ulid.Make().String()
		sessionID = &s
	}

	preAuthCode := ulid.Make().String()

	noTXCode := false
	if v := ctx.Form.StringOptional("no_tx_code"); v != nil && (*v == "true" || *v == "1") {
		noTXCode = true
	}

	// 5-digit numeric tx_code
	txCode := rand.Intn(90000) + 10000

	sess := core.Session{
		Subject: *sessionID,
		State:   string(core.SessionStateAuthorized),
	}

	if givenName := ctx.Form.StringOptional("given_name"); givenName != nil {
		sess.FirstName = *givenName
	}

	if familyName := ctx.Form.StringOptional("family_name"); familyName != nil {
		sess.LastName = *familyName
	}

	item := &authorizationcode.AuthCodeItem{
		Code:     preAuthCode,
		ClientID: "issuer-backend",
		UserID:   *sessionID,
		Scope:    scope,
		NoTXCode: noTXCode,
		Session:  sess,
	}

	if err := r.AuthCodeStore().SetItem(ctx, *item); err != nil {
		ctx.Log().Error("failed to store preauth item", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:preauth:itemStoreFailed"))

		return
	}

	resp := map[string]interface{}{
		"preauth_code": preAuthCode,
		"session_id":   sessionID,
	}

	if !noTXCode {
		if err := r.AuthCodeStore().SetTXCode(ctx, preAuthCode, txCode); err != nil {
			ctx.Log().Error("failed to store preauth tx_code", zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:preauth:txCodeStoreFailed"))

			return
		}

		resp["tx_code"] = txCode
	}

	ctx.JSON(resp)
}
