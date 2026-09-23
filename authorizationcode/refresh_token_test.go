// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"context"
	"testing"
	"time"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"

	"github.com/lx-lib/lx-idauth/core"
)

func testStoreForRefresh(t *testing.T) *Store {
	t.Helper()

	app := &testCacheProvider{c: cache.New(cache.MemoryCache)}

	st, err := NewAuthCodeStore(app, &Configuration{
		StateTTL:        5 * time.Minute,
		AuthCodeTTL:     time.Minute,
		PreAuthTTL:      5 * time.Minute,
		PARTTL:          90 * time.Second,
		RefreshTokenTTL: 720 * time.Hour,
	})
	qt.Assert(t, qt.IsNil(err))

	return st
}

func TestRefreshToken_IssueThenRedeem_ReturnsStoredItem(t *testing.T) {
	st := testStoreForRefresh(t)

	token, err := st.IssueRefreshToken(context.Background(), RefreshTokenItem{
		ClientID: "edim.wallet.instance",
		Scope:    "eu.europa.ec.eudi.pid_vc_sd_jwt",
		JKT:      "thumbprint-abc",
		Session:  core.Session{Subject: "10345678902"},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(token, "")))
	waitSet()

	item, err := st.RedeemRefreshToken(context.Background(), token)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(item.ClientID, "edim.wallet.instance"))
	qt.Check(t, qt.Equals(item.JKT, "thumbprint-abc"))
	qt.Check(t, qt.Equals(item.Session.Subject, "10345678902"))
}

func TestRefreshToken_Redeem_IsSingleUse(t *testing.T) {
	st := testStoreForRefresh(t)

	token, err := st.IssueRefreshToken(context.Background(), RefreshTokenItem{ClientID: "c", JKT: "k"})
	qt.Assert(t, qt.IsNil(err))
	waitSet()

	_, err = st.RedeemRefreshToken(context.Background(), token)
	qt.Assert(t, qt.IsNil(err))

	_, err = st.RedeemRefreshToken(context.Background(), token)
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestRefreshToken_Redeem_UnknownTokenErrors(t *testing.T) {
	st := testStoreForRefresh(t)

	_, err := st.RedeemRefreshToken(context.Background(), "not-a-real-token")
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestRefreshToken_TwoIssuancesProduceDifferentTokens(t *testing.T) {
	st := testStoreForRefresh(t)

	a, err := st.IssueRefreshToken(context.Background(), RefreshTokenItem{ClientID: "c", JKT: "k"})
	qt.Assert(t, qt.IsNil(err))
	b, err := st.IssueRefreshToken(context.Background(), RefreshTokenItem{ClientID: "c", JKT: "k"})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Not(qt.Equals(a, b)))
}
