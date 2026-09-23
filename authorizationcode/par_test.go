// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"context"
	"testing"
	"time"

	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
)

type testCacheProvider struct {
	c *cache.Cache
}

func (p *testCacheProvider) Cache() *cache.Cache {
	return p.c
}

func testStore(t *testing.T) *Store {
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

// waitSet gives Ristretto's async buffer time to process a set operation.
func waitSet() {
	time.Sleep(10 * time.Millisecond)
}

func TestPAR_SetThenPop_ReturnsStoredItem(t *testing.T) {
	st := testStore(t)

	id, err := st.SetPAR(context.Background(), PARItem{
		ClientID: "edim.wallet.instance",
		RawQuery: "client_id=edim.wallet.instance&scope=openid",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.Equals(id, "")))
	waitSet()

	item, err := st.PopPAR(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(item.ClientID, "edim.wallet.instance"))
	qt.Check(t, qt.Equals(item.RawQuery, "client_id=edim.wallet.instance&scope=openid"))
}

func TestPAR_Pop_IsSingleUse(t *testing.T) {
	st := testStore(t)

	id, err := st.SetPAR(context.Background(), PARItem{ClientID: "c", RawQuery: "q=1"})
	qt.Assert(t, qt.IsNil(err))
	waitSet()

	_, err = st.PopPAR(context.Background(), id)
	qt.Assert(t, qt.IsNil(err))

	_, err = st.PopPAR(context.Background(), id)
	qt.Check(t, qt.Not(qt.IsNil(err)))
}

func TestPAR_Pop_UnknownIDErrors(t *testing.T) {
	st := testStore(t)

	_, err := st.PopPAR(context.Background(), "does-not-exist")
	qt.Check(t, qt.Not(qt.IsNil(err)))
}
