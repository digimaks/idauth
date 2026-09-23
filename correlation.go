// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"github.com/lx-lib/lx-idauth/core"

	"azugo.io/azugo"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
)

// correlationStore wraps a core.CorrelationStore so a missing or expired
// correlation (nil, nil from Get) surfaces as a coded Problem instead of the
// bare errors.New("no session") the vendored callback handler falls back to,
// which otherwise renders as err:internal:unexpected.
type correlationStore struct {
	core.CorrelationStore
}

func newCorrelationStore(s core.CorrelationStore) *correlationStore {
	return &correlationStore{CorrelationStore: s}
}

func (s *correlationStore) Get(ctx *azugo.Context) (*core.Correlation, error) {
	cor, err := s.CorrelationStore.Get(ctx)
	if err != nil {
		return nil, err
	}

	if cor == nil {
		return nil, pkerrors.NewProblem("err:callback:correlationNotFound",
			pkerrors.WithDetail("correlation cookie missing or its session expired"))
	}

	return cor, nil
}
