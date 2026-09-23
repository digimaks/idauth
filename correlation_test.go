// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"errors"
	"testing"

	"github.com/lx-lib/lx-idauth/core"

	"azugo.io/azugo"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

type stubCorrelationStore struct {
	cor *core.Correlation
	err error
}

func (s *stubCorrelationStore) Set(_ *azugo.Context, correlation *core.Correlation) (*core.Correlation, error) {
	return correlation, nil
}

func (s *stubCorrelationStore) Get(_ *azugo.Context) (*core.Correlation, error) {
	return s.cor, s.err
}

func (s *stubCorrelationStore) Delete(_ *azugo.Context) error {
	return nil
}

func TestCorrelationStore_Get_MissingCorrelationReturnsCodedProblem(t *testing.T) {
	store := newCorrelationStore(&stubCorrelationStore{})

	cor, err := store.Get(nil)

	qt.Assert(t, qt.IsNil(cor))
	var problem *pkerrors.Problem
	qt.Assert(t, qt.ErrorAs(err, &problem))
	qt.Check(t, qt.Equals(problem.Code, "err:callback:correlationNotFound"))
	qt.Check(t, qt.Equals(problem.Status, fasthttp.StatusBadRequest))
}

func TestCorrelationStore_Get_UnderlyingErrorPassesThrough(t *testing.T) {
	wantErr := errors.New("cache unavailable")
	store := newCorrelationStore(&stubCorrelationStore{err: wantErr})

	cor, err := store.Get(nil)

	qt.Assert(t, qt.IsNil(cor))
	qt.Check(t, qt.ErrorIs(err, wantErr))
}

func TestCorrelationStore_Get_FoundCorrelationPassesThrough(t *testing.T) {
	want := &core.Correlation{ID: "abc"}
	store := newCorrelationStore(&stubCorrelationStore{cor: want})

	cor, err := store.Get(nil)

	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(cor, want))
}
