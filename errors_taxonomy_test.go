// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestErrorsTaxonomy_RegistersPreAuthReasons(t *testing.T) {
	cases := []string{
		"err:session:preAuthCodeMissing",
		"err:session:preAuthCodeInvalidOrExpired",
		"err:session:preAuthTXCodeInvalid",
		"err:session:preAuthSessionCreateFailed",
	}

	for _, code := range cases {
		p := pkerrors.NewProblem(code)
		qt.Check(t, qt.Equals(p.Status, fasthttp.StatusBadRequest), qt.Commentf("status for %s", code))
	}
}
