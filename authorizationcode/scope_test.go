// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestScopeSet_AllowsConfiguredCredentialScope(t *testing.T) {
	s := newScopeSet([]string{"openid", "profile", "eu.europa.ec.eudi.pid_vc_sd_jwt"})

	qt.Check(t, qt.IsTrue(s.Supported("eu.europa.ec.eudi.pid_vc_sd_jwt")))
	qt.Check(t, qt.IsTrue(s.Supported("openid eu.europa.ec.eudi.pid_vc_sd_jwt")))
}

func TestScopeSet_RejectsUnknownAndEmptyScope(t *testing.T) {
	s := newScopeSet([]string{"openid", "profile"})

	qt.Check(t, qt.IsFalse(s.Supported("eu.europa.ec.eudi.pid_vc_sd_jwt")))
	qt.Check(t, qt.IsFalse(s.Supported("")))
	qt.Check(t, qt.IsFalse(s.Supported("openid unknown")))
}

func TestNewScopeSet_EmptyFallsBackToDefaults(t *testing.T) {
	s := newScopeSet(nil)

	qt.Check(t, qt.IsTrue(s.Supported("openid")))
	qt.Check(t, qt.IsTrue(s.Supported("profile")))
}
