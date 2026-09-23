// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"
	"time"

	"github.com/lx-lib/lx-idauth/core"

	"github.com/go-quicktest/qt"
)

func TestBuildIntrospectionResponse_IncludesNamesWhenPresent(t *testing.T) {
	lastAccessed := time.Now()
	sess := &core.Session{
		Subject:      "10345678902",
		FirstName:    "Arturs",
		LastName:     "Testeris",
		Code:         "10345678902",
		Scope:        []string{"eu.europa.ec.eudi._pid_mdoc"},
		LastAccessed: &lastAccessed,
	}

	resp := buildIntrospectionResponse(sess, "https://idauth.laptop", time.Minute)

	qt.Check(t, qt.Equals(resp["sub"], "10345678902"))

	claims, ok := resp["claims"].(map[string]interface{})
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(claims["given_name"], "Arturs"))
	qt.Check(t, qt.Equals(claims["family_name"], "Testeris"))
	qt.Check(t, qt.Equals(claims["personal_administrative_number"], "10345678902"))
}

func TestBuildIntrospectionResponse_OmitsNamesWhenAbsent(t *testing.T) {
	sess := &core.Session{
		Subject:         "edim.self-service.portal",
		IsServiceClient: true,
	}

	resp := buildIntrospectionResponse(sess, "https://idauth.laptop", time.Minute)

	_, hasClaims := resp["claims"]
	qt.Check(t, qt.IsFalse(hasClaims))
}

func TestBuildIntrospectionResponse_MergesExtraClaimsWithoutOverwritingNamed(t *testing.T) {
	lastAccessed := time.Now()
	sess := &core.Session{
		Subject:      "10345678902",
		FirstName:    "Arturs",
		Code:         "10345678902",
		LastAccessed: &lastAccessed,
		Metadata:     map[string]string{"extra_claims": `{"given_name":"should-not-win","locale":"lv-LV"}`},
	}

	resp := buildIntrospectionResponse(sess, "https://idauth.laptop", time.Minute)

	claims, ok := resp["claims"].(map[string]interface{})
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(claims["given_name"], "Arturs"))
	qt.Check(t, qt.Equals(claims["locale"], "lv-LV"))
}

func TestBuildIntrospectionResponse_IgnoresMalformedExtraClaims(t *testing.T) {
	sess := &core.Session{
		Subject:  "10345678902",
		Metadata: map[string]string{"extra_claims": `not-json`},
	}

	resp := buildIntrospectionResponse(sess, "https://idauth.laptop", time.Minute)

	_, hasClaims := resp["claims"]
	qt.Check(t, qt.IsFalse(hasClaims))
}

func TestBuildIntrospectionResponse_SetsDPoPCnfWhenBound(t *testing.T) {
	sess := &core.Session{
		Subject:  "10345678902",
		Metadata: map[string]string{"dpop_jkt": "some-jkt-thumbprint"},
	}

	resp := buildIntrospectionResponse(sess, "https://idauth.laptop", time.Minute)

	qt.Check(t, qt.Equals(resp["token_type"], "DPoP"))
	cnf, ok := resp["cnf"].(map[string]string)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(cnf["jkt"], "some-jkt-thumbprint"))
}
