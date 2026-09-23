// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestMapClaims_MapsFixedFieldsAndKeepsRawClaims(t *testing.T) {
	claims := map[string]any{
		"sub":        "12345",
		"given_name": "Arturs",
		"surname":    "Testeris",
		"mail":       "arturs@example.org",
		"birthdate":  "1990-01-01",
	}
	fieldMap := map[string]ClaimMapping{
		"person_code": {Source: "sub"},
		"first_name":  {Source: "given_name"},
		"last_name":   {Source: "surname"},
		"email":       {Source: "mail"},
	}

	req := mapClaims(claims, fieldMap)

	qt.Check(t, qt.Equals(req.PersonCode, "12345"))
	qt.Check(t, qt.Equals(req.FirstName, "Arturs"))
	qt.Check(t, qt.Equals(req.LastName, "Testeris"))
	qt.Check(t, qt.Equals(req.Email, "arturs@example.org"))
	qt.Check(t, qt.DeepEquals(req.RawClaims, claims))
}

func TestMapClaims_OmitsFieldWhenSourceKeyMissing(t *testing.T) {
	claims := map[string]any{"sub": "12345"}
	fieldMap := map[string]ClaimMapping{
		"person_code": {Source: "sub"},
		"first_name":  {Source: "given_name"}, // not present in claims
	}

	req := mapClaims(claims, fieldMap)

	qt.Check(t, qt.Equals(req.PersonCode, "12345"))
	qt.Check(t, qt.Equals(req.FirstName, ""))
}

func TestMapClaims_OmitsFieldWhenNotAString(t *testing.T) {
	claims := map[string]any{"sub": 12345} // number, not string
	fieldMap := map[string]ClaimMapping{"person_code": {Source: "sub"}}

	req := mapClaims(claims, fieldMap)

	qt.Check(t, qt.Equals(req.PersonCode, ""))
}

func TestMapClaims_AppliesTransforms(t *testing.T) {
	claims := map[string]any{"serial_number": "PNOLV-010101-12345"}
	fieldMap := map[string]ClaimMapping{
		"person_code": {
			Source: "serial_number",
			Transforms: []TransformStep{
				{Name: "strip_prefixes", Args: []string{"PNOLV-", "PNOXX-"}},
				{Name: "strip_chars", Args: []string{"-"}},
			},
		},
	}

	req := mapClaims(claims, fieldMap)

	qt.Check(t, qt.Equals(req.PersonCode, "01010112345"))
}
