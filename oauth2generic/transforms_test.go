// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestApplyTransforms_StripPrefixes_FirstMatchWins(t *testing.T) {
	got, err := applyTransforms("PNOLV-010101-12345", []TransformStep{
		{Name: "strip_prefixes", Args: []string{"PNOLV-", "PNOXX-"}},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, "010101-12345"))
}

func TestApplyTransforms_StripPrefixes_NoMatchLeavesUnchanged(t *testing.T) {
	got, err := applyTransforms("SOMETHINGELSE-123", []TransformStep{
		{Name: "strip_prefixes", Args: []string{"PNOLV-", "PNOXX-"}},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, "SOMETHINGELSE-123"))
}

func TestApplyTransforms_StripChars(t *testing.T) {
	got, err := applyTransforms("010101-12345", []TransformStep{
		{Name: "strip_chars", Args: []string{"-"}},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, "01010112345"))
}

func TestApplyTransforms_ChainedReproducesEparakstsPersonCode(t *testing.T) {
	got, err := applyTransforms("PNOLV-010101-12345", []TransformStep{
		{Name: "strip_prefixes", Args: []string{"PNOLV-", "PNOXX-"}},
		{Name: "strip_chars", Args: []string{"-"}},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, "01010112345"))
}

func TestApplyTransforms_UnknownNameReturnsError(t *testing.T) {
	_, err := applyTransforms("value", []TransformStep{{Name: "does_not_exist"}})
	qt.Assert(t, qt.IsNotNil(err))
}

func TestValidateClaimFieldMap_ReturnsErrorForUnknownTransform(t *testing.T) {
	err := validateClaimFieldMap(map[string]ClaimMapping{
		"person_code": {Source: "sub", Transforms: []TransformStep{{Name: "does_not_exist"}}},
	})
	qt.Assert(t, qt.IsNotNil(err))
}

func TestValidateClaimFieldMap_NilForKnownTransforms(t *testing.T) {
	err := validateClaimFieldMap(map[string]ClaimMapping{
		"person_code": {Source: "sub", Transforms: []TransformStep{{Name: "strip_chars", Args: []string{"-"}}}},
	})
	qt.Assert(t, qt.IsNil(err))
}
