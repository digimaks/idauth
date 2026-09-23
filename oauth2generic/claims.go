// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

import "github.com/lx-lib/lx-idauth/core"

// mapClaims applies fieldMap (target field -> ClaimMapping) to build a
// *core.AuthRequest. A target whose source key is absent from claims, or
// whose value isn't a string, is left empty rather than erroring — it may
// still be recoverable downstream via RawClaims. A transform error (should
// not occur — validateClaimFieldMap catches unknown names at bind time)
// also degrades to empty, defense in depth rather than a second error path
// here. claims is always carried through in full as RawClaims regardless
// of fieldMap, so nothing is lost.
func mapClaims(claims map[string]any, fieldMap map[string]ClaimMapping) *core.AuthRequest {
	get := func(target string) string {
		mapping, ok := fieldMap[target]
		if !ok {
			return ""
		}

		v, _ := claims[mapping.Source].(string)

		transformed, err := applyTransforms(v, mapping.Transforms)
		if err != nil {
			return ""
		}

		return transformed
	}

	return &core.AuthRequest{
		PersonCode: get("person_code"),
		FirstName:  get("first_name"),
		LastName:   get("last_name"),
		Email:      get("email"),
		RawClaims:  claims,
	}
}
