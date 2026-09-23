// SPDX-License-Identifier: EUPL-1.2

package oauth2generic

import (
	"fmt"
	"strings"
)

// transformRegistry is a small, fixed whitelist of named claim-value
// transforms — deliberately not a scripting engine, so config stays
// auditable in a security-sensitive PID-issuance chain. Extend with one
// more named function if a future client needs something this doesn't
// cover, rather than generalizing pre-emptively.
var transformRegistry = map[string]func(value string, args []string) string{
	"strip_prefixes": func(value string, args []string) string {
		for _, prefix := range args {
			if strings.HasPrefix(value, prefix) {
				return strings.TrimPrefix(value, prefix)
			}
		}

		return value
	},
	"strip_chars": func(value string, args []string) string {
		for _, s := range args {
			value = strings.ReplaceAll(value, s, "")
		}

		return value
	},
}

// applyTransforms runs steps in order over value. Returns an error for an
// unknown transform name so misconfiguration is caught at bind time
// (validateClaimFieldMap), not silently ignored at request time.
func applyTransforms(value string, steps []TransformStep) (string, error) {
	for _, step := range steps {
		fn, ok := transformRegistry[step.Name]
		if !ok {
			return "", fmt.Errorf("oauth2generic: unknown claim transform %q", step.Name)
		}

		value = fn(value, step.Args)
	}

	return value, nil
}

// validateClaimFieldMap checks every transform name in fieldMap against
// the registry, so a typo in config fails the service at startup instead
// of silently producing an empty claim at login time.
func validateClaimFieldMap(fieldMap map[string]ClaimMapping) error {
	for target, mapping := range fieldMap {
		if _, err := applyTransforms("", mapping.Transforms); err != nil {
			return fmt.Errorf("oauth2generic: claim_field_map[%q]: %w", target, err)
		}
	}

	return nil
}
