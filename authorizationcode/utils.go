// SPDX-License-Identifier: EUPL-1.2

package authorizationcode

import (
	"crypto/sha256"
	"encoding/base64"
)

func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
