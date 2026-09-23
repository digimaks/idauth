// SPDX-License-Identifier: EUPL-1.2

package edim

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/lx-lib/lx-idauth/core"
)

func TestClientAllowsSameDevice(t *testing.T) {
	tests := []struct {
		name   string
		client *core.Client
		want   bool
	}{
		{"nil client", nil, false},
		{"no metadata", &core.Client{}, false},
		{"metadata false", &core.Client{Metadata: map[string]string{"same_device": "false"}}, false},
		{"other metadata key", &core.Client{Metadata: map[string]string{"token_binding": "dpop"}}, false},
		{"opted in", &core.Client{Metadata: map[string]string{"same_device": "true"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qt.Assert(t, qt.Equals(clientAllowsSameDevice(tt.client), tt.want))
		})
	}
}
