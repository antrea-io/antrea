// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDSRDispatchFromStr(t *testing.T) {
	tests := []struct {
		name             string
		str              string
		expectedOK       bool
		expectedDispatch DSRDispatch
	}{
		{name: "tunnel", str: "tunnel", expectedOK: true, expectedDispatch: DSRDispatchTunnel},
		{name: "uppercase tunnel", str: "Tunnel", expectedOK: true, expectedDispatch: DSRDispatchTunnel},
		{name: "l2", str: "l2", expectedOK: true, expectedDispatch: DSRDispatchL2},
		{name: "uppercase l2", str: "L2", expectedOK: true, expectedDispatch: DSRDispatchL2},
		{name: "unknown", str: "geneve", expectedOK: false, expectedDispatch: DSRDispatchInvalid},
		{name: "empty", str: "", expectedOK: false, expectedDispatch: DSRDispatchInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, dispatch := GetDSRDispatchFromStr(tt.str)
			assert.Equal(t, tt.expectedOK, ok)
			assert.Equal(t, tt.expectedDispatch, dispatch)
		})
	}
}

func TestDSRDispatchString(t *testing.T) {
	tests := []struct {
		dispatch DSRDispatch
		want     string
	}{
		{dispatch: DSRDispatchTunnel, want: "tunnel"},
		{dispatch: DSRDispatchL2, want: "l2"},
		{dispatch: DSRDispatchInvalid, want: "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.dispatch.String())
		})
	}
}
