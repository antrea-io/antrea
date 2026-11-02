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

func TestGetEgressDispatchFromStr(t *testing.T) {
	tests := []struct {
		name             string
		str              string
		expectedOK       bool
		expectedDispatch EgressDispatch
	}{
		{name: "tunnel", str: "tunnel", expectedOK: true, expectedDispatch: EgressDispatchTunnel},
		{name: "l2", str: "l2", expectedOK: true, expectedDispatch: EgressDispatchL2},
		{name: "uppercase", str: "L2", expectedOK: true, expectedDispatch: EgressDispatchL2},
		{name: "unknown", str: "geneve", expectedOK: false, expectedDispatch: EgressDispatchInvalid},
		{name: "empty", str: "", expectedOK: false, expectedDispatch: EgressDispatchInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, dispatch := GetEgressDispatchFromStr(tt.str)
			assert.Equal(t, tt.expectedOK, ok)
			assert.Equal(t, tt.expectedDispatch, dispatch)
		})
	}
}

func TestEgressDispatchString(t *testing.T) {
	tests := []struct {
		dispatch EgressDispatch
		expected string
	}{
		{dispatch: EgressDispatchTunnel, expected: "tunnel"},
		{dispatch: EgressDispatchL2, expected: "l2"},
		{dispatch: EgressDispatchInvalid, expected: "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.dispatch.String())
		})
	}
}
