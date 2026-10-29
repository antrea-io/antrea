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

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKindControlPlaneNodeName(t *testing.T) {
	const header = "CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\n"
	const single = header + "id kindest/node command created up ports kind-control-plane\n"
	const multiple = header +
		"leader kindest/node command created up ports leader-control-plane\n" +
		"east kindest/node command created up ports east-control-plane\n" +
		"west kindest/node command created up ports west-control-plane\n"
	for _, tt := range []struct {
		name        string
		stdout      string
		clusterName string
		want        string
		wantError   bool
	}{
		{name: "single cluster", stdout: single, want: "kind-control-plane"},
		{name: "multi-cluster compatibility", stdout: multiple, want: "west-control-plane"},
		{
			name: "explicit cluster", clusterName: "isolated",
			stdout: header + "id kindest/node command created up ports isolated-control-plane\n",
			want:   "isolated-control-plane",
		},
		{name: "explicit cluster rejects ambiguity", stdout: multiple, clusterName: "isolated", wantError: true},
		{name: "no containers", stdout: header, wantError: true},
		{name: "empty output", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name, err := kindControlPlaneNodeName(tt.stdout, tt.clusterName)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, name)
		})
	}
}
