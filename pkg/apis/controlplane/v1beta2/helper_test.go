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

package v1beta2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkPolicyReferenceToString(t *testing.T) {
	tests := []struct {
		name    string
		inNPRef *NetworkPolicyReference
		out     string
	}{
		{
			name: "k8s-np-ref",
			inNPRef: &NetworkPolicyReference{
				Type:      K8sNetworkPolicy,
				Namespace: "nsA",
				Name:      "npA",
			},
			out: "K8sNetworkPolicy:nsA/npA",
		},
		{
			name: "annp-ref",
			inNPRef: &NetworkPolicyReference{
				Type:      AntreaNetworkPolicy,
				Namespace: "nsA",
				Name:      "annpA",
			},
			out: "AntreaNetworkPolicy:nsA/annpA",
		},
		{
			name: "acnp-ref",
			inNPRef: &NetworkPolicyReference{
				Type:      AntreaClusterNetworkPolicy,
				Namespace: "",
				Name:      "acnpA",
			},
			out: "AntreaClusterNetworkPolicy:acnpA",
		},
		{
			name: "cnp-ref",
			inNPRef: &NetworkPolicyReference{
				Type:      ClusterNetworkPolicy,
				Namespace: "",
				Name:      "cnpA",
			},
			out: "ClusterNetworkPolicy:cnpA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualOut := tt.inNPRef.ToString()
			assert.Equal(t, tt.out, actualOut)
		})
	}
}
