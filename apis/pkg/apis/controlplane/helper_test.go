// Copyright 2021 Antrea Authors
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

package controlplane

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupReferenceToString(t *testing.T) {
	tests := []struct {
		name       string
		inGroupRef *GroupReference
		out        string
	}{
		{
			name: "cg-ref",
			inGroupRef: &GroupReference{
				Namespace: "",
				Name:      "cgA",
			},
			out: "cgA",
		},
		{
			name: "g-ref",
			inGroupRef: &GroupReference{
				Namespace: "nsA",
				Name:      "gA",
			},
			out: "nsA/gA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualOut := tt.inGroupRef.ToGroupName()
			assert.Equal(t, tt.out, actualOut)
		})
	}
}

func TestGroupReferenceToTypedString(t *testing.T) {
	tests := []struct {
		name       string
		inGroupRef *GroupReference
		out        string
	}{
		{
			name: "cg-ref",
			inGroupRef: &GroupReference{
				Namespace: "",
				Name:      "cgA",
			},
			out: "ClusterGroup:cgA",
		},
		{
			name: "g-ref",
			inGroupRef: &GroupReference{
				Namespace: "nsA",
				Name:      "gA",
			},
			out: "Group:nsA/gA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualOut := tt.inGroupRef.ToTypedString()
			assert.Equal(t, tt.out, actualOut)
		})
	}
}

func TestNetworkPolicyReferenceToString(t *testing.T) {
	tests := []struct {
		name    string
		inNPRef *NetworkPolicyReference
		out     string
	}{
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
			name: "annp-ref",
			inNPRef: &NetworkPolicyReference{
				Type:      AntreaNetworkPolicy,
				Namespace: "nsA",
				Name:      "annpA",
			},
			out: "AntreaNetworkPolicy:nsA/annpA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualOut := tt.inNPRef.ToString()
			assert.Equal(t, tt.out, actualOut)
		})
	}
}
