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

package antreanodeconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

func marshal(t *testing.T, object runtime.Object) []byte {
	t.Helper()
	raw, err := json.Marshal(object)
	require.NoError(t, err)
	return raw
}

func newAntreaNodeConfig(allowedVLANs []string) *crdv1alpha1.AntreaNodeConfig {
	return &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc"},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{
						BridgeName: "br-secondary",
						PhysicalInterfaces: []crdv1alpha1.OVSPhysicalInterfaceConfig{
							{Name: "eth1", AllowedVLANs: allowedVLANs},
						},
					},
				},
			},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name             string
		operation        admv1.Operation
		anc              *crdv1alpha1.AntreaNodeConfig
		expectedResponse *admv1.AdmissionResponse
	}{
		{
			name:      "valid VLAN range",
			operation: admv1.Create,
			anc:       newAntreaNodeConfig([]string{"100", "200-300"}),
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name:      "inverted VLAN range",
			operation: admv1.Create,
			anc:       newAntreaNodeConfig([]string{"300-200"}),
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "spec.secondaryNetwork.ovsBridges[0].physicalInterfaces[0].allowedVLANs is invalid: VLAN range start 300 is greater than end 200",
				},
			},
		},
		{
			name:      "single VLAN above maximum",
			operation: admv1.Create,
			anc:       newAntreaNodeConfig([]string{"4095"}),
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "spec.secondaryNetwork.ovsBridges[0].physicalInterfaces[0].allowedVLANs is invalid: VLAN ID 4095 is greater than the maximum VLAN ID 4094",
				},
			},
		},
		{
			name:      "range end above maximum",
			operation: admv1.Create,
			anc:       newAntreaNodeConfig([]string{"4094-4095"}),
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "spec.secondaryNetwork.ovsBridges[0].physicalInterfaces[0].allowedVLANs is invalid: VLAN ID 4095 is greater than the maximum VLAN ID 4094",
				},
			},
		},
		{
			name:      "overlapping VLAN ranges are allowed (OVSDB deduplicates)",
			operation: admv1.Update,
			anc:       newAntreaNodeConfig([]string{"100-200", "150"}),
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name:      "delete allowed",
			operation: admv1.Delete,
			anc:       newAntreaNodeConfig([]string{"300-200"}),
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name:      "empty secondary network allowed",
			operation: admv1.Create,
			anc: &crdv1alpha1.AntreaNodeConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "anc"},
				Spec: crdv1alpha1.AntreaNodeConfigSpec{
					NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
				},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name:      "bridge without physical interfaces allowed",
			operation: admv1.Create,
			anc: &crdv1alpha1.AntreaNodeConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "anc"},
				Spec: crdv1alpha1.AntreaNodeConfigSpec{
					NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
					SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
						OVSBridges: []crdv1alpha1.OVSBridgeConfig{
							{BridgeName: "br-secondary"},
						},
					},
				},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			review := &admv1.AdmissionReview{
				Request: &admv1.AdmissionRequest{
					Name:      tt.anc.Name,
					Operation: tt.operation,
					Object:    runtime.RawExtension{Raw: marshal(t, tt.anc)},
				},
			}
			assert.Equal(t, tt.expectedResponse, Validate(review))
		})
	}
}
