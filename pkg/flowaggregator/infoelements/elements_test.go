// Copyright 2025 Antrea Authors
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

package infoelements

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAntreaInfoElements(t *testing.T) {
	infoElementsK8sNames := []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationServicePort",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
		"egressNetworkPolicyRuleAction",
		"tcpState",
		"flowType",
		"egressName",
		"egressIP",
		"egressNodeName",
	}

	infoElementsK8sUIDs := []string{
		"sourcePodUUID",
		"sourceNodeUUID",
		"destinationPodUUID",
		"destinationNodeUUID",
		"destinationServicePort",
		"destinationServiceUUID",
		"ingressNetworkPolicyUUID",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyUUID",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
		"egressNetworkPolicyRuleAction",
		"tcpState",
		"flowType",
		"egressUUID",
		"egressIP",
		"egressNodeUUID",
	}

	infoElementsNoK8sIdentifiers := []string{
		"destinationServicePort",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleAction",
		"tcpState",
		"flowType",
		"egressIP",
	}

	infoElementsK8sNamesAndUIDs := []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourcePodUUID",
		"sourceNodeName",
		"sourceNodeUUID",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationPodUUID",
		"destinationNodeName",
		"destinationNodeUUID",
		"destinationServicePort",
		"destinationServicePortName",
		"destinationServiceUUID",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"ingressNetworkPolicyUUID",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyUUID",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
		"egressNetworkPolicyRuleAction",
		"tcpState",
		"flowType",
		"egressName",
		"egressUUID",
		"egressIP",
		"egressNodeName",
		"egressNodeUUID",
	}

	testCases := []struct {
		name            string
		includeK8sNames bool
		includeK8sUIDs  bool
		expectedIEs     []string
	}{
		{
			name:            "K8s names",
			includeK8sNames: true,
			includeK8sUIDs:  false,
			expectedIEs:     infoElementsK8sNames,
		},
		{
			name:            "K8s UIDs",
			includeK8sNames: false,
			includeK8sUIDs:  true,
			expectedIEs:     infoElementsK8sUIDs,
		},
		{
			name:            "no K8s identifiers",
			includeK8sNames: false,
			includeK8sUIDs:  false,
			expectedIEs:     infoElementsNoK8sIdentifiers,
		},
		{
			name:            "K8s names and UIDs",
			includeK8sNames: true,
			includeK8sUIDs:  true,
			expectedIEs:     infoElementsK8sNamesAndUIDs,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("ipv4", func(t *testing.T) {
				expectedIEs := append(tc.expectedIEs, "destinationClusterIPv4")
				assert.Equal(t, expectedIEs, AntreaInfoElements(tc.includeK8sNames, tc.includeK8sUIDs, false))
			})
			t.Run("ipv6", func(t *testing.T) {
				expectedIEs := append(tc.expectedIEs, "destinationClusterIPv6")
				assert.Equal(t, expectedIEs, AntreaInfoElements(tc.includeK8sNames, tc.includeK8sUIDs, true))
			})
		})
	}
}
