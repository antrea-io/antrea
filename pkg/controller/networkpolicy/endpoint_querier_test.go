// Copyright 2020 Antrea Authors
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

package networkpolicy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

// pods represent kubernetes pods for testing proper query results
var pods = []*corev1.Pod{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podA",
			Namespace: "testNamespace",
			Labels:    map[string]string{"foo": "bar"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "container-1",
			}},
			NodeName: "nodeA",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: "1.2.3.4",
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podB",
			Namespace: "testNamespace",
			Labels:    map[string]string{"foo": "bar"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "container-1",
			}},
			NodeName: "nodeA",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: "1.2.3.4",
		},
	},
}

// polices represent kubernetes policies for testing proper query results
//
// policy 0: select all matching pods and allow ingress and egress from matching pods
// policy 1: select all matching pods and deny default egress
// policy 2: select all matching pods and allow ingress from multiple matching pods

var policies = []*networkingv1.NetworkPolicy{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress-egress",
			Namespace: "testNamespace",
			UID:       types.UID("uid-0"),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-egress",
			Namespace: "testNamespace",
			UID:       types.UID("uid-1"),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-multiple-ingress-rules",
			Namespace: "testNamespace",
			UID:       types.UID("uid-2"),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "baz"},
							},
						},
					},
				},
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
				},
			},
		},
	},
}

var namespaces = []*corev1.Namespace{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testNamespace",
			UID:  "testNamespaceUID",
		},
	},
}

func makeControllerAndEndpointQuerier(objects ...runtime.Object) *endpointQuerier {
	// create controller
	_, c := newController(objects, nil)
	c.heartbeatCh = make(chan heartbeat, 1000)
	stopCh := make(chan struct{})
	// create querier with stores inside controller
	querier := NewEndpointQuerier(c.NetworkPolicyController)
	// start informers and run controller
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.Start(stopCh)
	go c.groupingController.Run(stopCh)
	go c.groupingInterface.Run(stopCh)
	go c.Run(stopCh)
	// wait until computation is done, we assume it is done when no signal has been received on heartbeat channel for 3s.
	idleTimeout := 3 * time.Second
	timer := time.NewTimer(idleTimeout)
	func() {
		for {
			timer.Reset(idleTimeout)
			select {
			case <-c.heartbeatCh:
				continue
			case <-timer.C:
				close(stopCh)
				return
			}
		}
	}()
	// block until computation complete
	<-stopCh
	return querier
}

func TestQueryNetworkPolicyRules(t *testing.T) {
	policyRef := controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: policies[0].Namespace, Name: policies[0].Name, UID: policies[0].UID}
	policyRef1 := controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: policies[1].Namespace, Name: policies[1].Name, UID: policies[1].UID}
	policyRef2 := controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: policies[2].Namespace, Name: policies[2].Name, UID: policies[2].UID}
	ns, podA := "testNamespace", "podA"

	testCases := []struct {
		name             string
		objs             []runtime.Object
		podNamespace     string
		podName          string
		expectedResponse *antreatypes.EndpointNetworkPolicyRules
	}{
		{
			name:         "No matching pod",
			objs:         []runtime.Object{},
			podNamespace: "non-existing-namespace",
			podName:      "non-existing-pod",
		},
		{
			name:             "Empty response",
			objs:             []runtime.Object{namespaces[0], pods[0]},
			podNamespace:     ns,
			podName:          podA,
			expectedResponse: &antreatypes.EndpointNetworkPolicyRules{Namespace: ns, Name: podA},
		},
		{
			name:    "Default namespace",
			objs:    []runtime.Object{namespaces[0], pods[0]},
			podName: podA,
		},
		{
			name:         "Single KNP applied with ingress and egress rules",
			objs:         []runtime.Object{namespaces[0], pods[0], policies[0]},
			podNamespace: ns,
			podName:      podA,
			expectedResponse: &antreatypes.EndpointNetworkPolicyRules{
				Namespace:       ns,
				Name:            podA,
				AppliedPolicies: []*controlplane.NetworkPolicyReference{&policyRef},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{Policy: &policyRef, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}},
				},
				EndpointAsEgressDstRules: []*antreatypes.RuleInfo{
					{Policy: &policyRef, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionOut}},
				},
			},
		},
		{
			name:         "Multiple KNP applied", // Pod is selected by different policies
			objs:         []runtime.Object{namespaces[0], pods[0], policies[0], policies[1]},
			podNamespace: ns,
			podName:      podA,
			expectedResponse: &antreatypes.EndpointNetworkPolicyRules{
				Namespace:       ns,
				Name:            podA,
				AppliedPolicies: []*controlplane.NetworkPolicyReference{&policyRef, &policyRef1},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{Policy: &policyRef, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}},
				},
				EndpointAsEgressDstRules: []*antreatypes.RuleInfo{
					{Policy: &policyRef, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionOut}},
				},
			},
		},
		{
			name:         "Single KNP applied with multiple ingress rules", // Pod is selected by policy with multiple rules
			objs:         []runtime.Object{namespaces[0], pods[0], policies[2]},
			podNamespace: ns,
			podName:      podA,
			expectedResponse: &antreatypes.EndpointNetworkPolicyRules{
				Namespace:       ns,
				Name:            podA,
				AppliedPolicies: []*controlplane.NetworkPolicyReference{&policyRef2},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{Policy: &policyRef2, Index: 1, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}},
				},
			},
		},
	}

	evaluateResponse := func(expectedRules, responseRules []*antreatypes.RuleInfo) {
		assert.Equal(t, len(expectedRules), len(responseRules))
		for idx := range expectedRules {
			assert.EqualValues(t, expectedRules[idx].Rule.Direction, responseRules[idx].Rule.Direction)
			assert.Equal(t, expectedRules[idx].Index, responseRules[idx].Index)
			assert.Equal(t, expectedRules[idx].Policy, responseRules[idx].Policy)
		}
		return
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			endpointQuerier := makeControllerAndEndpointQuerier(tc.objs...)
			response, err := endpointQuerier.QueryNetworkPolicyRules(tc.podNamespace, tc.podName)
			require.NoErrorf(t, err, "Expected QueryNetworkPolicies to succeed")
			if tc.expectedResponse == nil {
				assert.Nil(t, response, "Expected nil response from QueryNetworkPolicyRules")
			} else {
				assert.Equal(t, tc.expectedResponse.Namespace, response.Namespace)
				assert.Equal(t, tc.expectedResponse.Name, response.Name)
				assert.Equal(t, len(tc.expectedResponse.AppliedPolicies), len(response.AppliedPolicies))
				var expectedPolicies, responsePolicies []*controlplane.NetworkPolicyReference
				for idx, expected := range tc.expectedResponse.AppliedPolicies {
					expectedPolicies = append(expectedPolicies, expected)
					responsePolicies = append(responsePolicies, response.AppliedPolicies[idx])
				}
				assert.ElementsMatch(t, expectedPolicies, responsePolicies)
				evaluateResponse(tc.expectedResponse.EndpointAsIngressSrcRules, response.EndpointAsIngressSrcRules)
				evaluateResponse(tc.expectedResponse.EndpointAsEgressDstRules, response.EndpointAsEgressDstRules)
			}
		})
	}
}
