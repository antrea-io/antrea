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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	queriermock "antrea.io/antrea/pkg/controller/networkpolicy/testing"
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

func makeControllerAndEndpointQuerier(objects ...runtime.Object) *EndpointQuerierImpl {
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
				Namespace: ns,
				Name:      podA,
				AppliedPolicies: []*antreatypes.NetworkPolicy{
					{SourceRef: &policyRef},
				},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{Policy: &antreatypes.NetworkPolicy{SourceRef: &policyRef}, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}},
				},
				EndpointAsEgressDstRules: []*antreatypes.RuleInfo{
					{Policy: &antreatypes.NetworkPolicy{SourceRef: &policyRef}, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionOut}},
				},
			},
		},
		{
			name:         "Multiple KNP applied", // Pod is selected by different policies
			objs:         []runtime.Object{namespaces[0], pods[0], policies[0], policies[1]},
			podNamespace: ns,
			podName:      podA,
			expectedResponse: &antreatypes.EndpointNetworkPolicyRules{
				Namespace: ns,
				Name:      podA,
				AppliedPolicies: []*antreatypes.NetworkPolicy{
					{SourceRef: &policyRef},
					{SourceRef: &policyRef1},
				},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{Policy: &antreatypes.NetworkPolicy{SourceRef: &policyRef}, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}},
				},
				EndpointAsEgressDstRules: []*antreatypes.RuleInfo{
					{Policy: &antreatypes.NetworkPolicy{SourceRef: &policyRef}, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionOut}},
				},
			},
		},
		{
			name:         "Single KNP applied with multiple ingress rules", // Pod is selected by policy with multiple rules
			objs:         []runtime.Object{namespaces[0], pods[0], policies[2]},
			podNamespace: ns,
			podName:      podA,
			expectedResponse: &antreatypes.EndpointNetworkPolicyRules{
				Namespace: ns,
				Name:      podA,
				AppliedPolicies: []*antreatypes.NetworkPolicy{
					{SourceRef: &policyRef2},
				},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{Policy: &antreatypes.NetworkPolicy{SourceRef: &policyRef2}, Index: 1, Rule: &controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}},
				},
			},
		},
	}

	evaluateResponse := func(expectedRules, responseRules []*antreatypes.RuleInfo) {
		assert.Equal(t, len(expectedRules), len(responseRules))
		for idx := range expectedRules {
			assert.EqualValues(t, expectedRules[idx].Rule.Direction, responseRules[idx].Rule.Direction)
			assert.Equal(t, expectedRules[idx].Index, responseRules[idx].Index)
			assert.Equal(t, expectedRules[idx].Policy.SourceRef, responseRules[idx].Policy.SourceRef)
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
					expectedPolicies = append(expectedPolicies, expected.SourceRef)
					responsePolicies = append(responsePolicies, response.AppliedPolicies[idx].SourceRef)
				}
				assert.ElementsMatch(t, expectedPolicies, responsePolicies)
				evaluateResponse(tc.expectedResponse.EndpointAsIngressSrcRules, response.EndpointAsIngressSrcRules)
				evaluateResponse(tc.expectedResponse.EndpointAsEgressDstRules, response.EndpointAsEgressDstRules)
			}
		})
	}
}

type AccessTestCase struct {
	name              string
	request           *controlplane.NetworkPolicyEvaluationRequest
	mockQueryResponse []mockResponse
	expectedResult    *controlplane.NetworkPolicyEvaluationResponse
	expectedErr       string
}

type mockResponse struct {
	response *antreatypes.EndpointNetworkPolicyRules
	error    error
}

func TestQueryNetworkPolicyEvaluation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	namespace, pod1, pod2 := "ns", "pod1", "pod2"
	accessRequest := &controlplane.NetworkPolicyEvaluationRequest{
		Source:      controlplane.Entity{Pod: &controlplane.PodReference{Namespace: namespace, Name: pod1}},
		Destination: controlplane.Entity{Pod: &controlplane.PodReference{Namespace: namespace, Name: pod2}},
	}
	argsMock := []string{namespace, pod1, namespace, pod2}
	uid1, uid2 := types.UID(fmt.Sprint(111)), types.UID(fmt.Sprint(222))
	priority1, priority2, defaultPriority, tierEmergency := float64(10), float64(15), float64(-1), int32(50)

	// functions used to generate mock responses
	generatePolicies := func(policyUID types.UID, policyType controlplane.NetworkPolicyType, direction controlplane.Direction, tierPriority *int32, policyPriority *float64, numRules int, action *crdv1beta1.RuleAction) []*antreatypes.NetworkPolicy {
		rules := make([]controlplane.NetworkPolicyRule, numRules)
		for i := 0; i < numRules; i++ {
			rules[i] = controlplane.NetworkPolicyRule{
				Direction: direction,
				Name:      fmt.Sprintf("Policy%sRule%d", policyUID, i),
				Priority:  int32(i),
			}
			if action != nil {
				rules[i].Action = action
			}
		}
		return []*antreatypes.NetworkPolicy{{
			UID:          policyUID,
			Name:         fmt.Sprintf("Policy%s", policyUID),
			SourceRef:    &controlplane.NetworkPolicyReference{Type: policyType, Namespace: namespace, Name: fmt.Sprintf("Policy%s", policyUID), UID: policyUID},
			Rules:        rules,
			TierPriority: tierPriority,
			Priority:     policyPriority,
		}}
	}
	generateRuleInfo := func(policy *antreatypes.NetworkPolicy) []*antreatypes.RuleInfo {
		ruleInfoMatches := make([]*antreatypes.RuleInfo, len(policy.Rules))
		for i := 0; i < len(policy.Rules); i++ {
			ruleInfoMatches[i] = &antreatypes.RuleInfo{
				Policy: policy,
				Index:  i,
				Rule:   &controlplane.NetworkPolicyRule{Direction: policy.Rules[i].Direction, Name: policy.Rules[i].Name, Action: policy.Rules[i].Action},
			}
		}
		return ruleInfoMatches
	}
	generateResponse := func(podID int, appliedPolicies []*antreatypes.NetworkPolicy, matchedRules []*antreatypes.RuleInfo) *antreatypes.EndpointNetworkPolicyRules {
		endpointRule := &antreatypes.EndpointNetworkPolicyRules{
			Namespace:       namespace,
			Name:            fmt.Sprintf("pod%d", podID),
			AppliedPolicies: appliedPolicies,
		}
		if podID == 1 {
			endpointRule.EndpointAsIngressSrcRules = matchedRules
		} else if podID == 2 {
			endpointRule.EndpointAsEgressDstRules = matchedRules
		}
		return endpointRule
	}

	expectedResponse111 := controlplane.NetworkPolicyEvaluationResponse{
		NetworkPolicy: controlplane.NetworkPolicyReference{Type: controlplane.AntreaNetworkPolicy, Namespace: namespace, Name: "Policy111", UID: uid1},
		RuleIndex:     0,
		Rule:          controlplane.RuleRef{Direction: controlplane.DirectionOut, Name: "Policy111Rule0", Action: &allowAction},
	}
	expectedResponse222 := controlplane.NetworkPolicyEvaluationResponse{
		NetworkPolicy: controlplane.NetworkPolicyReference{Type: controlplane.AntreaNetworkPolicy, Namespace: namespace, Name: "Policy222", UID: uid2},
		RuleIndex:     0,
		Rule:          controlplane.RuleRef{Direction: controlplane.DirectionIn, Name: "Policy222Rule0", Action: &allowAction},
	}

	testCases := []AccessTestCase{
		{
			name:    "Pass rule fallthrough",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.BaselineTierPriority), nil, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, &tierEmergency, nil, 1, &passAction)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, &tierEmergency, nil, 1, &passAction),
					generateRuleInfo(generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.BaselineTierPriority), nil, 1, &allowAction)[0]))},
			},
			expectedResult: &expectedResponse111,
		},
		{
			name:    "Different Tier priorities",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, &tierEmergency, nil, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), nil, 1, &allowAction)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), nil, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, &tierEmergency, nil, 1, &allowAction)[0]))},
			},
			expectedResult: &expectedResponse111,
		},
		{
			name:    "Different policy priorities 1",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority2, 1, &allowAction)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority2, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction)[0]))},
			},
			expectedResult: &expectedResponse111,
		},
		{
			name:    "Different policy priorities 2",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), &priority2, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), &priority2, 1, &allowAction)[0]))},
			},
			expectedResult: &expectedResponse222,
		},
		{
			name:    "Different rule priorities",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, nil, generateRuleInfo(generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 2, &allowAction)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 2, &allowAction), nil)},
			},
			expectedResult: &expectedResponse222,
		},
		{
			name:    "Different policy names",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.AntreaNetworkPolicy, controlplane.DirectionIn, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), &priority1, 1, &allowAction)[0]))},
			},
			expectedResult: &expectedResponse111,
		},
		{
			name:    "KNP and baseline ANP",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.BaselineTierPriority), nil, 1, &allowAction),
					generateRuleInfo(generatePolicies(uid2, controlplane.K8sNetworkPolicy, controlplane.DirectionIn, nil, &defaultPriority, 1, nil)[0]))},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.K8sNetworkPolicy, controlplane.DirectionIn, nil, &defaultPriority, 1, nil),
					generateRuleInfo(generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.BaselineTierPriority), nil, 1, &allowAction)[0]))},
			},
			expectedResult: &controlplane.NetworkPolicyEvaluationResponse{
				NetworkPolicy: controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: namespace, Name: "Policy222", UID: uid2},
				RuleIndex:     0,
				Rule:          controlplane.RuleRef{Direction: controlplane.DirectionIn, Name: "Policy222Rule0"},
			},
		},
		{
			name:    "KNP and default isolation",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.K8sNetworkPolicy, controlplane.DirectionOut, nil, &defaultPriority, 1, nil), nil)},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.K8sNetworkPolicy, controlplane.DirectionIn, nil, &defaultPriority, 1, nil),
					generateRuleInfo(generatePolicies(uid1, controlplane.K8sNetworkPolicy, controlplane.DirectionOut, nil, &defaultPriority, 1, nil)[0]))},
			},
			expectedResult: &controlplane.NetworkPolicyEvaluationResponse{
				NetworkPolicy: controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: namespace, Name: "Policy111", UID: uid1},
				RuleIndex:     0,
				Rule:          controlplane.RuleRef{Direction: controlplane.DirectionOut, Name: "Policy111Rule0"},
			},
		},
		{
			name:    "KNP egress default isolation",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.K8sNetworkPolicy, controlplane.DirectionOut, nil, &defaultPriority, 1, nil), nil)},
				{response: generateResponse(2, nil, nil)},
			},
			expectedResult: &controlplane.NetworkPolicyEvaluationResponse{
				NetworkPolicy: controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: namespace, Name: "Policy111", UID: uid1},
				RuleIndex:     -1,
				Rule:          controlplane.RuleRef{Direction: controlplane.DirectionOut, Name: "Policy111Rule0"},
			},
		},
		{
			name:    "KNP ingress default isolation",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, nil, nil)},
				{response: generateResponse(2, generatePolicies(uid2, controlplane.K8sNetworkPolicy, controlplane.DirectionIn, nil, &defaultPriority, 1, nil), nil)},
			},
			expectedResult: &controlplane.NetworkPolicyEvaluationResponse{
				NetworkPolicy: controlplane.NetworkPolicyReference{Type: controlplane.K8sNetworkPolicy, Namespace: namespace, Name: "Policy222", UID: uid2},
				RuleIndex:     -1,
				Rule:          controlplane.RuleRef{Direction: controlplane.DirectionIn, Name: "Policy222Rule0"},
			},
		},
		{
			name:    "No common rule found",
			request: accessRequest,
			mockQueryResponse: []mockResponse{
				{response: generateResponse(1, generatePolicies(uid1, controlplane.AntreaNetworkPolicy, controlplane.DirectionOut, ptr.To(crdv1beta1.DefaultTierPriority), nil, 1, &allowAction), nil)},
				{response: generateResponse(2, nil, nil)},
			},
		},
		{
			name:              "Querier error 1",
			request:           accessRequest,
			mockQueryResponse: []mockResponse{{}, {error: errors.NewInternalError(fmt.Errorf("querier error"))}},
			expectedErr:       "querier error",
		},
		{
			name:              "Querier error 2",
			request:           accessRequest,
			mockQueryResponse: []mockResponse{{error: errors.NewInternalError(fmt.Errorf("querier error"))}, {}},
			expectedErr:       "querier error",
		},
		{
			name:        "Request error",
			request:     &controlplane.NetworkPolicyEvaluationRequest{Destination: controlplane.Entity{Pod: &controlplane.PodReference{Namespace: namespace}}},
			expectedErr: "invalid NetworkPolicyEvaluation request entities",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mockQuerier := queriermock.NewMockEndpointQuerier(mockCtrl)
			if tc.mockQueryResponse != nil {
				for i, mock := range tc.mockQueryResponse {
					mockQuerier.EXPECT().QueryNetworkPolicyRules(argsMock[2*i], argsMock[2*i+1]).Return(mock.response, mock.error)
					if mock.error != nil {
						break
					}
				}
			}
			policyRuleQuerier := NewPolicyRuleQuerier(mockQuerier)
			response, err := policyRuleQuerier.QueryNetworkPolicyEvaluation(tc.request)
			if tc.expectedErr == "" {
				assert.Nil(t, err)
				assert.Equal(t, tc.expectedResult, response)
			} else {
				assert.ErrorContains(t, err, tc.expectedErr)
			}

		})
	}
}
