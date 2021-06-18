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

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
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
// policy 0: select all pods and deny default ingress
// policy 1: select all pods and deny default egress

var policies = []*networkingv1.NetworkPolicy{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress-egress",
			Namespace: "testNamespace",
			UID:       types.UID("uid-1"),
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
								MatchLabels:      map[string]string{"foo": "bar"},
								MatchExpressions: nil,
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
								MatchLabels:      map[string]string{"foo": "bar"},
								MatchExpressions: nil,
							},
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-deny-egress",
			UID:  types.UID("uid-2"),
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
	_, c := newController(objects...)
	c.heartbeatCh = make(chan heartbeat, 1000)
	stopCh := make(chan struct{})
	// create querier with stores inside controller
	querier := NewEndpointQuerier(c.NetworkPolicyController)
	// start informers and run controller
	c.informerFactory.Start(stopCh)
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

func TestEndpointQuery(t *testing.T) {
	policyRef0 := PolicyRef{policies[0].Namespace, policies[0].Name, policies[0].UID}
	policyRef1 := PolicyRef{policies[1].Namespace, policies[1].Name, policies[1].UID}

	testCases := []struct {
		name             string
		objs             []runtime.Object
		podNamespace     string
		podName          string
		expectedResponse *EndpointQueryResponse
	}{
		{
			"InvalidSelector", // provided Namespace / Name does not match any Pod
			[]runtime.Object{},
			"non-existing-namespace",
			"non-existing-pod",
			nil,
		},
		{
			"NoPolicy", // Pod is not selected by any policy
			[]runtime.Object{namespaces[0], pods[0]},
			"testNamespace",
			"podA",
			&EndpointQueryResponse{
				[]Endpoint{
					{Namespace: "testNamespace", Name: "podA", Policies: []Policy{}, Rules: []Rule{}},
				},
			},
		},
		{
			"SingleAppliedIngressEgressPolicy", // Pod is selected by a single policy
			[]runtime.Object{namespaces[0], pods[0], policies[0]},
			"testNamespace",
			"podA",
			&EndpointQueryResponse{
				[]Endpoint{
					{
						Namespace: "testNamespace",
						Name:      "podA",
						Policies:  []Policy{{policyRef0}},
						Rules: []Rule{
							{policyRef0, v1beta2.DirectionOut, 0},
							{policyRef0, v1beta2.DirectionIn, 0},
						},
					},
				},
			},
		},
		{
			"MultiplePolicy", // Pod is selected by different policies
			[]runtime.Object{namespaces[0], pods[0], policies[0], policies[1]},
			"testNamespace",
			"podA",
			&EndpointQueryResponse{
				[]Endpoint{
					{
						Namespace: "testNamespace",
						Name:      "podA",
						Policies: []Policy{
							{policyRef0},
							{policyRef1},
						},
						Rules: []Rule{
							{policyRef0, v1beta2.DirectionOut, 0},
							{policyRef0, v1beta2.DirectionIn, 0},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			endpointQuerier := makeControllerAndEndpointQuerier(tc.objs...)
			response, err := endpointQuerier.QueryNetworkPolicies(tc.podNamespace, tc.podName)
			require.NoErrorf(t, err, "Expected QueryNetworkPolicies to succeed")
			if tc.expectedResponse == nil {
				assert.Nil(t, response, "Expected nil response from QueryNetworkPolicies")
			} else {
				assert.Len(t, response.Endpoints, 1, "QueryNetworkPolicies should only return responses with a single endpoint")
				expectedEndpoint := &tc.expectedResponse.Endpoints[0]
				endpoint := &response.Endpoints[0]
				assert.Equal(t, expectedEndpoint.Namespace, endpoint.Namespace)
				assert.Equal(t, expectedEndpoint.Name, endpoint.Name)
				assert.ElementsMatch(t, expectedEndpoint.Rules, endpoint.Rules)
				assert.ElementsMatch(t, expectedEndpoint.Policies, endpoint.Policies)
			}
		})
	}
}
