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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"
	"time"
)

// pods represent kubernetes pods for testing proper query results
var pods = []v1.Pod{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podA",
			Namespace: "testNamespace",
			Labels:    map[string]string{"foo": "bar"},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name: "container-1",
			}},
			NodeName: "nodeA",
		},
		Status: v1.PodStatus{
			Conditions: []v1.PodCondition{
				{
					Type:   v1.PodReady,
					Status: v1.ConditionTrue,
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
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name: "container-1",
			}},
			NodeName: "nodeA",
		},
		Status: v1.PodStatus{
			Conditions: []v1.PodCondition{
				{
					Type:   v1.PodReady,
					Status: v1.ConditionTrue,
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

var policies = []networkingv1.NetworkPolicy{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress-egress",
			Namespace: "testNamespace",
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

var namespaces = []v1.Namespace{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testNamespace",
			UID:  "testNamespaceUID",
		},
	},
}

func makeControllerAndEndpointQueryReplier(objects ...runtime.Object) *EndpointQueryReplier {
	// create controller
	_, c := newController(objects...)
	c.heartbeatCh = make(chan heartbeat, 1000)
	stopCh := make(chan struct{})
	// create querier with stores inside controller
	querier := NewEndpointQueryReplier(c.NetworkPolicyController)
	// start informers and run controller
	c.informerFactory.Start(stopCh)
	go c.Run(stopCh)
	// wait until computation is done, we assume it is done when no signal has been received on heartbeat channel for 500ms
	idleTimeout := 500 * time.Millisecond
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

// TestInvalidSelector tests the result of QueryNetworkPolicy when the selector (right now pod, namespace) does not
// select any pods
func TestInvalidSelector(t *testing.T) {
	endpointQuerier := makeControllerAndEndpointQueryReplier()
	// test appropriate response to QueryNetworkPolices
	namespace, pod := "non-existing-namespace", "non-existing-pod"
	response, err := endpointQuerier.QueryNetworkPolicies(namespace, pod)
	if response != nil {
		assert.Fail(t, "expected nil endpoints")
	}
	assert.Equal(t, nil, err, "expected not nil error")
}

// TestNoPolicy tests the result of QueryNetworkPolicy when no policies are relevant to the endpoint
func TestNoPolicy(t *testing.T) {
	endpointQuerier := makeControllerAndEndpointQueryReplier(&namespaces[0], &pods[0])
	namespace1, pod1 := "testNamespace", "podA"
	response1, err := endpointQuerier.QueryNetworkPolicies(namespace1, pod1)
	require.Equal(t, nil, err)
	// test applied policy response
	assert.Equal(t, 0, len(response1.Endpoints[0].Policies))
	// test egress + ingress policy response
	assert.Equal(t, 0, len(response1.Endpoints[0].Rules))
}

// TestSingleAppliedPolicy tests the result of QueryNetworkPolicy when the selector (right now pod, namespace) selects a
// pod which has a single network policy object applied to it
func TestSingleAppliedIngressEgressPolicy(t *testing.T) {
	endpointQuerier := makeControllerAndEndpointQueryReplier(&namespaces[0], &pods[0], &policies[0])
	namespace1, pod1 := "testNamespace", "podA"
	response1, err := endpointQuerier.QueryNetworkPolicies(namespace1, pod1)
	require.Equal(t, nil, err)
	// test applied policy response
	assert.Equal(t, "test-ingress-egress", response1.Endpoints[0].Policies[0].PolicyRef.Name)
	// test egress policy response
	assert.Equal(t, v1beta1.DirectionOut, response1.Endpoints[0].Rules[0].Direction)
	assert.Equal(t, "test-ingress-egress", response1.Endpoints[0].Rules[0].PolicyRef.Name)
	// test ingress policy response
	assert.Equal(t, v1beta1.DirectionIn, response1.Endpoints[0].Rules[1].Direction)
	assert.Equal(t, "test-ingress-egress", response1.Endpoints[0].Rules[1].Name)
}

// TestMultiplePolicy tests the result of QueryNetworkPolicy when the selector (right now pod, namespace) selects
// a pod which has multiple networkpolicies which define policies on it.
func TestMultiplePolicy(t *testing.T) {
	endpointQuerier := makeControllerAndEndpointQueryReplier(&namespaces[0], &pods[0], &policies[0], &policies[1])
	namespace1, pod1 := "testNamespace", "podA"
	response, err := endpointQuerier.QueryNetworkPolicies(namespace1, pod1)
	require.Equal(t, nil, err)
	assert.True(t, response.Endpoints[0].Policies[0].Name == "default-deny-egress" ||
		response.Endpoints[0].Policies[0].Name == "test-ingress-egress")
	assert.True(t, response.Endpoints[0].Policies[1].Name == "default-deny-egress" ||
		response.Endpoints[0].Policies[1].Name == "test-ingress-egress")
}
