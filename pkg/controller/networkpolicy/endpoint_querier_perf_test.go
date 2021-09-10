//go:build !race
// +build !race

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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
)

/*
TestLargeScaleEndpointQueryManyPolicies tests the execution time and the memory usage of computing a scale
of 10k Namespaces, 10k NetworkPolicies, 10k Pods, where query returns every policy (applied + ingress).

NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)
1            10000   10000               13.88       1092

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestLargeScaleEndpointQueryManyPolicies(t *testing.T) {
	namespace := rand.String(8)
	getObjects := func() ([]*v1.Namespace, []*networkingv1.NetworkPolicy, []*v1.Pod) {
		namespaces := []*v1.Namespace{
			{
				ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"app": namespace}},
			},
		}
		uid := rand.String(8)
		networkPolicies := []*networkingv1.NetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "np-1" + uid, UID: types.UID(uuid.New().String())},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app-1": "scale-1"}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app-1": "scale-1"},
									},
								},
							},
						},
					},
				},
			},
		}
		pods := []*v1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "pod1" + uid, UID: types.UID(uuid.New().String()), Labels: map[string]string{"app-1": "scale-1"}},
				Spec:       v1.PodSpec{NodeName: getRandomNodeName()},
				Status:     v1.PodStatus{PodIP: getRandomIP()},
			},
		}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(10000, getObjects)
	testQueryEndpoint(t, 25*time.Second, namespaces[0:1], networkPolicies, pods, 10000)
}

func testQueryEndpoint(t *testing.T, maxExecutionTime time.Duration, namespaces []*v1.Namespace, networkPolicies []*networkingv1.NetworkPolicy, pods []*v1.Pod, responseLength int) {
	// Stat the maximum heap allocation.
	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	var maxAlloc uint64
	wg.Add(1)
	go func() {
		statMaxMemAlloc(&maxAlloc, 500*time.Millisecond, stopCh)
		wg.Done()
	}()
	// create controller
	objs := toRunTimeObjects(namespaces, networkPolicies, pods)
	querier := makeControllerAndEndpointQuerier(objs...)
	// Everything is ready, now start timing.
	start := time.Now()
	// track execution time by calling query endpoint 1000 times on random pods
	for i := 0; i < 1000; i++ {
		pod, namespace := pods[i].Name, pods[i].Namespace
		response, err := querier.QueryNetworkPolicies(namespace, pod)
		require.Equal(t, err, nil)
		require.Equal(t, len(response.Endpoints[0].Policies), responseLength)
	}
	// Stop tracking go routines
	stopCh <- struct{}{}
	// Minus the idle time to get the actual execution time.
	executionTime := time.Since(start)
	if executionTime > maxExecutionTime {
		t.Errorf("The actual execution time %v is greater than the maximum value %v", executionTime, maxExecutionTime)
	}

	// Block until all statistics are done.
	wg.Wait()

	t.Logf(`Summary metrics:
NAMESPACES   PODS    NETWORK-POLICIES    TIME(s)    MEMORY(M)    
%-12d %-7d %-19d %-10.2f %-12d 
`, len(namespaces), len(pods), len(networkPolicies), float64(executionTime)/float64(time.Second), maxAlloc/1024/1024)
}
