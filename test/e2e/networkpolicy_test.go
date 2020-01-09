// Copyright 2019 Antrea Authors
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

package e2e

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIPBlockWithExcept(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	workerNode := workerNodeName(1)

	nginxPodName := randName("test-pod-nginx-")
	if err = data.createNginxPodOnNode(nginxPodName, workerNode); err != nil {
		t.Fatalf("Error when creating nginx pod: %v", err)
	}
	defer deletePodWrapper(t, data, nginxPodName)
	_, err = data.podWaitForIP(defaultTimeout, nginxPodName)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", nginxPodName, err)
	}

	svcName := randName("test-svc-nginx-")
	if err = data.createNginxService(svcName); err != nil {
		t.Fatalf("Error when creating nginx service: %v", err)
	}
	defer func() {
		if err = data.deleteService(svcName); err != nil {
			t.Fatalf("Error when deleting nginx service: %v", err)
		}
	}()

	npDenyAll := "test-networkpolicy-deny-all"
	denyAllPolicy, err := data.createNetworkPolicyDenyAll(npDenyAll)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(denyAllPolicy); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	podName0 := randName("test-pod-networkpolicy-")
	if err := data.createBusyboxPodOnNode(podName0, workerNode); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, podName0)
	if _, err := data.podWaitForIP(defaultTimeout, podName0); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName0, err)
	}

	podName1 := randName("test-pod-networkpolicy-")
	if err := data.createBusyboxPodOnNode(podName1, workerNode); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, podName1)
	podIP1, err := data.podWaitForIP(defaultTimeout, podName1)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName1, err)
	}

	// Both pods cannot connect to service.
	if err = data.runNetcatCommandFromTestPod(podName0, svcName); err == nil {
		t.Fatalf("Pod %s should not be able to connect Service %s, but was able to connect", podName0, svcName)
	}
	if err = data.runNetcatCommandFromTestPod(podName1, svcName); err == nil {
		t.Fatalf("Pod %s should not be able to connect Service %s, but was able to connect", podName1, svcName)
	}

	npIPblockExcept := "test-networkpolicy-ipblock-except"
	IPBlockExceptPolicy, err := data.createNetworkPolicyIPBlockWithExcept(npIPblockExcept, podIP1)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(IPBlockExceptPolicy); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	// pod0 can connect to service.
	if err = data.runNetcatCommandFromTestPod(podName0, svcName); err != nil {
		t.Fatalf("Pod %s should be able to connect Service %s, but was not able to connect: %v", podName0, svcName, err)
	}
	// pod1 cannot connect to service.
	if err = data.runNetcatCommandFromTestPod(podName1, svcName); err == nil {
		t.Fatalf("Pod %s should not be able to connect Service %s, but was able to connect", podName1, svcName)
	}
}

// createNetworkPolicyDenyAll creates a network policy with IPBlock's Except field.
func (data *TestData) createNetworkPolicyDenyAll(name string) (*networkingv1.NetworkPolicy, error) {
	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{},
	}
	return data.createNetworkPolicy(name, spec)
}

// createNetworkPolicyIPBlockWithExcept creates a network policy with IPBlock's Except field.
func (data *TestData) createNetworkPolicyIPBlockWithExcept(name string, exceptIP string) (*networkingv1.NetworkPolicy, error) {
	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app": "nginx",
			},
		},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: clusterInfo.podNetworkCIDR,
							Except: []string{
								exceptIP + "/32",
							},
						},
					},
				},
			},
		},
	}
	return data.createNetworkPolicy(name, spec)
}
