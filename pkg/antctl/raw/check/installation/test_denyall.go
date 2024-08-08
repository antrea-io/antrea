// Copyright 2024 Antrea Authors.
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

package installation

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DenyAllConnectivityTest struct {
	networkPolicy *networkingv1.NetworkPolicy
}

// Provide enough time for policies to be enforced by the CNI plugin.
const networkPolicyDelay = 2 * time.Second

func init() {
	RegisterTest("egress-deny-all-connectivity", &DenyAllConnectivityTest{networkPolicy: &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egress-deny-all",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{clientDeploymentName},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	}})
	RegisterTest("ingress-deny-all-connectivity", &DenyAllConnectivityTest{networkPolicy: &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ingress-deny-all",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{echoSameNodeDeploymentName, echoOtherNodeDeploymentName},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}})
}

func (t *DenyAllConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	services := []*corev1.Service{testContext.echoSameNodeService}
	if testContext.echoOtherNodeService != nil {
		services = append(services, testContext.echoOtherNodeService)
	}
	_, err := testContext.client.NetworkingV1().NetworkPolicies(testContext.namespace).Create(ctx, t.networkPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating NetworkPolicy: %w", err)
	}
	defer func() error {
		if err := testContext.client.NetworkingV1().NetworkPolicies(testContext.namespace).Delete(ctx, t.networkPolicy.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("NetworkPolicy deletion was unsuccessful: %w", err)
		}
		testContext.Log("NetworkPolicy deletion was successful")
		return nil
	}()
	time.Sleep(networkPolicyDelay)
	testContext.Log("NetworkPolicy applied successfully")
	for _, clientPod := range testContext.clientPods {
		for _, service := range services {
			for _, clusterIP := range service.Spec.ClusterIPs {
				if err := testContext.tcpProbe(ctx, clientPod.Name, "", clusterIP, 80); err != nil {
					testContext.Log("NetworkPolicy is working as expected: Pod %s cannot connect to Service %s (%s)", clientPod.Name, service.Name, clusterIP)
				} else {
					return fmt.Errorf("NetworkPolicy is not working as expected: Pod %s connected to Service %s (%s) when it should not", clientPod.Name, service.Name, clusterIP)
				}
			}
		}
	}
	return nil
}
