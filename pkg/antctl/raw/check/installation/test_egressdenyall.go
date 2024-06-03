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

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type EgressDenyAllConnectivityTest struct{}

func init() {
	RegisterTest("egress-deny-all-connectivity", &EgressDenyAllConnectivityTest{})
}

func (t EgressDenyAllConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	services := []string{echoSameNodeDeploymentName}
	if testContext.echoOtherNodePod != nil {
		services = append(services, echoOtherNodeDeploymentName)
	}
	if err := applyEgressDenyAll(ctx, testContext.client, testContext.namespace); err != nil {
		return err
	}
	defer func() error {
		if err := testContext.client.NetworkingV1().NetworkPolicies(testContext.namespace).Delete(ctx, "egress-deny-all", metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("NetworkPolicy deletion was unsuccessful: %w", err)
		}
		testContext.Log("NetworkPolicy deletion was successful")
		return nil
	}()
	testContext.Log("NetworkPolicy applied successfully")
	for _, clientPod := range testContext.clientPods {
		for _, service := range services {
			if err := testContext.runAgnhostConnect(ctx, clientPod.Name, "", service, 80); err != nil {
				testContext.Log("NetworkPolicy is working as expected: Pod %s cannot connect to Service %s", clientPod.Name, service)
			} else {
				return fmt.Errorf("NetworkPolicy is not working as expected: Pod %s connected to Service %s when it should not", clientPod.Name, service)
			}
		}
	}
	return nil
}

func applyEgressDenyAll(ctx context.Context, client kubernetes.Interface, namespace string) error {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-deny-all",
			Namespace: namespace,
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
	}
	_, err := client.NetworkingV1().NetworkPolicies(namespace).Create(ctx, networkPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating NetworkPolicy: %w", err)
	}
	return nil
}
