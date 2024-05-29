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

type IngressDenyAllConnectivityTest struct{}

func init() {
	RegisterTest("ingress-deny-all-connectivity", &IngressDenyAllConnectivityTest{})
}

func (a IngressDenyAllConnectivityTest) Run(ctx context.Context, testContext *testContext) error {
	values := []string{echoSameNodeDeploymentName}
	services := []string{echoSameNodeDeploymentName}
	if testContext.echoOtherNodePod != nil {
		values = append(values, echoOtherNodeDeploymentName)
		services = append(services, echoOtherNodeDeploymentName)
	}
	if err := applyIngressDenyAll(ctx, testContext.client, testContext.namespace, values); err != nil {
		return err
	}
	defer func() {
		if err := testContext.client.NetworkingV1().NetworkPolicies(testContext.namespace).Delete(ctx, "ingress-deny-all", metav1.DeleteOptions{}); err != nil {
			testContext.Log("NetworkPolicy deletion is unsuccessful: %v", err)
		}
		testContext.Log("NetworkPolicy deletion is successful")
	}()
	testContext.Log("NetworkPolicy applied successfully")
	for _, clientPod := range testContext.clientPods {
		for _, service := range services {
			if err := testContext.runAgnhostConnect(ctx, clientPod.Name, "", service, 80); err != nil {
				testContext.Log("NetworkPolicy is working as expected: Pod %s cannot connect to Service %s", clientPod.Name, service)
			} else {
				return fmt.Errorf("networkPolicy is not working as expected: Pod %s connected to Service %s when it should not", clientPod.Name, service)
			}
		}
	}
	return nil
}

func applyIngressDenyAll(ctx context.Context, client kubernetes.Interface, namespace string, values []string) error {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-deny-all",
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   values,
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
	_, err := client.NetworkingV1().NetworkPolicies(namespace).Create(ctx, networkPolicy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating NetworkPolicy: %w", err)
	}
	return nil
}
