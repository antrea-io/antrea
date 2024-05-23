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

package check

import (
	"context"
	"fmt"
	"os"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

func WaitForNetworkPolicyReady(ctx context.Context, client kubernetes.Interface, namespace string, policyName string, clusterName string) error {
	fmt.Fprintf(os.Stdout, fmt.Sprintf("[%s] ", clusterName)+"Waiting for Network policy %s to get applied successfully...\n", policyName)
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, policyName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("error while waiting for network policy to get ready: %w", err)
	}
	fmt.Fprintf(os.Stdout, fmt.Sprintf("[%s] ", clusterName)+"Network policy %s is ready.\n", policyName)
	return nil
}

func WaitForNetworkPolicyTeardown(ctx context.Context, client kubernetes.Interface, namespace string, policyName string, clusterName string) error {
	err := client.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, policyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting network policy: %w", err)
	}
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, policyName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	})
	if err != nil {
		fmt.Fprintf(os.Stdout, fmt.Sprintf("[%s] ", clusterName)+"Network policy deletion failed\n")
	} else {
		fmt.Fprintf(os.Stdout, fmt.Sprintf("[%s] ", clusterName)+"Network policy deletion successful\n")
	}
	return nil
}

func ApplyIngressAll(ctx context.Context, client kubernetes.Interface, namespace string) error {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "all-ingress-deny",
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"echo-same-node", "echo-other-node"},
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
		return fmt.Errorf("error creating network policy: %w", err)
	}
	return nil
}

func ApplyEgressAll(ctx context.Context, client kubernetes.Interface, namespace string) error {
	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "all-egress-deny",
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test-client"},
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
		return fmt.Errorf("error creating network policy: %w", err)
	}
	return nil
}
