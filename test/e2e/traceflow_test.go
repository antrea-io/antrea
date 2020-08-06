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

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
)

type testcase struct {
	name            string
	tf              *v1alpha1.Traceflow
	expectedPhase   v1alpha1.TraceflowPhase
	expectedResults []v1alpha1.NodeResult
}

// TestTraceflow verifies if traceflow can trace intra/inter nodes traffic with some NetworkPolicies set.
func TestTraceflow(t *testing.T) {
	skipIfProviderIs(t, "kind", "Inter nodes test needs Geneve tunnel")
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	if err = data.enableTraceflow(t); err != nil {
		t.Fatal("Error when enabling Traceflow")
	}

	node1 := workerNodeName(1)
	node2 := workerNodeName(2)

	node1Pods, node1IPs, node1CleanupFn := createTestBusyboxPods(t, data, 2, node1)
	node2Pods, node2IPs, node2CleanupFn := createTestBusyboxPods(t, data, 1, node2)
	defer node1CleanupFn()
	defer node2CleanupFn()

	// Setup 2 NetworkPolicies:
	// 1. Allow all egress traffic.
	// 2. Deny ingress traffic on pod with label antrea-e2e = node1Pods[1]. So flow node1Pods[0] -> node1Pods[1] will be dropped.
	var allowAllEgress *networkingv1.NetworkPolicy
	allowAllEgressName := "test-networkpolicy-allow-all-egress"
	if allowAllEgress, err = data.createNPAllowAllEgress(allowAllEgressName); err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(allowAllEgress); err != nil {
			t.Errorf("Error when deleting network policy: %v", err)
		}
	}()

	var denyAllIngress *networkingv1.NetworkPolicy
	denyAllIngressName := "test-networkpolicy-deny-ingress"
	if denyAllIngress, err = data.createNPDenyAllIngress("antrea-e2e", node1Pods[1], denyAllIngressName); err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(denyAllIngress); err != nil {
			t.Errorf("Error when deleting network policy: %v", err)
		}
	}()

	antreaPod, err := data.getAntreaPodOnNode(node1)
	if err = data.waitForNetworkpolicyRealized(antreaPod, allowAllEgressName); err != nil {
		t.Fatal(err)
	}
	if err = data.waitForNetworkpolicyRealized(antreaPod, denyAllIngressName); err != nil {
		t.Fatal(err)
	}

	// Creates 4 traceflows:
	// 1. node1Pods[0] -> node1Pods[1], intra node1.
	// 2. node1Pods[0] -> node2Pods[0], inter node1 and node2.
	// 3. node1Pods[0] -> node1IPs[1], intra node1.
	// 4. node1Pods[0] -> node2IPs[0], inter node1 and node2.
	testcases := []testcase{
		{
			name: "intraNodeTraceflow",
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", testNamespace, node1Pods[0], testNamespace, node1Pods[1])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       node1Pods[1],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 6,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
							},
						},
					},
				},
			},
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.SpoofGuard,
							Action:    v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.NetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.NetworkPolicy,
							ComponentInfo: "IngressDefaultRule",
							Action:        v1alpha1.Dropped,
						},
					},
				},
			},
		},
		{
			name: "interNodeTraceflow",
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", testNamespace, node1Pods[0], testNamespace, node2Pods[0])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       node2Pods[0],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 6,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
							},
						},
					},
				},
			},
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.SpoofGuard,
							Action:    v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.NetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.Forwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.Forwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component:     v1alpha1.Forwarding,
							ComponentInfo: "Classification",
							Action:        v1alpha1.Received,
						},
						{
							Component:     v1alpha1.Forwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.Delivered,
						},
					},
				},
			},
		},
		{
			name: "intraNodeUDPDstIPTraceflow",
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], node1IPs[1])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: node1IPs[1],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 17,
						},
						TransportHeader: v1alpha1.TransportHeader{
							UDP: &v1alpha1.UDPHeader{
								DstPort: 321,
							},
						},
					},
				},
			},
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.SpoofGuard,
							Action:    v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.NetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.NetworkPolicy,
							ComponentInfo: "IngressDefaultRule",
							Action:        v1alpha1.Dropped,
						},
					},
				},
			},
		},
		{
			name: "interNodeICMPDstIPTraceflow",
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], node2IPs[0])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: node2IPs[0],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: 1,
						},
					},
				},
			},
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.SpoofGuard,
							Action:    v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.NetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.Forwarded,
						},
						{
							Component:     v1alpha1.Forwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.Forwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component:     v1alpha1.Forwarding,
							ComponentInfo: "Classification",
							Action:        v1alpha1.Received,
						},
						{
							Component:     v1alpha1.Forwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.Delivered,
						},
					},
				},
			},
		},
	}

	t.Run("traceflowGroupTest", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if _, err := data.crdClient.OpsV1alpha1().Traceflows().Create(context.TODO(), tc.tf, metav1.CreateOptions{}); err != nil {
					t.Fatalf("Error when creating traceflow: %v", err)
				}
				defer func() {
					if err := data.crdClient.OpsV1alpha1().Traceflows().Delete(context.TODO(), tc.tf.Name, metav1.DeleteOptions{}); err != nil {
						t.Errorf("Error when deleting traceflow: %v", err)
					}
				}()

				tf, err := data.waitForTraceflow(tc.tf.Name, tc.expectedPhase)
				if err != nil {
					t.Fatalf("Error: Get Traceflow failed: %v", err)
					return
				}
				if len(tf.Status.Results) != len(tc.expectedResults) {
					t.Fatalf("Error: Traceflow Results should be %v, but got %v", tc.expectedResults, tf.Status.Results)
					return
				}
				if len(tc.expectedResults) == 1 {
					if err = compareObservations(tc.expectedResults[0], tf.Status.Results[0], t); err != nil {
						t.Fatal(err)
						return
					}
				} else {
					if tf.Status.Results[0].Observations[0].Component == v1alpha1.SpoofGuard {
						if err = compareObservations(tc.expectedResults[0], tf.Status.Results[0], t); err != nil {
							t.Fatal(err)
							return
						}
						if err = compareObservations(tc.expectedResults[1], tf.Status.Results[1], t); err != nil {
							t.Fatal(err)
							return
						}
					} else {
						if err = compareObservations(tc.expectedResults[0], tf.Status.Results[1], t); err != nil {
							t.Fatal(err)
							return
						}
						if err = compareObservations(tc.expectedResults[1], tf.Status.Results[0], t); err != nil {
							t.Fatal(err)
							return
						}
					}
				}
			})
		}
	})
}

func (data *TestData) waitForTraceflow(name string, phase v1alpha1.TraceflowPhase) (*v1alpha1.Traceflow, error) {
	var tf *v1alpha1.Traceflow
	var err error
	if err = wait.PollImmediate(1*time.Second, 15*time.Second, func() (bool, error) {
		tf, err = data.crdClient.OpsV1alpha1().Traceflows().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil || tf.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return tf, nil
}

func (data *TestData) enableTraceflow(t *testing.T) error {
	configMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		t.Fatalf("Failed to get ConfigMap: %v", err)
	}

	// Enable Traceflow in antrea-controller and antrea-agent ConfigMap.
	// Use Geneve tunnel.
	antreaControllerConf, _ := configMap.Data["antrea-controller.conf"]
	antreaControllerConf = strings.Replace(antreaControllerConf, "#  Traceflow: false", " Traceflow: true", 1)
	configMap.Data["antrea-controller.conf"] = antreaControllerConf
	antreaAgentConf, _ := configMap.Data["antrea-agent.conf"]
	antreaAgentConf = strings.Replace(antreaAgentConf, "#  Traceflow: false", " Traceflow: true", 1)
	antreaAgentConf = strings.Replace(antreaAgentConf, "#tunnelType: geneve", "tunnelType: geneve", 1)
	configMap.Data["antrea-agent.conf"] = antreaAgentConf

	if _, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update ConfigMap %s: %v", configMap.Name, err)
	}
	_, err = data.restartAntreaControllerPod(defaultTimeout)
	if err != nil {
		return fmt.Errorf("error when restarting antrea-controller Pod: %v", err)
	}
	err = data.restartAntreaAgentPods(defaultTimeout)
	if err != nil {
		return fmt.Errorf("error when restarting antrea-agent Pod: %v", err)
	}

	return nil
}

// compareObservations compares expected results and actual results.
func compareObservations(expected v1alpha1.NodeResult, actual v1alpha1.NodeResult, t *testing.T) error {
	if expected.Node != actual.Node {
		return fmt.Errorf("NodeResult should be on %s, but is on %s", expected.Node, actual.Node)
	}
	exObs := expected.Observations
	acObs := actual.Observations
	if len(exObs) != len(acObs) {
		return fmt.Errorf("Observations should be %v, but got %v", exObs, acObs)
	}
	for i := 0; i < len(exObs); i++ {
		if exObs[i].Component != acObs[i].Component ||
			exObs[i].ComponentInfo != acObs[i].ComponentInfo ||
			exObs[i].Action != acObs[i].Action {
			return fmt.Errorf("Observations should be %v, but got %v", exObs, acObs)
		}
	}
	return nil
}

// createNPDenyAllIngress creates a NetworkPolicy that denies all ingress traffic for pods of specific label.
func (data *TestData) createNPDenyAllIngress(key string, value string, name string) (*networkingv1.NetworkPolicy, error) {
	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				key: value,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	}
	return data.createNetworkPolicy(name, spec)
}

// createNPAllowAllEgress creates a NetworkPolicy that allows all egress traffic.
func (data *TestData) createNPAllowAllEgress(name string) (*networkingv1.NetworkPolicy, error) {
	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			{},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
	}
	return data.createNetworkPolicy(name, spec)
}

// waitForNetworkpolicyRealized waits for the NetworkPolicy to be realized by the antrea-agent Pod.
func (data *TestData) waitForNetworkpolicyRealized(pod string, networkpolicy string) error {
	if err := wait.Poll(200*time.Millisecond, 5*time.Second, func() (bool, error) {
		cmds := []string{"antctl", "get", "networkpolicy", networkpolicy, "-n", testNamespace}
		if _, stderr, err := runAntctl(pod, cmds, data); err != nil {
			if strings.Contains(stderr, "server could not find the requested resource") {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}); err == wait.ErrWaitTimeout {
		return fmt.Errorf("NetworkPolicy %s isn't realized in time", networkpolicy)
	} else if err != nil {
		return fmt.Errorf("Error when executing antctl get NetworkPolicy: %v", err)
	}
	return nil
}
