// Copyright 2021 Antrea Authors
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
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/features"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

const waitEgressRealizedTimeout = 3 * time.Second
const waitEgressDualStackRealizedTimeout = 5 * time.Second

func skipIfEgressDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.Egress, true, true)
}

func skipIfEgressSeparateSubnetDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.EgressSeparateSubnet, true, false)
}

func TestEgress(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfAntreaIPAMTest(t)
	skipIfEgressDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	// Egress works for encap and hybrid modes.
	skipIfEncapModeIs(t, data, config.TrafficEncapModeNoEncap)
	skipIfEncapModeIs(t, data, config.TrafficEncapModeNetworkPolicyOnly)

	t.Run("testEgressClientIP", func(t *testing.T) { testEgressClientIP(t, data) })
	t.Run("testEgressClientIPFromVLANSubnet", func(t *testing.T) { testEgressClientIPFromVLANSubnet(t, data) })
	t.Run("testEgressCRUD", func(t *testing.T) { testEgressCRUD(t, data) })
	t.Run("testEgressUpdateEgressIP", func(t *testing.T) { testEgressUpdateEgressIP(t, data) })
	t.Run("testEgressUpdateNodeSelector", func(t *testing.T) { testEgressUpdateNodeSelector(t, data) })
	t.Run("testEgressNodeFailure", func(t *testing.T) { testEgressNodeFailure(t, data) })
	t.Run("testCreateExternalIPPool", func(t *testing.T) { testCreateExternalIPPool(t, data) })
	t.Run("testUpdateBandwidth", func(t *testing.T) { testEgressUpdateBandwidth(t, data) })
}

func TestDualStackEgress(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfAntreaIPAMTest(t)
	skipIfEgressDisabled(t)
	// Dual-stack Egress requires a cluster with both IPv4 and IPv6 pod networks.
	skipIfNotIPv4Cluster(t)
	skipIfNotIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfEncapModeIs(t, data, config.TrafficEncapModeNoEncap)
	skipIfEncapModeIs(t, data, config.TrafficEncapModeNetworkPolicyOnly)

	t.Run("testDualStackEgressClientIP", func(t *testing.T) { testDualStackEgressClientIP(t, data) })
	t.Run("testDualStackEgressCRUD", func(t *testing.T) { testDualStackEgressCRUD(t, data) })
	t.Run("testDualStackEgressUpdateEgressIPs", func(t *testing.T) { testDualStackEgressUpdateEgressIPs(t, data) })
	t.Run("testDualStackEgressUpdateNodeSelector", func(t *testing.T) { testDualStackEgressUpdateNodeSelector(t, data) })
	t.Run("testDualStackEgressNodeFailure", func(t *testing.T) { testDualStackEgressNodeFailure(t, data) })
	t.Run("testDualStackEgressUpdateBandwidth", func(t *testing.T) { testDualStackEgressUpdateBandwidth(t, data) })

}

func testCreateExternalIPPool(t *testing.T, data *TestData) {
	eip := v1beta1.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeExternalIPPool"},
		Spec:       v1beta1.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro-"}}},
	}

	_, err := data.CRDClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), &eip, metav1.CreateOptions{})
	assert.Error(t, err, "Should fail to create ExternalIPPool")
}

func testEgressClientIP(t *testing.T, data *TestData) {
	tests := []struct {
		name       string
		localIP0   string
		localIP1   string
		serverIP   string
		fakeServer string
		ipMaskLen  int
	}{
		{
			name:       "ipv4-cluster",
			localIP0:   "1.1.1.10",
			localIP1:   "1.1.1.11",
			serverIP:   "1.1.1.20",
			fakeServer: "eth-ipv4",
			ipMaskLen:  24,
		},
		{
			name:       "ipv6-cluster",
			localIP0:   "2021::aaa1",
			localIP1:   "2021::aaa2",
			serverIP:   "2021::aaa3",
			fakeServer: "eth-ipv6",
			ipMaskLen:  124,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			egressNode := controlPlaneNodeName()
			var egressNodeIP string
			if utilnet.IsIPv6String(tt.localIP0) {
				skipIfNotIPv6Cluster(t)
				egressNodeIP = controlPlaneNodeIPv6()
			} else {
				skipIfNotIPv4Cluster(t)
				egressNodeIP = controlPlaneNodeIPv4()
			}

			cmd, _ := getCommandInFakeExternalNetwork("/agnhost netexec", tt.ipMaskLen, tt.serverIP, tt.localIP0, tt.localIP1)
			if err := NewPodBuilder(tt.fakeServer, data.testNamespace, agnhostImage).OnNode(egressNode).WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data); err != nil {
				t.Fatalf("Failed to create server Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, tt.fakeServer)
			if err := data.podWaitForRunning(defaultTimeout, tt.fakeServer, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", tt.fakeServer)
			}

			localPod := fmt.Sprintf("localpod%s", tt.name)
			remotePod := fmt.Sprintf("remotepod%s", tt.name)
			if err := data.createToolboxPodOnNode(localPod, data.testNamespace, egressNode, false); err != nil {
				t.Fatalf("Failed to create local Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, localPod)
			if err := data.podWaitForRunning(defaultTimeout, localPod, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", localPod)
			}
			if err := data.createToolboxPodOnNode(remotePod, data.testNamespace, workerNodeName(1), false); err != nil {
				t.Fatalf("Failed to create remote Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, remotePod)
			if err := data.podWaitForRunning(defaultTimeout, remotePod, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", remotePod)
			}

			// As the fake server runs in a netns of the Egress Node, only egress Node can reach the server, Pods running on
			// other Nodes cannot reach it before Egress is added.
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIP, tt.localIP0, tt.localIP1)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIP)

			t.Logf("Creating an Egress applying to all e2e Pods")
			matchExpressions := []metav1.LabelSelectorRequirement{
				{
					Key:      "antrea-e2e",
					Operator: metav1.LabelSelectorOpExists,
				},
			}
			egress := data.createEgress(t, "egress-", matchExpressions, nil, "", egressNodeIP, nil)
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIP, egressNodeIP)
			assertClientIP(data, t, remotePod, toolboxContainerName, tt.serverIP, egressNodeIP)

			var err error
			err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*100, time.Second, false,
				func(ctx context.Context) (bool, error) {
					egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					return egress.Status.EgressNode == egressNode, nil
				})
			assert.NoError(t, err, "Egress failed to reach expected status")

			t.Log("Checking the client IP of a Pod whose Egress has been created in advance")
			initialIPChecker := "initial-ip-checker"
			clientIPStr := egress.Spec.EgressIP
			if utilnet.IsIPv6String(clientIPStr) {
				clientIPStr = fmt.Sprintf("[%s]", clientIPStr)
			}
			url := getHTTPURLFromIPPort(tt.serverIP, 8080, "clientip")
			cmd = fmt.Sprintf("wget -T 3 -O - %s | grep %s:", url, clientIPStr)
			if err := NewPodBuilder(initialIPChecker, data.testNamespace, agnhostImage).OnNode(egressNode).WithCommand([]string{"sh", "-c", cmd}).Create(data); err != nil {
				t.Fatalf("Failed to create Pod initial-ip-checker: %v", err)
			}
			defer data.DeletePod(data.testNamespace, initialIPChecker)
			_, err = data.PodWaitFor(timeout, initialIPChecker, data.testNamespace, func(pod *v1.Pod) (bool, error) {
				if pod.Status.Phase == v1.PodFailed {
					return false, fmt.Errorf("Pod terminated with failure")
				}
				return pod.Status.Phase == v1.PodSucceeded, nil
			})
			assert.NoError(t, err, "Failed to get expected client IP %s for Pod initial-ip-checker", initialIPChecker)

			t.Log("Updating the Egress's AppliedTo to remotePod only")
			egress.Spec.AppliedTo = v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"antrea-e2e": remotePod},
				},
			}
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Failed to update Egress %v: %v", egress, err)
			}
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIP, tt.localIP0, tt.localIP1)
			assertClientIP(data, t, remotePod, toolboxContainerName, tt.serverIP, egressNodeIP)

			t.Log("Updating the Egress's AppliedTo to localPod only")
			egress.Spec.AppliedTo = v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"antrea-e2e": localPod},
				},
			}
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Failed to update Egress %v: %v", egress, err)
			}
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIP, egressNodeIP)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIP)

			t.Logf("Updating the Egress's EgressIP to %s", tt.localIP1)
			egress.Spec.EgressIP = tt.localIP1
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Failed to update Egress %v: %v", egress, err)
			}
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIP, tt.localIP1)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIP)

			t.Log("Deleting the Egress")
			err = data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Fatalf("Failed to delete Egress %v: %v", egress, err)
			}
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIP, tt.localIP0, tt.localIP1)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIP)
		})
	}
}

func testEgressClientIPFromVLANSubnet(t *testing.T, data *TestData) {
	skipIfEgressSeparateSubnetDisabled(t)
	tests := []struct {
		name        string
		serverIP    string
		vlanSubnet  string
		vlanGateway string
		vlanID      int
	}{
		{
			name:        "ipv4-cluster",
			serverIP:    externalInfo.externalServerIPv4,
			vlanSubnet:  externalInfo.vlanSubnetIPv4,
			vlanGateway: externalInfo.vlanGatewayIPv4,
			vlanID:      externalInfo.vlanID,
		},
		{
			name:        "ipv6-cluster",
			serverIP:    externalInfo.externalServerIPv6,
			vlanSubnet:  externalInfo.vlanSubnetIPv6,
			vlanGateway: externalInfo.vlanGatewayIPv6,
			vlanID:      externalInfo.vlanID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.serverIP == "" {
				t.Skipf("Skipping test as the server IP is not set")
			}
			if tt.vlanSubnet == "" {
				t.Skipf("Skipping test as the vlan subnet is not set")
			}
			if utilnet.IsIPv6String(tt.serverIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}

			clientNode := workerNodeName(1)
			clientPod1 := fmt.Sprintf("clientpod1-%s", tt.name)
			clientPod2 := fmt.Sprintf("clientpod2-%s", tt.name)
			if err := data.createToolboxPodOnNode(clientPod1, data.testNamespace, clientNode, false); err != nil {
				t.Fatalf("Failed to create client Pod %s: %v", clientPod1, err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, clientPod1)
			if err := data.podWaitForRunning(defaultTimeout, clientPod1, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", clientPod1)
			}
			if err := data.createToolboxPodOnNode(clientPod2, data.testNamespace, clientNode, false); err != nil {
				t.Fatalf("Failed to create applied Pod %s: %v", clientPod2, err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, clientPod2)
			if err := data.podWaitForRunning(defaultTimeout, clientPod2, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", clientPod2)
			}

			gatewayIP := net.ParseIP(tt.vlanGateway)
			_, cidr, _ := net.ParseCIDR(tt.vlanSubnet)
			prefixLength, _ := cidr.Mask.Size()
			// We need only 1 Egress IP, set the range to include the next IP of the gateway IP.
			ipRange := v1beta1.IPRange{Start: ip.NextIP(gatewayIP).String(), End: ip.NextIP(gatewayIP).String()}
			subnet := v1beta1.SubnetInfo{
				Gateway:      tt.vlanGateway,
				PrefixLength: int32(prefixLength),
				VLAN:         int32(tt.vlanID),
			}
			pool := data.createExternalIPPool(t, "pool-vlan", ipRange, &subnet, nil, nil)
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "egress-vlan", nil, map[string]string{"antrea-e2e": clientPod1}, pool.Name, "", nil)
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			err := wait.PollUntilContextTimeout(context.Background(), 500*time.Millisecond, 3*time.Second, true, func(ctx context.Context) (done bool, err error) {
				egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				if !k8s.SemanticIgnoringTime.DeepEqual([]v1beta1.EgressCondition{
					{Type: v1beta1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
					{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				}, egress.Status.Conditions) {
					return false, nil
				}
				return true, nil
			})
			require.NoError(t, err, "Egress didn't meet expected conditions, current status: %v", egress.Status)

			// By default, Pod will be SNATed to Node IP.
			defaultClientIP := workerNodeIPv4(1)
			if utilnet.IsIPv6String(tt.serverIP) {
				defaultClientIP = workerNodeIPv6(1)
			}

			assertClientIP(data, t, clientPod1, toolboxContainerName, tt.serverIP, egress.Spec.EgressIP)
			assertClientIP(data, t, clientPod2, toolboxContainerName, tt.serverIP, defaultClientIP)

			t.Log("Updating the Egress's AppliedTo to clientPod2 only")
			egress.Spec.AppliedTo = v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"antrea-e2e": clientPod2},
				},
			}
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Failed to update Egress %v: %v", egress, err)
			}
			assertClientIP(data, t, clientPod1, toolboxContainerName, tt.serverIP, defaultClientIP)
			assertClientIP(data, t, clientPod2, toolboxContainerName, tt.serverIP, egress.Spec.EgressIP)

			t.Log("Deleting the Egress")
			err = data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Fatalf("Failed to delete Egress %v: %v", egress, err)
			}
			assertClientIP(data, t, clientPod1, toolboxContainerName, tt.serverIP, defaultClientIP)
			assertClientIP(data, t, clientPod2, toolboxContainerName, tt.serverIP, defaultClientIP)
		})
	}
}

func testEgressCRUD(t *testing.T, data *TestData) {
	tests := []struct {
		name               string
		ipRange            v1beta1.IPRange
		nodeSelector       metav1.LabelSelector
		expectedEgressIP   string
		expectedNodes      sets.Set[string]
		expectedTotal      int
		expectedConditions []v1beta1.EgressCondition
	}{
		{
			name:    "single matching Node",
			ipRange: v1beta1.IPRange{CIDR: "169.254.100.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedEgressIP: "169.254.100.1",
			expectedNodes:    sets.New[string](nodeName(0)),
			expectedTotal:    2,
			expectedConditions: []v1beta1.EgressCondition{
				{Type: v1beta1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
			},
		},
		{
			name:    "single matching Node with IPv6 range",
			ipRange: v1beta1.IPRange{CIDR: "2021:1::aaa0/124"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedEgressIP: "2021:1::aaa1",
			expectedNodes:    sets.New[string](nodeName(0)),
			expectedTotal:    15,
			expectedConditions: []v1beta1.EgressCondition{
				{Type: v1beta1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
			},
		},
		{
			name:    "two matching Nodes",
			ipRange: v1beta1.IPRange{Start: "169.254.101.10", End: "169.254.101.11"},
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedEgressIP: "169.254.101.10",
			expectedNodes:    sets.New[string](nodeName(0), nodeName(1)),
			expectedTotal:    2,
			expectedConditions: []v1beta1.EgressCondition{
				{Type: v1beta1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully assigned to EgressNode"},
				{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
			},
		},
		{
			name:    "no matching Node",
			ipRange: v1beta1.IPRange{CIDR: "169.254.102.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo": "bar",
				},
			},
			expectedEgressIP: "169.254.102.1",
			expectedNodes:    sets.New[string](),
			expectedTotal:    2,
			expectedConditions: []v1beta1.EgressCondition{
				{Type: v1beta1.IPAssigned, Status: v1.ConditionFalse, Reason: "AssignmentError", Message: "Failed to assign the IP to EgressNode: no Node available"},
				{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.expectedEgressIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}
			pool := data.createExternalIPPool(t, "crud-pool-", tt.ipRange, nil, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "crud-egress-", nil, map[string]string{"foo": "bar"}, pool.Name, "", nil)
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			// Use Poll to wait the interval before the first run to detect the case that the IP is assigned to any Node
			// when it's not supposed to.
			err := wait.PollUntilContextTimeout(context.Background(), 500*time.Millisecond, 3*time.Second, false, func(ctx context.Context) (done bool, err error) {
				egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				if egress.Spec.EgressIP != tt.expectedEgressIP {
					return false, nil
				}
				if !k8s.SemanticIgnoringTime.DeepEqual(tt.expectedConditions, egress.Status.Conditions) {
					return false, nil
				}
				if tt.expectedNodes.Len() == 0 {
					if egress.Status.EgressNode != "" {
						return false, fmt.Errorf("this Egress shouldn't be assigned to any Node")
					}
				} else {
					if !tt.expectedNodes.Has(egress.Status.EgressNode) {
						return false, nil
					}
				}
				return true, nil
			})
			require.NoError(t, err, "Expected egressIP=%s nodeName in %s, got egressIP=%s nodeName=%s", tt.expectedEgressIP, sets.List(tt.expectedNodes), egress.Spec.EgressIP, egress.Status.EgressNode)
			if egress.Status.EgressNode != "" {
				exists, err := hasIP(data, egress.Status.EgressNode, egress.Spec.EgressIP)
				require.NoError(t, err, "Failed to check if IP exists on Node")
				assert.True(t, exists, "Didn't find desired IP on Node")
				// Testing the events recorded during creation of an Egress resource.
				expectedMessage := fmt.Sprintf("Assigned Egress %s with IP %s on Node %v", egress.Name, tt.expectedEgressIP, egress.Status.EgressNode)
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					events, err := data.clientset.EventsV1().Events("").List(context.TODO(), metav1.ListOptions{
						FieldSelector: fmt.Sprintf("regarding.name=%s", egress.Name),
					})
					if assert.NoError(c, err) && assert.Len(c, events.Items, 1) {
						assert.Contains(c, events.Items[0].Note, expectedMessage)
					}
				}, 2*time.Second, 200*time.Millisecond)
			}

			checkEIPStatus := func(expectedUsed int) {
				var gotUsed, gotTotal int
				err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, 2*time.Second, true,
					func(ctx context.Context) (done bool, err error) {
						pool, err := data.CRDClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), pool.Name, metav1.GetOptions{})
						if err != nil {
							return false, fmt.Errorf("failed to get ExternalIPPool: %v", err)
						}
						gotUsed, gotTotal = pool.Status.Usage.Used, pool.Status.Usage.Total
						if expectedUsed != pool.Status.Usage.Used {
							return false, nil
						}
						if tt.expectedTotal != pool.Status.Usage.Total {
							return false, nil
						}
						return true, nil
					})
				require.NoError(t, err, "ExternalIPPool status not match: expectedTotal=%d, got=%d, expectedUsed=%d, got=%d", tt.expectedTotal, gotTotal, expectedUsed, gotUsed)
			}
			checkEIPStatus(1)

			err = data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			require.NoError(t, err, "Failed to delete Egress")
			if egress.Status.EgressNode != "" {
				err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true,
					func(ctx context.Context) (done bool, err error) {
						exists, err := hasIP(data, egress.Status.EgressNode, egress.Spec.EgressIP)
						if err != nil {
							return false, fmt.Errorf("check ip error: %v", err)
						}
						return !exists, nil
					})
				require.NoError(t, err, "Found stale IP (%s) exists on Node (%s)", egress.Spec.EgressIP, egress.Status.EgressNode)
			}
			checkEIPStatus(0)
		})
	}
}

func testEgressUpdateEgressIP(t *testing.T, data *TestData) {
	tests := []struct {
		name             string
		originalNode     string
		newNode          string
		originalIPRange  v1beta1.IPRange
		originalEgressIP string
		newIPRange       v1beta1.IPRange
		newEgressIP      string
	}{
		{
			name:             "same Node",
			originalNode:     nodeName(0),
			newNode:          nodeName(0),
			originalIPRange:  v1beta1.IPRange{CIDR: "169.254.100.0/30"},
			originalEgressIP: "169.254.100.1",
			newIPRange:       v1beta1.IPRange{CIDR: "169.254.101.0/30"},
			newEgressIP:      "169.254.101.1",
		},
		{
			name:             "different Nodes",
			originalNode:     nodeName(0),
			newNode:          nodeName(1),
			originalIPRange:  v1beta1.IPRange{CIDR: "169.254.100.0/30"},
			originalEgressIP: "169.254.100.1",
			newIPRange:       v1beta1.IPRange{CIDR: "169.254.101.0/30"},
			newEgressIP:      "169.254.101.1",
		},
		{
			name:             "different Nodes in IPv6 cluster",
			originalNode:     nodeName(0),
			newNode:          nodeName(1),
			originalIPRange:  v1beta1.IPRange{CIDR: "2021:2::aaa0/124"},
			originalEgressIP: "2021:2::aaa1",
			newIPRange:       v1beta1.IPRange{CIDR: "2021:2::bbb0/124"},
			newEgressIP:      "2021:2::bbb1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.originalEgressIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}
			originalPool := data.createExternalIPPool(t, "originalpool-", tt.originalIPRange, nil, nil, map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), originalPool.Name, metav1.DeleteOptions{})
			newPool := data.createExternalIPPool(t, "newpool-", tt.newIPRange, nil, nil, map[string]string{v1.LabelHostname: tt.newNode})
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), newPool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "egress-", nil, map[string]string{"foo": "bar"}, originalPool.Name, "", nil)
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err := data.checkEgressState(egress.Name, tt.originalEgressIP, tt.originalNode, "", time.Second)
			require.NoError(t, err)

			// The Egress maybe has been modified.
			toUpdate := egress.DeepCopy()
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				toUpdate.Spec.ExternalIPPool = newPool.Name
				toUpdate.Spec.EgressIP = tt.newEgressIP
				_, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
				if err != nil && errors.IsConflict(err) {
					toUpdate, _ = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				}
				return err
			})
			require.NoError(t, err, "Failed to update Egress")
			expectedMessages := []string{
				fmt.Sprintf("Assigned Egress %s with IP %s on Node %v", egress.Name, tt.originalEgressIP, tt.originalNode),
				fmt.Sprintf("Unassigned Egress %s with IP %s from Node %v", egress.Name, tt.originalEgressIP, tt.originalNode),
				fmt.Sprintf("Assigned Egress %s with IP %s on Node %v", egress.Name, tt.newEgressIP, tt.newNode),
			}
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				events, err := data.clientset.EventsV1().Events("").List(context.TODO(), metav1.ListOptions{
					FieldSelector: fmt.Sprintf("regarding.name=%s", egress.Name),
				})
				if assert.NoError(c, err) && assert.Len(c, events.Items, len(expectedMessages)) {
					recordedMessages := []string{}
					for _, items := range events.Items {
						recordedMessages = append(recordedMessages, items.Note)
					}
					assert.Equal(c, expectedMessages[0], recordedMessages[0])
					// The order of unassigning from original Node and assigning on new Node is random.
					assert.ElementsMatch(c, expectedMessages[1:], recordedMessages[1:])
				}
			}, 2*time.Second, 200*time.Millisecond)

			_, err = data.checkEgressState(egress.Name, tt.newEgressIP, tt.newNode, "", time.Second)
			require.NoError(t, err)
			err = wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true,
				func(ctx context.Context) (done bool, err error) {
					exists, err := hasIP(data, tt.originalNode, tt.originalEgressIP)
					if err != nil {
						return false, fmt.Errorf("check ip error: %v", err)
					}
					return !exists, nil
				})
			require.NoError(t, err, "Found stale IP (%s) exists on Node (%s)", tt.originalEgressIP, tt.originalNode)
		})
	}
}

func testEgressUpdateNodeSelector(t *testing.T, data *TestData) {
	// This test relies on IP neighbors to determine the effective Egress IP and requires all Nodes to be in the same subnet.
	// In hybrid mode, Nodes are in different subnets, so the test is skipped.
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)
	tests := []struct {
		name      string
		ipRange   v1beta1.IPRange
		ipVersion int
	}{
		{
			name:      "IPv4 cluster",
			ipRange:   v1beta1.IPRange{CIDR: "169.254.100.0/30"},
			ipVersion: 4,
		},
		{
			name:      "IPv6 cluster",
			ipRange:   v1beta1.IPRange{CIDR: "2021:3::aaa1/124"},
			ipVersion: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.ipVersion {
			case 4:
				skipIfNotIPv4Cluster(t)
			case 6:
				skipIfNotIPv6Cluster(t)
			}
			updateNodeSelector := func(poolName, evictNode string, ensureExists bool) {
				pool, err := data.CRDClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
				require.NoError(t, err, "Failed to get ExternalIPPool %v", pool)
				newNodes := sets.New[string](pool.Spec.NodeSelector.MatchExpressions[0].Values...)
				if ensureExists {
					newNodes.Insert(evictNode)
				} else {
					newNodes.Delete(evictNode)
				}
				pool.Spec.NodeSelector.MatchExpressions[0].Values = sets.List(newNodes)
				_, err = data.CRDClient.CrdV1beta1().ExternalIPPools().Update(context.TODO(), pool, metav1.UpdateOptions{})
				require.NoError(t, err, "Failed to update ExternalIPPool %v", pool)
			}
			shrinkEgressNodes := func(poolName, evictNode string) {
				// Remove one Node from the node candidates.
				updateNodeSelector(poolName, evictNode, false)
			}
			restoreEgressNodes := func(poolName, evictNode string) {
				// Add the removed Node back to the node candidates.
				updateNodeSelector(poolName, evictNode, true)
			}
			// Egress IP migration should happen fast when it's caused by nodeSelector update.
			// No IP should be left on the evicted Node.
			testEgressMigration(t, data, shrinkEgressNodes, restoreEgressNodes, true, time.Second, &tt.ipRange)
		})
	}
}

func testEgressNodeFailure(t *testing.T, data *TestData) {
	// This test relies on IP neighbors to determine the effective Egress IP and requires all Nodes to be in the same subnet.
	// In hybrid mode, Nodes are in different subnets, so the test is skipped.
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)
	tests := []struct {
		name      string
		ipRange   v1beta1.IPRange
		ipVersion int
	}{
		{
			name:      "IPv4 cluster",
			ipRange:   v1beta1.IPRange{CIDR: "169.254.100.0/30"},
			ipVersion: 4,
		},
		{
			name:      "IPv6 cluster",
			ipRange:   v1beta1.IPRange{CIDR: "2021:4::aaa1/124"},
			ipVersion: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.ipVersion {
			case 4:
				skipIfNotIPv4Cluster(t)
			case 6:
				skipIfNotIPv6Cluster(t)
			}
			signalAgent := func(nodeName, signal string) {
				cmd := fmt.Sprintf("pkill -%s antrea-agent", signal)
				if testOptions.providerName != "kind" {
					cmd = "sudo " + cmd
				}
				rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
				if rc != 0 || err != nil {
					t.Errorf("Error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
						cmd, nodeName, rc, stdout, stderr, err)
				}
			}
			pauseAgent := func(_, evictNode string) {
				// Send "STOP" signal to antrea-agent.
				signalAgent(evictNode, "STOP")
			}
			restoreAgent := func(_, evictNode string) {
				// Send "CONT" signal to antrea-agent.
				signalAgent(evictNode, "CONT")
			}
			// Egress IP migration may take a few seconds when it's caused by Node failure detection.
			// Skip checking Egress IP on the evicted Node because Egress IP will be left on it (no running antrea-agent).
			testEgressMigration(t, data, pauseAgent, restoreAgent, false, 10*time.Second, &tt.ipRange)
		})
	}
}

func testEgressMigration(t *testing.T, data *TestData, triggerFunc, revertFunc func(poolName, evictNode string), checkEvictNode bool, timeout time.Duration, ipRange *v1beta1.IPRange) {
	nodeCandidates := sets.New[string](nodeName(0), nodeName(1))
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      v1.LabelHostname,
			Operator: metav1.LabelSelectorOpIn,
			Values:   sets.List(nodeCandidates),
		},
	}
	externalIPPoolTwoNodes := data.createExternalIPPool(t, "pool-with-two-nodes-", *ipRange, nil, matchExpressions, nil)
	defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), externalIPPoolTwoNodes.Name, metav1.DeleteOptions{})

	egress := data.createEgress(t, "migration-egress-", nil, map[string]string{"foo": "bar"}, externalIPPoolTwoNodes.Name, "", nil)
	defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	var err error
	egress, err = data.waitForEgressRealized(egress)
	require.NoError(t, err)
	assert.True(t, nodeCandidates.Has(egress.Status.EgressNode))

	fromNode, toNode := nodeName(0), nodeName(1)
	if egress.Status.EgressNode != fromNode {
		fromNode, toNode = nodeName(1), nodeName(0)
	}
	var checkIPNeighbor func(string)
	if observerNode := nodeName(2); observerNode != "" {
		checkIPNeighbor, err = setupIPNeighborChecker(data, t, observerNode, fromNode, toNode, egress.Spec.EgressIP)
		require.NoError(t, err)
	} else {
		checkIPNeighbor = func(_ string) {
			t.Logf("The cluster didn't have enough Nodes, skip IP neighbor check")
		}
	}

	checkIPNeighbor(fromNode)

	// Trigger Egress IP migration. The EgressIP should be moved to the other Node.
	triggerFunc(externalIPPoolTwoNodes.Name, fromNode)
	// Defer revertFunc to restore the testbed regardless of success or failure.
	defer revertFunc(externalIPPoolTwoNodes.Name, fromNode)
	// Only check evictNode when checkEvictNode is true.
	var otherNodeToCheck string
	if checkEvictNode {
		otherNodeToCheck = fromNode
	}
	_, err = data.checkEgressState(egress.Name, egress.Spec.EgressIP, toNode, otherNodeToCheck, timeout)
	assert.NoError(t, err)
	checkIPNeighbor(toNode)

	// Revert the operation. The EgressIP should be moved back.
	revertFunc(externalIPPoolTwoNodes.Name, fromNode)
	_, err = data.checkEgressState(egress.Name, egress.Spec.EgressIP, fromNode, toNode, timeout)
	assert.NoError(t, err)
	checkIPNeighbor(fromNode)
}

func testEgressUpdateBandwidth(t *testing.T, data *TestData) {
	skipIfEgressShapingDisabled(t)
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)
	bandwidth := &v1beta1.Bandwidth{
		Rate:  "100M",
		Burst: "200M",
	}
	transMap := map[string]int{
		"100M": 100,
		"200M": 200,
	}

	egressNode := nodeName(1)
	egressNodeIP := nodeIP(1)

	// Create another netns to fake an external network on the host network Pod.
	fakeExternalName := "fake-external"
	fakeExternalCmd := "iperf3 -s"
	cmd, _ := getCommandInFakeExternalNetwork(fakeExternalCmd, 24, "1.1.1.1", "1.1.1.254")

	err := NewPodBuilder(fakeExternalName, data.testNamespace, ToolboxImage).OnNode(egressNode).WithCommand([]string{"bash", "-c", cmd}).InHostNetwork().Privileged().Create(data)
	require.NoError(t, err, "Failed to create fake external Pod")
	defer deletePodWrapper(t, data, data.testNamespace, fakeExternalName)
	err = data.podWaitForRunning(defaultTimeout, fakeExternalName, data.testNamespace)
	require.NoError(t, err, "Error when waiting for fake external Pod to be in the Running state")

	clientPodName := "client-pod"
	err = NewPodBuilder(clientPodName, data.testNamespace, ToolboxImage).OnNode(egressNode).Create(data)
	require.NoError(t, err, "Failed to create client Pod")
	defer deletePodWrapper(t, data, data.testNamespace, clientPodName)
	err = data.podWaitForRunning(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Error when waiting for the client Pod to be in the Running state")

	egress := data.createEgress(t, "egress-qos-", nil, map[string]string{"antrea-e2e": clientPodName}, "", egressNodeIP, bandwidth)
	_, err = data.waitForEgressRealized(egress)
	require.NoError(t, err, "Error when waiting for Egress to be realized")
	defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	// expectedBandwidth is Mbps
	runIperf := func(cmd []string, expectedBandwidth int) {
		stdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, "toolbox", cmd)
		if err != nil {
			t.Fatalf("Error when running iperf3 client: %v", err)
		}
		stdout = strings.TrimSpace(stdout)
		actualBandwidth, _ := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
		t.Logf("Actual bandwidth: %v Mbits/sec", actualBandwidth)
		// Allow a certain deviation.
		assert.InEpsilon(t, actualBandwidth, expectedBandwidth, 0.2)
	}

	runIperf([]string{"bash", "-c", "iperf3 -c 1.1.1.1 -f m -t 1|grep sender|awk '{print $7}'"}, transMap[bandwidth.Rate]+transMap[bandwidth.Burst])
	runIperf([]string{"bash", "-c", "iperf3 -c 1.1.1.1 -f m -O 1|grep sender|awk '{print $7}'"}, transMap[bandwidth.Rate])
}

func (data *TestData) checkEgressState(egressName, expectedIP, expectedNode, otherNode string, timeout time.Duration) (*v1beta1.Egress, error) {
	var egress *v1beta1.Egress
	var expectedNodeHasIP, otherNodeHasIP bool
	pollErr := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egressName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if egress.Spec.EgressIP != expectedIP {
			return false, nil
		}
		if egress.Status.EgressNode != expectedNode {
			return false, nil
		}
		// Make sure the IP is configured on the desired Node.
		expectedNodeHasIP, err = hasIP(data, expectedNode, expectedIP)
		if err != nil {
			return false, err
		}
		if !expectedNodeHasIP {
			return false, nil
		}
		if otherNode != "" {
			// Make sure the IP is not configured on the other Node.
			otherNodeHasIP, err = hasIP(data, otherNode, expectedIP)
			if err != nil {
				return false, err
			}
			if otherNodeHasIP {
				return false, nil
			}
		}
		return true, nil
	})
	if pollErr != nil {
		return egress, fmt.Errorf("egress did not reach expected state, err: %v, egress: %v, expectedIP: %s, expectedNode: %s, expectedNodeHasIP: %v, otherNodeHasIP: %v", pollErr, egress, expectedIP, expectedNode, expectedNodeHasIP, otherNodeHasIP)
	}
	return egress, nil
}

func hasIP(data *TestData, nodeName string, ip string) (bool, error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return false, err
	}
	cmd := []string{"ip", "-br", "addr"}
	stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
	if err != nil {
		return false, err
	}
	return strings.Contains(stdout, ip+"/32") || strings.Contains(stdout, ip+"/128"), nil
}

func setupIPNeighborChecker(data *TestData, t *testing.T, observerNode, node1, node2, ip string) (checkIPNeighbor func(string), err error) {
	transportInterface, err := data.GetTransportInterfaceName()
	require.NoError(t, err)

	macAddress1, err := data.GetNodeMACAddress(node1, transportInterface)
	require.NoError(t, err)
	macAddress2, err := data.GetNodeMACAddress(node2, transportInterface)
	require.NoError(t, err)
	nodeToMACAddress := map[string]string{node1: macAddress1, node2: macAddress2}

	antreaPodName, err := data.getAntreaPodOnNode(observerNode)
	require.NoError(t, err)

	// The Egress IP may not be in the same subnet as the primary IP of the transport interface.
	// Adding a direct route for the Egress IP so the Node will query its MAC address, instead of trying to connect via
	// its gateway.
	cmd := []string{"ip", "route", "replace", ip, "dev", transportInterface}
	_, _, err = data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
	require.NoError(t, err, "Failed to add a direct route for Egress IP %s on Node %s", ip, observerNode)

	t.Cleanup(func() {
		cmd := []string{"ip", "route", "del", ip, "dev", transportInterface}
		_, _, err = data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
		require.NoError(t, err, "Failed to delete the direct route for Egress IP %s on Node %s", ip, observerNode)
	})

	checkIPNeighbor = func(expectNode string) {
		check := func(allowEmpty bool) {
			showIPNeighCmd := []string{"ip", "neighbor", "show", ip, "dev", transportInterface}
			// stdout example:
			// 172.18.0.1 lladdr 02:42:c2:60:91:66 STALE
			stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, showIPNeighCmd)
			require.NoError(t, err, "Failed to query lladdr for Egress IP %s on Node %s", ip, observerNode)
			if stdout == "" || strings.Contains(stdout, "FAILED") {
				if !allowEmpty {
					t.Errorf("Didn't get lladdr for Egress IP %s on Node %s", ip, observerNode)
				}
				return
			}
			fields := strings.Fields(stdout)
			require.Len(t, fields, 4)
			llAddr := fields[2]
			assert.Equal(t, nodeToMACAddress[expectNode], llAddr, "lladdr for Egress IP %s didn't match the MAC address of Node %s", ip, expectNode)
		}
		// Before the Node actually connects to the Egress IP, we expect that the lladdr either matches the Egress Node's MAC address or is empty.
		check(true)
		// The protocol must be present when using wget with IPv6 address.
		cmd := []string{"wget", getHTTPURLFromIPPort(ip, 80), "-T", "1", "-t", "1"}
		// We don't care whether it succeeds, just make it connect to the Egress IP to learn its MAC address.
		data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
		// After the Node tries to connect to the Egress IP, we expect that the lladdr matches the Egress Node's MAC address.
		check(false)
	}
	return checkIPNeighbor, nil
}

func (data *TestData) createExternalIPPool(t *testing.T, generateName string, ipRange v1beta1.IPRange, subnet *v1beta1.SubnetInfo, matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string) *v1beta1.ExternalIPPool {
	pool := &v1beta1.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1beta1.ExternalIPPoolSpec{
			IPRanges:   []v1beta1.IPRange{ipRange},
			SubnetInfo: subnet,
			NodeSelector: metav1.LabelSelector{
				MatchExpressions: matchExpressions,
				MatchLabels:      matchLabels,
			},
		},
	}
	pool, err := data.CRDClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), pool, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create ExternalIPPool")
	return pool
}

func (data *TestData) createEgress(t *testing.T, generateName string, matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string, externalPoolName string, egressIP string, bandwidth *v1beta1.Bandwidth) *v1beta1.Egress {
	egress := &v1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1beta1.EgressSpec{
			AppliedTo: v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: matchExpressions,
					MatchLabels:      matchLabels,
				},
			},
			ExternalIPPool: externalPoolName,
			EgressIP:       egressIP,
			Bandwidth:      bandwidth,
		},
	}
	egress, err := data.CRDClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create Egress")
	return egress
}

func (data *TestData) waitForEgressRealized(egress *v1beta1.Egress) (*v1beta1.Egress, error) {
	err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, waitEgressRealizedTimeout, true,
		func(ctx context.Context) (done bool, err error) {
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if egress.Spec.EgressIP == "" || egress.Status.EgressNode == "" {
				return false, nil
			}
			return true, nil
		})
	if err != nil {
		return nil, fmt.Errorf("wait for Egress %#v realized failed: %v", egress, err)
	}
	return egress, nil
}

// assertClientIP asserts the Pod is translated to the provided client IP.
func assertClientIP(data *TestData, t *testing.T, pod, container, serverIP string, clientIPs ...string) {
	var exeErr error
	var stdout, stderr string
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 5*time.Second, false, func(ctx context.Context) (done bool, err error) {
		url := getHTTPURLFromIPPort(serverIP, 8080, "clientip")
		stdout, stderr, exeErr = data.runWgetCommandFromTestPodWithRetry(pod, data.testNamespace, container, url, 5)
		if exeErr != nil {
			return false, nil
		}

		// The stdout return is in this format: x.x.x.x:port or [xx:xx:xx::x]:port
		host, _, err := net.SplitHostPort(stdout)
		if err != nil {
			return false, nil
		}
		for _, cip := range clientIPs {
			if cip == host {
				return true, nil
			}
		}
		return false, nil
	})
	require.NoError(t, err, "Failed to get expected client IPs %s for Pod %s, stdout: %s, stderr: %s, err: %v", clientIPs, pod, stdout, stderr, exeErr)
}

// assertConnError asserts the Pod is not able to access the API that replies the request's client IP.
func assertConnError(data *TestData, t *testing.T, pod, container, serverIP string) {
	var exeErr error
	var stdout, stderr string
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 2*time.Second, false,
		func(ctx context.Context) (done bool, err error) {
			url := getHTTPURLFromIPPort(serverIP, 8080, "clientip")
			stdout, stderr, exeErr = data.runWgetCommandFromTestPodWithRetry(pod, data.testNamespace, url, container, 5)
			if exeErr != nil {
				return true, nil
			}
			return false, nil
		})
	require.NoError(t, err, "Failed to get expected error, stdout: %v, stderr: %v, err: %v", stdout, stderr, exeErr)

}

func (data *TestData) createDualStackEgress(t *testing.T, generateName string,
	matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string,
	ipv4Pool, ipv6Pool string, ipv4IP, ipv6IP string) *v1beta1.Egress {

	egress := &v1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1beta1.EgressSpec{
			AppliedTo: v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: matchExpressions,
					MatchLabels:      matchLabels,
				},
			},
		},
	}
	if ipv4Pool != "" && ipv6Pool != "" && ipv4IP == "" && ipv6IP == "" {
		egress.Spec.ExternalIPPools = []string{ipv4Pool, ipv6Pool}
	}
	if ipv4IP != "" && ipv6IP != "" && ipv4Pool == "" && ipv6Pool == "" {
		egress.Spec.EgressIPs = []string{ipv4IP, ipv6IP}
	}
	if ipv4Pool != "" && ipv6Pool != "" && ipv4IP != "" && ipv6IP != "" {
		egress.Spec.EgressIPs = []string{ipv4IP, ipv6IP}
		egress.Spec.ExternalIPPools = []string{ipv4Pool, ipv6Pool}
	}
	var err error
	egress, err = data.CRDClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create dual-stack Egress")
	return egress
}

func (data *TestData) checkDualStackEgressState(t *testing.T, egressName, expectedIPv4, expectedIPv6 string, timeout time.Duration) (*v1beta1.Egress, error) {
	t.Helper()
	var egress *v1beta1.Egress
	pollErr := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egressName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if egress.Status.EgressNode == "" {
			return false, nil
		}
		statusIPs := sets.New[string](egress.Status.EgressIPs...)
		if !statusIPs.Has(expectedIPv4) || !statusIPs.Has(expectedIPv6) {
			return false, nil
		}
		for _, ip := range []string{expectedIPv4, expectedIPv6} {
			ok, err := hasIP(data, egress.Status.EgressNode, ip)
			if err != nil {
				return false, nil
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	})
	if pollErr != nil {
		return egress, fmt.Errorf("dual-stack egress %s did not reach expected state (ipv4=%s ipv6=%s): %v, got status=%+v",
			egressName, expectedIPv4, expectedIPv6, pollErr, egress.Status)
	}
	return egress, nil
}

func (data *TestData) waitForDualStackEgressRealized(egress *v1beta1.Egress) (*v1beta1.Egress, error) {
	err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, waitEgressDualStackRealizedTimeout, true,
		func(ctx context.Context) (done bool, err error) {
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if egress.Status.EgressNode == "" || len(egress.Status.EgressIPs) < 2 {
				return false, nil
			}
			return true, nil
		})
	if err != nil {
		return nil, fmt.Errorf("wait for dual-stack Egress %s realized failed: %v, status=%+v", egress.Name, err, egress.Status)
	}
	return egress, nil
}

func testDualStackEgressClientIP(t *testing.T, data *TestData) {
	tests := []struct {
		name       string
		localIP0v4 string
		localIP1v4 string
		serverIPv4 string
		localIP0v6 string
		localIP1v6 string
		serverIPv6 string
		fakeV4Name string
		fakeV6Name string
	}{
		{
			name:       "dual-stack-cluster",
			localIP0v4: "1.1.2.10",
			localIP1v4: "1.1.2.11",
			serverIPv4: "1.1.2.20",
			localIP0v6: "2021:50::aa0a",
			localIP1v6: "2021:50::aa0b",
			serverIPv6: "2021:50::aa14",
			fakeV4Name: "ds-fake-v4",
			fakeV6Name: "ds-fake-v6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			egressNode := controlPlaneNodeName()
			egressNodeIPv4 := controlPlaneNodeIPv4()
			egressNodeIPv6 := controlPlaneNodeIPv6()

			cmdIPv4, _ := getCommandInFakeExternalNetwork("/agnhost netexec", 24, tt.serverIPv4, tt.localIP0v4, tt.localIP1v4)
			if err := NewPodBuilder(tt.fakeV4Name, data.testNamespace, agnhostImage).OnNode(egressNode).
				WithCommand([]string{"sh", "-c", cmdIPv4}).InHostNetwork().Privileged().Create(data); err != nil {
				t.Fatalf("Failed to create IPv4 fake server Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, tt.fakeV4Name)

			cmdIPv6, _ := getCommandInFakeExternalNetwork("/agnhost netexec", 120, tt.serverIPv6, tt.localIP0v6, tt.localIP1v6)
			if err := NewPodBuilder(tt.fakeV6Name, data.testNamespace, agnhostImage).OnNode(egressNode).
				WithCommand([]string{"sh", "-c", cmdIPv6}).InHostNetwork().Privileged().Create(data); err != nil {
				t.Fatalf("Failed to create IPv6 fake server Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, tt.fakeV6Name)

			for _, name := range []string{tt.fakeV4Name, tt.fakeV6Name} {
				if err := data.podWaitForRunning(defaultTimeout, name, data.testNamespace); err != nil {
					t.Fatalf("Error waiting for fake server Pod %s: %v", name, err)
				}
			}

			localPod := "ds-localpod"
			remotePod := "ds-remotepod"
			if err := data.createToolboxPodOnNode(localPod, data.testNamespace, egressNode, false); err != nil {
				t.Fatalf("Failed to create local Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, localPod)
			if err := data.createToolboxPodOnNode(remotePod, data.testNamespace, workerNodeName(1), false); err != nil {
				t.Fatalf("Failed to create remote Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, remotePod)
			for _, p := range []string{localPod, remotePod} {
				if err := data.podWaitForRunning(defaultTimeout, p, data.testNamespace); err != nil {
					t.Fatalf("Error waiting for Pod %s: %v", p, err)
				}
			}

			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv4, tt.localIP0v4, tt.localIP1v4)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv4)
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv6, tt.localIP0v6, tt.localIP1v6)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv6)

			t.Logf("Creating a dual-stack Egress with static IPs [%s, %s]", egressNodeIPv4, egressNodeIPv6)
			matchExpressions := []metav1.LabelSelectorRequirement{
				{Key: "antrea-e2e", Operator: metav1.LabelSelectorOpExists},
			}
			egress := data.createDualStackEgress(t, "ds-egress-", matchExpressions, nil,
				"", "", egressNodeIPv4, egressNodeIPv6)
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv4, egressNodeIPv4)
			assertClientIP(data, t, remotePod, toolboxContainerName, tt.serverIPv4, egressNodeIPv4)
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv6, egressNodeIPv6)
			assertClientIP(data, t, remotePod, toolboxContainerName, tt.serverIPv6, egressNodeIPv6)

			var err error
			err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*100, time.Second*5, false,
				func(ctx context.Context) (bool, error) {
					egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					return egress.Status.EgressNode == egressNode, nil
				})
			assert.NoError(t, err, "Dual-stack Egress failed to set EgressNode in status")

			t.Log("Updating AppliedTo to remotePod only")
			egress.Spec.AppliedTo = v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": remotePod}},
			}
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			require.NoError(t, err)

			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv4, tt.localIP0v4, tt.localIP1v4)
			assertClientIP(data, t, remotePod, toolboxContainerName, tt.serverIPv4, egressNodeIPv4)
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv6, tt.localIP0v6, tt.localIP1v6)
			assertClientIP(data, t, remotePod, toolboxContainerName, tt.serverIPv6, egressNodeIPv6)

			t.Log("Updating AppliedTo to localPod only")
			egress.Spec.AppliedTo = v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"antrea-e2e": localPod}},
			}
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			require.NoError(t, err)

			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv4, egressNodeIPv4)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv4)
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv6, egressNodeIPv6)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv6)

			t.Log("Updating EgressIPs to localIP0v4/localIP0v6")
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			egress.Spec.EgressIPs = []string{tt.localIP0v4, tt.localIP0v6}
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			require.NoError(t, err)

			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv4, tt.localIP0v4)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv4)
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv6, tt.localIP0v6)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv6)

			t.Log("Deleting the dual-stack Egress")
			require.NoError(t, data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{}))
			assertClientIP(data, t, localPod, toolboxContainerName, tt.serverIPv4, tt.localIP0v4, tt.localIP1v4)
			assertConnError(data, t, remotePod, toolboxContainerName, tt.serverIPv4)
		})
	}
}

func testDualStackEgressCRUD(t *testing.T, data *TestData) {
	tests := []struct {
		name           string
		ipv4Range      v1beta1.IPRange
		ipv6Range      v1beta1.IPRange
		expectedIPv4   string
		expectedIPv6   string
		nodeSelector   metav1.LabelSelector
		expectedNodes  sets.Set[string]
		noNodeExpected bool
	}{
		{
			name:         "single matching Node",
			ipv4Range:    v1beta1.IPRange{CIDR: "169.254.200.0/30"},
			ipv6Range:    v1beta1.IPRange{CIDR: "2021:10::aaa0/124"},
			expectedIPv4: "169.254.200.1",
			expectedIPv6: "2021:10::aaa1",
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{v1.LabelHostname: nodeName(0)},
			},
			expectedNodes: sets.New[string](nodeName(0)),
		},
		{
			name:         "two matching Nodes",
			ipv4Range:    v1beta1.IPRange{Start: "169.254.201.10", End: "169.254.201.11"},
			ipv6Range:    v1beta1.IPRange{CIDR: "2021:11::aaa0/124"},
			expectedIPv4: "169.254.201.10",
			expectedIPv6: "2021:11::aaa1",
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedNodes: sets.New[string](nodeName(0), nodeName(1)),
		},
		{
			name:         "no matching Node",
			ipv4Range:    v1beta1.IPRange{CIDR: "169.254.202.0/30"},
			ipv6Range:    v1beta1.IPRange{CIDR: "2021:12::aaa0/124"},
			expectedIPv4: "169.254.202.1",
			expectedIPv6: "2021:12::aaa1",
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			},
			expectedNodes:  sets.New[string](),
			noNodeExpected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4Pool := data.createExternalIPPool(t, "ds-crud-v4-pool-", tt.ipv4Range, nil,
				tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), ipv4Pool.Name, metav1.DeleteOptions{})

			ipv6Pool := data.createExternalIPPool(t, "ds-crud-v6-pool-", tt.ipv6Range, nil,
				tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), ipv6Pool.Name, metav1.DeleteOptions{})

			egress := data.createDualStackEgress(t, "ds-crud-egress-", nil, map[string]string{"foo": "bar"},
				ipv4Pool.Name, ipv6Pool.Name, "", "")
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

			var gotEgress *v1beta1.Egress
			err := wait.PollUntilContextTimeout(context.Background(), 500*time.Millisecond, 10*time.Second, false, func(ctx context.Context) (bool, error) {
				var e error
				gotEgress, e = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				if e != nil {
					return false, e
				}
				if tt.noNodeExpected {
					specIPs := sets.New[string](gotEgress.Spec.EgressIPs...)
					if !specIPs.Has(tt.expectedIPv4) || !specIPs.Has(tt.expectedIPv6) {
						return false, nil
					}
					if gotEgress.Status.EgressNode != "" {
						return false, nil
					}
					cond := v1beta1.GetEgressCondition(gotEgress.Status.Conditions, v1beta1.IPAssigned)
					return cond != nil && cond.Status == v1.ConditionFalse, nil
				}
				statusIPs := sets.New[string](gotEgress.Status.EgressIPs...)
				if !statusIPs.Has(tt.expectedIPv4) || !statusIPs.Has(tt.expectedIPv6) {
					return false, nil
				}
				return tt.expectedNodes.Has(gotEgress.Status.EgressNode), nil
			})
			require.NoError(t, err, "Dual-stack Egress did not reach expected state: ipv4=%s ipv6=%s nodes=%v, got=Spec.EgressIPs=%v Status=%+v",
				tt.expectedIPv4, tt.expectedIPv6, sets.List(tt.expectedNodes), gotEgress.Spec.EgressIPs, gotEgress.Status)

			if !tt.noNodeExpected {
				for _, ip := range []string{tt.expectedIPv4, tt.expectedIPv6} {
					exists, err := hasIP(data, gotEgress.Status.EgressNode, ip)
					require.NoError(t, err)
					assert.True(t, exists, "IP %s not found on node %s", ip, gotEgress.Status.EgressNode)
				}
			}

			// Verify ExternalIPPool usage increases by 1 for both pools.
			for _, poolName := range []string{ipv4Pool.Name, ipv6Pool.Name} {
				err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, 2*time.Second, true,
					func(ctx context.Context) (bool, error) {
						pool, e := data.CRDClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
						if e != nil {
							return false, e
						}
						return pool.Status.Usage.Used == 1, nil
					})
				require.NoError(t, err, "ExternalIPPool %s usage did not reach 1", poolName)
			}

			// Delete and verify IPs are removed from the Node and pool usage drops to 0.
			err = data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			require.NoError(t, err)

			if !tt.noNodeExpected {
				for _, ip := range []string{tt.expectedIPv4, tt.expectedIPv6} {
					err = wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true,
						func(ctx context.Context) (bool, error) {
							exists, e := hasIP(data, gotEgress.Status.EgressNode, ip)
							if e != nil {
								return false, nil
							}
							return !exists, nil
						})
					require.NoError(t, err, "Stale IP %s still exists on node %s after Egress deletion", ip, gotEgress.Status.EgressNode)
				}
			}

			for _, poolName := range []string{ipv4Pool.Name, ipv6Pool.Name} {
				err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, 2*time.Second, true,
					func(ctx context.Context) (bool, error) {
						pool, e := data.CRDClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
						if e != nil {
							return false, e
						}
						return pool.Status.Usage.Used == 0, nil
					})
				require.NoError(t, err, "ExternalIPPool %s usage did not drop to 0 after Egress deletion", poolName)
			}
		})
	}
}

func testDualStackEgressUpdateEgressIPs(t *testing.T, data *TestData) {
	tests := []struct {
		name          string
		originalNode  string
		newNode       string
		origIPv4Range v1beta1.IPRange
		origIPv6Range v1beta1.IPRange
		origIPv4      string
		origIPv6      string
		newIPv4Range  v1beta1.IPRange
		newIPv6Range  v1beta1.IPRange
		newIPv4       string
		newIPv6       string
	}{
		{
			name:          "same Node",
			originalNode:  nodeName(0),
			newNode:       nodeName(0),
			origIPv4Range: v1beta1.IPRange{CIDR: "169.254.210.0/30"},
			origIPv6Range: v1beta1.IPRange{CIDR: "2021:20::aaa0/124"},
			origIPv4:      "169.254.210.1",
			origIPv6:      "2021:20::aaa1",
			newIPv4Range:  v1beta1.IPRange{CIDR: "169.254.211.0/30"},
			newIPv6Range:  v1beta1.IPRange{CIDR: "2021:21::aaa0/124"},
			newIPv4:       "169.254.211.1",
			newIPv6:       "2021:21::aaa1",
		},
		{
			name:          "different Nodes",
			originalNode:  nodeName(0),
			newNode:       nodeName(1),
			origIPv4Range: v1beta1.IPRange{CIDR: "169.254.212.0/30"},
			origIPv6Range: v1beta1.IPRange{CIDR: "2021:22::aaa0/124"},
			origIPv4:      "169.254.212.1",
			origIPv6:      "2021:22::aaa1",
			newIPv4Range:  v1beta1.IPRange{CIDR: "169.254.213.0/30"},
			newIPv6Range:  v1beta1.IPRange{CIDR: "2021:23::aaa0/124"},
			newIPv4:       "169.254.213.1",
			newIPv6:       "2021:23::aaa1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origIPv4Pool := data.createExternalIPPool(t, "ds-update-orig-v4-", tt.origIPv4Range, nil, nil,
				map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), origIPv4Pool.Name, metav1.DeleteOptions{})
			origIPv6Pool := data.createExternalIPPool(t, "ds-update-orig-v6-", tt.origIPv6Range, nil, nil,
				map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), origIPv6Pool.Name, metav1.DeleteOptions{})

			newIPv4Pool := data.createExternalIPPool(t, "ds-update-new-v4-", tt.newIPv4Range, nil, nil,
				map[string]string{v1.LabelHostname: tt.newNode})
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), newIPv4Pool.Name, metav1.DeleteOptions{})
			newIPv6Pool := data.createExternalIPPool(t, "ds-update-new-v6-", tt.newIPv6Range, nil, nil,
				map[string]string{v1.LabelHostname: tt.newNode})
			defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), newIPv6Pool.Name, metav1.DeleteOptions{})

			egress := data.createDualStackEgress(t, "ds-update-egress-", nil, map[string]string{"foo": "bar"},
				origIPv4Pool.Name, origIPv6Pool.Name, "", "")
			defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

			egress, err := data.checkDualStackEgressState(t, egress.Name, tt.origIPv4, tt.origIPv6, 3*time.Second)
			require.NoError(t, err, "Original dual-stack Egress state not reached")
			assert.Equal(t, tt.originalNode, egress.Status.EgressNode)

			toUpdate := egress.DeepCopy()
			updateErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				toUpdate.Spec.ExternalIPPools = []string{newIPv4Pool.Name, newIPv6Pool.Name}
				toUpdate.Spec.EgressIPs = []string{tt.newIPv4, tt.newIPv6}
				_, e := data.CRDClient.CrdV1beta1().Egresses().Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
				if e != nil && errors.IsConflict(e) {
					toUpdate, _ = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				}
				return e
			})
			require.NoError(t, updateErr, "Failed to update dual-stack Egress pools")

			_, err = data.checkDualStackEgressState(t, egress.Name, tt.newIPv4, tt.newIPv6, 3*time.Second)
			require.NoError(t, err, "New dual-stack Egress state not reached")

			// Old IPs must be removed from the original node.
			for _, ip := range []string{tt.origIPv4, tt.origIPv6} {
				err = wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true,
					func(ctx context.Context) (bool, error) {
						exists, e := hasIP(data, tt.originalNode, ip)
						if e != nil {
							return false, nil
						}
						return !exists, nil
					})
				require.NoError(t, err, "Stale IP %s still present on original node %s", ip, tt.originalNode)
			}
		})
	}
}

func testDualStackEgressUpdateNodeSelector(t *testing.T, data *TestData) {
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

	ipv4Range := v1beta1.IPRange{CIDR: "169.254.220.0/30"}
	ipv6Range := v1beta1.IPRange{CIDR: "2021:30::aaa0/124"}
	nodeCandidates := sets.New[string](nodeName(0), nodeName(1))
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      v1.LabelHostname,
			Operator: metav1.LabelSelectorOpIn,
			Values:   sets.List(nodeCandidates),
		},
	}

	ipv4Pool := data.createExternalIPPool(t, "ds-ns-v4-pool-", ipv4Range, nil, matchExpressions, nil)
	defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), ipv4Pool.Name, metav1.DeleteOptions{})

	ipv6Pool := data.createExternalIPPool(t, "ds-ns-v6-pool-", ipv6Range, nil, matchExpressions, nil)
	defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), ipv6Pool.Name, metav1.DeleteOptions{})

	egress := data.createDualStackEgress(t, "ds-ns-egress-", nil, map[string]string{"foo": "bar"},
		ipv4Pool.Name, ipv6Pool.Name, "", "")
	defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	egress, err := data.waitForDualStackEgressRealized(egress)
	require.NoError(t, err)
	require.True(t, nodeCandidates.Has(egress.Status.EgressNode), "Initial EgressNode not in candidate set")

	fromNode := egress.Status.EgressNode
	toNode := nodeName(0)
	if fromNode == nodeName(0) {
		toNode = nodeName(1)
	}
	allocatedIPv4 := ""
	allocatedIPv6 := ""
	for _, ip := range egress.Status.EgressIPs {
		if utilnet.IsIPv6String(ip) {
			allocatedIPv6 = ip
		} else {
			allocatedIPv4 = ip
		}
	}
	require.NotEmpty(t, allocatedIPv4, "No IPv4 found in Status.EgressIPs")
	require.NotEmpty(t, allocatedIPv6, "No IPv6 found in Status.EgressIPs")

	// Remove fromNode from both pools simultaneously.
	updatePoolNodeSelector := func(poolName, evictNode string, add bool) {
		pool, e := data.CRDClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
		require.NoError(t, e)
		nodes := sets.New[string](pool.Spec.NodeSelector.MatchExpressions[0].Values...)
		if add {
			nodes.Insert(evictNode)
		} else {
			nodes.Delete(evictNode)
		}
		pool.Spec.NodeSelector.MatchExpressions[0].Values = sets.List(nodes)
		_, e = data.CRDClient.CrdV1beta1().ExternalIPPools().Update(context.TODO(), pool, metav1.UpdateOptions{})
		require.NoError(t, e)
	}

	updatePoolNodeSelector(ipv4Pool.Name, fromNode, false)
	updatePoolNodeSelector(ipv6Pool.Name, fromNode, false)
	defer func() {
		updatePoolNodeSelector(ipv4Pool.Name, fromNode, true)
		updatePoolNodeSelector(ipv6Pool.Name, fromNode, true)
	}()

	// Both IPs must appear on toNode and not on fromNode.
	_, err = data.checkDualStackEgressState(t, egress.Name, allocatedIPv4, allocatedIPv6, 3*time.Second)
	require.NoError(t, err)
	updatedEgress, _ := data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	assert.Equal(t, toNode, updatedEgress.Status.EgressNode, "EgressNode did not migrate to expected node")

	for _, ip := range []string{allocatedIPv4, allocatedIPv6} {
		exists, e := hasIP(data, fromNode, ip)
		require.NoError(t, e)
		assert.False(t, exists, "IP %s still present on evicted node %s", ip, fromNode)
	}

	// Restore fromNode to both pools; IPs should migrate back.
	updatePoolNodeSelector(ipv4Pool.Name, fromNode, true)
	updatePoolNodeSelector(ipv6Pool.Name, fromNode, true)

	_, err = data.checkDualStackEgressState(t, egress.Name, allocatedIPv4, allocatedIPv6, 3*time.Second)
	require.NoError(t, err)
	restoredEgress, _ := data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	assert.Equal(t, fromNode, restoredEgress.Status.EgressNode, "EgressNode did not migrate back to original node")
}

func testDualStackEgressNodeFailure(t *testing.T, data *TestData) {
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

	ipv4Range := v1beta1.IPRange{CIDR: "169.254.230.0/30"}
	ipv6Range := v1beta1.IPRange{CIDR: "2021:40::aaa0/124"}
	nodeCandidates := sets.New[string](nodeName(0), nodeName(1))
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      v1.LabelHostname,
			Operator: metav1.LabelSelectorOpIn,
			Values:   sets.List(nodeCandidates),
		},
	}

	ipv4Pool := data.createExternalIPPool(t, "ds-fail-v4-pool-", ipv4Range, nil, matchExpressions, nil)
	defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), ipv4Pool.Name, metav1.DeleteOptions{})

	ipv6Pool := data.createExternalIPPool(t, "ds-fail-v6-pool-", ipv6Range, nil, matchExpressions, nil)
	defer data.CRDClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), ipv6Pool.Name, metav1.DeleteOptions{})

	egress := data.createDualStackEgress(t, "ds-fail-egress-", nil, map[string]string{"foo": "bar"},
		ipv4Pool.Name, ipv6Pool.Name, "", "")
	defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	egress, err := data.waitForDualStackEgressRealized(egress)
	require.NoError(t, err)
	require.True(t, nodeCandidates.Has(egress.Status.EgressNode))

	fromNode := egress.Status.EgressNode
	toNode := nodeName(0)
	if fromNode == nodeName(0) {
		toNode = nodeName(1)
	}
	allocatedIPv4 := ""
	allocatedIPv6 := ""
	for _, ip := range egress.Status.EgressIPs {
		if utilnet.IsIPv6String(ip) {
			allocatedIPv6 = ip
		} else {
			allocatedIPv4 = ip
		}
	}
	require.NotEmpty(t, allocatedIPv4)
	require.NotEmpty(t, allocatedIPv6)

	type neighborChecker struct {
		check func(string)
	}
	var ipNeighborCheckers []neighborChecker
	if observerNode := nodeName(2); observerNode != "" {
		for _, ip := range []string{allocatedIPv4, allocatedIPv6} {
			fn, setupErr := setupIPNeighborChecker(data, t, observerNode, fromNode, toNode, ip)
			require.NoError(t, setupErr)
			ipNeighborCheckers = append(ipNeighborCheckers, neighborChecker{check: fn})
		}
	} else {
		noopChecker := neighborChecker{check: func(_ string) {
			t.Logf("The cluster didn't have enough Nodes, skip IP neighbor check")
		}}
		ipNeighborCheckers = []neighborChecker{noopChecker, noopChecker}
	}
	checkAllIPNeighbors := func(expectNode string) {
		for _, nc := range ipNeighborCheckers {
			nc.check(expectNode)
		}
	}

	checkAllIPNeighbors(fromNode)

	signalAgent := func(nodeName, signal string) {
		cmd := fmt.Sprintf("pkill -%s antrea-agent", signal)
		if testOptions.providerName != "kind" {
			cmd = "sudo " + cmd
		}
		rc, stdout, stderr, runErr := data.RunCommandOnNode(nodeName, cmd)
		if rc != 0 || runErr != nil {
			t.Errorf("Error running '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, err: %v",
				cmd, nodeName, rc, stdout, stderr, runErr)
		}
	}

	checkDualStackEgressOnNode := func(expectedNode string, timeout time.Duration) error {
		var expectedNodeHasIPv4, expectedNodeHasIPv6 bool
		pollErr := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true, func(ctx context.Context) (bool, error) {
			e, getErr := data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			if getErr != nil {
				return false, getErr
			}
			if e.Status.EgressNode != expectedNode {
				return false, nil
			}
			statusIPs := sets.New[string](e.Status.EgressIPs...)
			if !statusIPs.Has(allocatedIPv4) || !statusIPs.Has(allocatedIPv6) {
				return false, nil
			}
			var ipErr error
			expectedNodeHasIPv4, ipErr = hasIP(data, expectedNode, allocatedIPv4)
			if ipErr != nil {
				return false, nil
			}
			if !expectedNodeHasIPv4 {
				return false, nil
			}
			expectedNodeHasIPv6, ipErr = hasIP(data, expectedNode, allocatedIPv6)
			if ipErr != nil {
				return false, nil
			}
			if !expectedNodeHasIPv6 {
				return false, nil
			}
			return true, nil
		})
		if pollErr != nil {
			return fmt.Errorf("dual-stack egress did not reach expected state on node %s: %v (hasIPv4=%v, hasIPv6=%v)",
				expectedNode, pollErr, expectedNodeHasIPv4, expectedNodeHasIPv6)
		}
		return nil
	}

	signalAgent(fromNode, "STOP")
	defer signalAgent(fromNode, "CONT")

	assert.NoError(t, checkDualStackEgressOnNode(toNode, 15*time.Second),
		"EgressNode did not migrate to toNode after agent pause")
	checkAllIPNeighbors(toNode)

	signalAgent(fromNode, "CONT")
	assert.NoError(t, checkDualStackEgressOnNode(fromNode, 15*time.Second),
		"EgressNode did not migrate back after agent resume")
	checkAllIPNeighbors(fromNode)
}

func testDualStackEgressUpdateBandwidth(t *testing.T, data *TestData) {
	skipIfEgressShapingDisabled(t)

	bandwidth := &v1beta1.Bandwidth{
		Rate:  "100M",
		Burst: "200M",
	}
	transMap := map[string]int{
		"100M": 100,
		"200M": 200,
	}

	egressNode := controlPlaneNodeName()
	egressNodeIPv4 := controlPlaneNodeIPv4()
	egressNodeIPv6 := controlPlaneNodeIPv6()

	// Fake IPv4 external network running iperf3 server.
	fakeIPv4Name := "ds-bw-fake-v4"
	fakeIPv4ServerIP := "1.1.3.20"
	fakeIPv4LocalIP := "1.1.3.10"
	cmdIPv4, _ := getCommandInFakeExternalNetwork("iperf3 -s", 24, fakeIPv4ServerIP, fakeIPv4LocalIP)
	err := NewPodBuilder(fakeIPv4Name, data.testNamespace, ToolboxImage).OnNode(egressNode).
		WithCommand([]string{"bash", "-c", cmdIPv4}).InHostNetwork().Privileged().Create(data)
	require.NoError(t, err, "Failed to create IPv4 iperf server Pod")
	defer deletePodWrapper(t, data, data.testNamespace, fakeIPv4Name)

	// Fake IPv6 external network running iperf3 server.
	fakeIPv6Name := "ds-bw-fake-v6"
	fakeIPv6ServerIP := "2021:60::aa14"
	fakeIPv6LocalIP := "2021:60::aa0a"
	cmdIPv6, _ := getCommandInFakeExternalNetwork("iperf3 -s", 120, fakeIPv6ServerIP, fakeIPv6LocalIP)
	err = NewPodBuilder(fakeIPv6Name, data.testNamespace, ToolboxImage).OnNode(egressNode).
		WithCommand([]string{"bash", "-c", cmdIPv6}).InHostNetwork().Privileged().Create(data)
	require.NoError(t, err, "Failed to create IPv6 iperf server Pod")
	defer deletePodWrapper(t, data, data.testNamespace, fakeIPv6Name)

	for _, name := range []string{fakeIPv4Name, fakeIPv6Name} {
		require.NoError(t, data.podWaitForRunning(defaultTimeout, name, data.testNamespace),
			"Fake iperf server Pod %s did not become ready", name)
	}

	clientPodName := "ds-bw-client"
	err = NewPodBuilder(clientPodName, data.testNamespace, ToolboxImage).OnNode(egressNode).Create(data)
	require.NoError(t, err, "Failed to create client Pod")
	defer deletePodWrapper(t, data, data.testNamespace, clientPodName)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientPodName, data.testNamespace),
		"Client Pod did not become ready")

	egress := &v1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "ds-egress-bw-"},
		Spec: v1beta1.EgressSpec{
			AppliedTo: v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"antrea-e2e": clientPodName},
				},
			},
			EgressIPs: []string{egressNodeIPv4, egressNodeIPv6},
			Bandwidth: bandwidth,
		},
	}
	egress, err = data.CRDClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create dual-stack Egress with bandwidth")
	defer data.CRDClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	err = wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, waitEgressRealizedTimeout, true,
		func(ctx context.Context) (bool, error) {
			egress, err = data.CRDClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return egress.Status.EgressNode != "", nil
		})
	require.NoError(t, err, "Dual-stack Egress did not set EgressNode, status=%+v", egress.Status)

	runIperf := func(cmd []string, expectedBandwidth int) {
		stdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, "toolbox", cmd)
		if err != nil {
			t.Fatalf("Error when running iperf3 client: %v", err)
		}
		stdout = strings.TrimSpace(stdout)
		actualBandwidth, _ := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
		t.Logf("Actual bandwidth: %v Mbits/sec", actualBandwidth)
		assert.InEpsilon(t, actualBandwidth, expectedBandwidth, 0.2)
	}

	// Verify IPv4 traffic is shaped.
	t.Log("Measuring IPv4 bandwidth (burst)")
	runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -f m -t 1|grep sender|awk '{print $7}'", fakeIPv4ServerIP)},
		transMap[bandwidth.Rate]+transMap[bandwidth.Burst])
	t.Log("Measuring IPv4 bandwidth (sustained)")
	runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -f m -O 1|grep sender|awk '{print $7}'", fakeIPv4ServerIP)},
		transMap[bandwidth.Rate])

	// Verify IPv6 traffic is shaped independently by its own meter.
	t.Log("Measuring IPv6 bandwidth (burst)")
	runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -6 -f m -t 1|grep sender|awk '{print $7}'", fakeIPv6ServerIP)},
		transMap[bandwidth.Rate]+transMap[bandwidth.Burst])
	t.Log("Measuring IPv6 bandwidth (sustained)")
	runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -6 -f m -O 1|grep sender|awk '{print $7}'", fakeIPv6ServerIP)},
		transMap[bandwidth.Rate])
}
