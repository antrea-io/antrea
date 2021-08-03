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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

func TestEgress(t *testing.T) {
	skipIfProviderIs(t, "kind", "pkt_mark field is not properly supported for OVS userspace (netdev) datapath.")
	// TODO: remove this after making the test support IPv6 and dual-stack.
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	// Egress works for encap mode only.
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

	cc := []configChange{
		{"Egress", "true", true},
	}
	ac := []configChange{
		{"Egress", "true", true},
	}
	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to enable NetworkPolicyStats feature: %v", err)
	}

	t.Run("testEgressClientIP", func(t *testing.T) { testEgressClientIP(t, data) })
	t.Run("testEgressCRUD", func(t *testing.T) { testEgressCRUD(t, data) })
	t.Run("testEgressUpdateEgressIP", func(t *testing.T) { testEgressUpdateEgressIP(t, data) })
	t.Run("testEgressUpdateNodeSelector", func(t *testing.T) { testEgressUpdateNodeSelector(t, data) })
	t.Run("testEgressNodeFailure", func(t *testing.T) { testEgressNodeFailure(t, data) })
}

func testEgressClientIP(t *testing.T, data *TestData) {
	egressNode := controlPlaneNodeName()
	egressNodeIP := controlPlaneNodeIP()
	localIP0 := "1.1.1.10"
	localIP1 := "1.1.1.11"
	serverIP := "1.1.1.20"
	fakeServer := "fakeserver"

	// Create a http server in another netns to fake an external server connected to the egress Node.
	cmd := fmt.Sprintf(`ip netns add %[1]s && \
ip link add dev %[1]s-a type veth peer name %[1]s-b && \
ip link set dev %[1]s-a netns %[1]s && \
ip addr add %[3]s/24 dev %[1]s-b && \
ip addr add %[4]s/24 dev %[1]s-b && \
ip link set dev %[1]s-b up && \
ip netns exec %[1]s ip addr add %[2]s/24 dev %[1]s-a && \
ip netns exec %[1]s ip link set dev %[1]s-a up && \
ip netns exec %[1]s ip route replace default via %[3]s && \
ip netns exec %[1]s /agnhost netexec
`, fakeServer, serverIP, localIP0, localIP1)
	if err := data.createPodOnNode(fakeServer, testNamespace, egressNode, agnhostImage, []string{"sh", "-c", cmd}, nil, nil, nil, true, func(pod *v1.Pod) {
		privileged := true
		pod.Spec.Containers[0].SecurityContext = &v1.SecurityContext{Privileged: &privileged}
	}); err != nil {
		t.Fatalf("Failed to create server Pod: %v", err)
	}
	defer deletePodWrapper(t, data, fakeServer)
	if err := data.podWaitForRunning(defaultTimeout, fakeServer, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", fakeServer)
	}

	localPod := "localpod"
	remotePod := "remotepod"
	if err := data.createBusyboxPodOnNode(localPod, testNamespace, egressNode); err != nil {
		t.Fatalf("Failed to create local Pod: %v", err)
	}
	defer deletePodWrapper(t, data, localPod)
	if err := data.podWaitForRunning(defaultTimeout, localPod, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", localPod)
	}
	if err := data.createBusyboxPodOnNode(remotePod, testNamespace, workerNodeName(1)); err != nil {
		t.Fatalf("Failed to create remote Pod: %v", err)
	}
	defer deletePodWrapper(t, data, remotePod)
	if err := data.podWaitForRunning(defaultTimeout, remotePod, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", remotePod)
	}

	// getClientIP gets the translated client IP by accessing the API that replies the request's client IP.
	getClientIP := func(pod string) (string, string, error) {
		cmd := []string{"wget", "-T", "3", "-O", "-", fmt.Sprintf("%s:8080/clientip", serverIP)}
		return data.runCommandFromPod(testNamespace, pod, busyboxContainerName, cmd)
	}

	// assertClientIP asserts the Pod is translated to the provided client IP.
	assertClientIP := func(pod string, clientIP string) {
		var exeErr error
		var stdout, stderr string
		if err := wait.Poll(100*time.Millisecond, 2*time.Second, func() (done bool, err error) {
			stdout, stderr, exeErr = getClientIP(pod)
			if exeErr != nil {
				return false, nil
			}
			// The stdout return is in this format: x.x.x.x:port or [xx:xx:xx::x]:port
			host, _, err := net.SplitHostPort(stdout)
			if err != nil {
				return false, nil
			}
			return host == clientIP, nil
		}); err != nil {
			t.Fatalf("Failed to get expected client IP %s for Pod %s, stdout: %s, stderr: %s, err: %v", clientIP, pod, stdout, stderr, exeErr)
		}
	}

	// assertConnError asserts the Pod is not able to access the API that replies the request's client IP.
	assertConnError := func(pod string) {
		var exeErr error
		var stdout, stderr string
		if err := wait.Poll(100*time.Millisecond, 2*time.Second, func() (done bool, err error) {
			stdout, stderr, exeErr = getClientIP(pod)
			if exeErr != nil {
				return true, nil
			}
			return false, nil
		}); err != nil {
			t.Fatalf("Failed to get expected error, stdout: %v, stderr: %v, err: %v", stdout, stderr, exeErr)
		}
	}

	// As the fake server runs in a netns of the Egress Node, only egress Node can reach the server, Pods running on
	// other Nodes cannot reach it before Egress is added.
	assertClientIP(localPod, localIP0)
	assertConnError(remotePod)

	t.Logf("Creating an Egress applying to both Pods")
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      "antrea-e2e",
			Operator: metav1.LabelSelectorOpExists,
		},
	}
	egress := data.createEgress(t, "egress-", matchExpressions, nil, "", egressNodeIP)
	defer data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
	assertClientIP(localPod, egressNodeIP)
	assertClientIP(remotePod, egressNodeIP)

	t.Log("Updating the Egress's AppliedTo to remotePod only")
	egress.Spec.AppliedTo = v1alpha2.AppliedTo{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"antrea-e2e": remotePod},
		},
	}
	egress, err := data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update Egress %v: %v", egress, err)
	}
	assertClientIP(localPod, localIP0)
	assertClientIP(remotePod, egressNodeIP)

	t.Log("Updating the Egress's AppliedTo to localPod only")
	egress.Spec.AppliedTo = v1alpha2.AppliedTo{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"antrea-e2e": localPod},
		},
	}
	egress, err = data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update Egress %v: %v", egress, err)
	}
	assertClientIP(localPod, egressNodeIP)
	assertConnError(remotePod)

	t.Logf("Updating the Egress's EgressIP to %s", localIP1)
	egress.Spec.EgressIP = localIP1
	egress, err = data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update Egress %v: %v", egress, err)
	}
	assertClientIP(localPod, localIP1)
	assertConnError(remotePod)

	t.Log("Deleting the Egress")
	err = data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete Egress %v: %v", egress, err)
	}
	assertClientIP(localPod, localIP0)
	assertConnError(remotePod)
}

func testEgressCRUD(t *testing.T, data *TestData) {
	tests := []struct {
		name             string
		ipRange          v1alpha2.IPRange
		nodeSelector     metav1.LabelSelector
		expectedEgressIP string
		expectedNodes    sets.String
	}{
		{
			name:    "single matching Node",
			ipRange: v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedEgressIP: "169.254.100.1",
			expectedNodes:    sets.NewString(nodeName(0)),
		},
		{
			name:    "two matching Nodes",
			ipRange: v1alpha2.IPRange{Start: "169.254.101.10", End: "169.254.101.11"},
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
			expectedNodes:    sets.NewString(nodeName(0), nodeName(1)),
		},
		{
			name:    "no matching Node",
			ipRange: v1alpha2.IPRange{CIDR: "169.254.102.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo": "bar",
				},
			},
			expectedEgressIP: "169.254.102.1",
			expectedNodes:    sets.NewString(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := data.createExternalIPPool(t, "pool-", tt.ipRange, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "egress-", nil, map[string]string{"foo": "bar"}, pool.Name, "")
			defer data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			// Use Poll to wait the interval before the first run to detect the case that the IP is assigned to any Node
			// when it's not supposed to.
			err := wait.Poll(500*time.Millisecond, 3*time.Second, func() (done bool, err error) {
				egress, err = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				if egress.Spec.EgressIP != tt.expectedEgressIP {
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
			require.NoError(t, err, "Expected egressIP=%s nodeName in %s, got egressIP=%s nodeName=%s", tt.expectedEgressIP, tt.expectedNodes.List(), egress.Spec.EgressIP, egress.Status.EgressNode)
			if egress.Status.EgressNode != "" {
				exists, err := hasIP(data, egress.Status.EgressNode, egress.Spec.EgressIP)
				require.NoError(t, err, "Failed to check if IP exists on Node")
				assert.True(t, exists, "Didn't find desired IP on Node")
			}

			err = data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			require.NoError(t, err, "Failed to delete Egress")
			if egress.Status.EgressNode != "" {
				exists, err := hasIP(data, egress.Status.EgressNode, egress.Spec.EgressIP)
				require.NoError(t, err, "Failed to check if IP exists on Node")
				assert.False(t, exists, "Found stale IP on Node")
			}
		})
	}
}

func testEgressUpdateEgressIP(t *testing.T, data *TestData) {
	tests := []struct {
		name             string
		originalNode     string
		newNode          string
		originalEgressIP string
		newEgressIP      string
	}{
		{
			name:         "same Node",
			originalNode: nodeName(0),
			newNode:      nodeName(0),
		},
		{
			name:         "different Nodes",
			originalNode: nodeName(0),
			newNode:      nodeName(1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPool := data.createExternalIPPool(t, "originalpool-", v1alpha2.IPRange{CIDR: "169.254.100.0/30"}, nil, map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), originalPool.Name, metav1.DeleteOptions{})
			newPool := data.createExternalIPPool(t, "newpool-", v1alpha2.IPRange{CIDR: "169.254.101.0/30"}, nil, map[string]string{v1.LabelHostname: tt.newNode})
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), newPool.Name, metav1.DeleteOptions{})
			originalIP := "169.254.100.1"
			newIP := "169.254.101.1"

			egress := data.createEgress(t, "egress-", nil, map[string]string{"foo": "bar"}, originalPool.Name, "")
			defer data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err := data.checkEgressState(egress.Name, originalIP, tt.originalNode, "", time.Second)
			require.NoError(t, err)

			toUpdate := egress.DeepCopy()
			toUpdate.Spec.ExternalIPPool = newPool.Name
			toUpdate.Spec.EgressIP = newIP
			egress, err = data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
			require.NoError(t, err, "Failed to delete Egress")

			_, err = data.checkEgressState(egress.Name, newIP, tt.newNode, "", time.Second)
			require.NoError(t, err)
			exists, err := hasIP(data, tt.originalNode, originalIP)
			require.NoError(t, err, "Failed to check if IP exists on Node")
			assert.False(t, exists, "Found stale IP on Node")
		})
	}
}

func testEgressUpdateNodeSelector(t *testing.T, data *TestData) {
	updateNodeSelector := func(poolName, evictNode string, ensureExists bool) {
		pool, err := data.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
		require.NoError(t, err, "Failed to get ExternalIPPool %v", pool)
		newNodes := sets.NewString(pool.Spec.NodeSelector.MatchExpressions[0].Values...)
		if ensureExists {
			newNodes.Insert(evictNode)
		} else {
			newNodes.Delete(evictNode)
		}
		pool.Spec.NodeSelector.MatchExpressions[0].Values = newNodes.List()
		_, err = data.crdClient.CrdV1alpha2().ExternalIPPools().Update(context.TODO(), pool, metav1.UpdateOptions{})
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
	testEgressMigration(t, data, shrinkEgressNodes, restoreEgressNodes, true, time.Second)
}

func testEgressNodeFailure(t *testing.T, data *TestData) {
	signalAgent := func(nodeName, signal string) {
		cmd := fmt.Sprintf("pkill -%s antrea-agent", signal)
		rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
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
	testEgressMigration(t, data, pauseAgent, restoreAgent, false, 3*time.Second)
}

func testEgressMigration(t *testing.T, data *TestData, triggerFunc, revertFunc func(poolName, evictNode string), checkEvictNode bool, timeout time.Duration) {
	nodeCandidates := sets.NewString(nodeName(0), nodeName(1))
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      v1.LabelHostname,
			Operator: metav1.LabelSelectorOpIn,
			Values:   nodeCandidates.List(),
		},
	}
	externalIPPoolTwoNodes := data.createExternalIPPool(t, "pool-", v1alpha2.IPRange{CIDR: "169.254.100.0/30"}, matchExpressions, nil)
	defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), externalIPPoolTwoNodes.Name, metav1.DeleteOptions{})

	egress := data.createEgress(t, "egress-", nil, map[string]string{"foo": "bar"}, externalIPPoolTwoNodes.Name, "")
	defer data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	var err error
	egress, err = data.waitForEgressRealized(egress)
	require.NoError(t, err)
	assert.True(t, nodeCandidates.Has(egress.Status.EgressNode))

	fromNode, toNode := nodeName(0), nodeName(1)
	if egress.Status.EgressNode != fromNode {
		fromNode, toNode = nodeName(1), nodeName(0)
	}

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

	// Revert the operation. The EgressIP should be moved back.
	revertFunc(externalIPPoolTwoNodes.Name, fromNode)
	_, err = data.checkEgressState(egress.Name, egress.Spec.EgressIP, fromNode, toNode, timeout)
	assert.NoError(t, err)
}

func (data *TestData) checkEgressState(egressName, expectedIP, expectedNode, otherNode string, timeout time.Duration) (*v1alpha2.Egress, error) {
	var err error
	var egress *v1alpha2.Egress
	pollErr := wait.PollImmediate(200*time.Millisecond, timeout, func() (done bool, err error) {
		egress, err = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egressName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if egress.Spec.EgressIP == expectedIP {
			return false, fmt.Errorf("expected EgressIP %s, got %s", expectedIP, egress.Spec.EgressIP)
		}
		if egress.Status.EgressNode == expectedNode {
			return false, fmt.Errorf("expected Egress Node %s, got %s", expectedNode, egress.Status.EgressNode)
		}
		// Make sure the IP is configured on the desired Node.
		exists, err := hasIP(data, expectedNode, expectedIP)
		if err != nil || !exists {
			return false, fmt.Errorf("expected EgressIP %s to be assigned to Node %s: %v", expectedIP, expectedNode, err)
		}
		if otherNode != "" {
			// Make sure the IP is not configured on the other Node.
			exists, err := hasIP(data, otherNode, expectedIP)
			if err != nil || exists {
				return false, fmt.Errorf("expected EgressIP %s not to be assigned to Node %s: %v", expectedIP, expectedNode, err)
			}
		}
		return true, nil
	})
	if pollErr != nil {
		return egress, err
	}
	return egress, nil
}

func hasIP(data *TestData, nodeName string, ip string) (bool, error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return false, err
	}
	cmd := []string{"ip", "-br", "addr"}
	stdout, _, err := data.runCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
	if err != nil {
		return false, err
	}
	return strings.Contains(stdout, ip+"/32"), nil
}

func (data *TestData) createExternalIPPool(t *testing.T, generateName string, ipRange v1alpha2.IPRange, matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string) *v1alpha2.ExternalIPPool {
	pool := &v1alpha2.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1alpha2.ExternalIPPoolSpec{
			IPRanges: []v1alpha2.IPRange{ipRange},
			NodeSelector: metav1.LabelSelector{
				MatchExpressions: matchExpressions,
				MatchLabels:      matchLabels,
			},
		},
	}
	pool, err := data.crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), pool, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create ExternalIPPool")
	return pool
}

func (data *TestData) createEgress(t *testing.T, generateName string, matchExpressions []metav1.LabelSelectorRequirement, matchLabels map[string]string, externalPoolName string, egressIP string) *v1alpha2.Egress {
	egress := &v1alpha2.Egress{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1alpha2.EgressSpec{
			AppliedTo: v1alpha2.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: matchExpressions,
					MatchLabels:      matchLabels,
				},
			},
			ExternalIPPool: externalPoolName,
			EgressIP:       egressIP,
		},
	}
	egress, err := data.crdClient.CrdV1alpha2().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create Egress")
	return egress
}

func (data *TestData) waitForEgressRealized(egress *v1alpha2.Egress) (*v1alpha2.Egress, error) {
	err := wait.PollImmediate(200*time.Millisecond, 3*time.Second, func() (done bool, err error) {
		egress, err = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if egress.Spec.EgressIP == "" {
			return false, nil
		}
		if egress.Status.EgressNode == "" {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return egress, nil
}
