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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/features"
)

const waitEgressRealizedTimeout = 3 * time.Second

func skipIfEgressDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.Egress, true, true)
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
	// Egress works for encap mode only.
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

	t.Run("testEgressClientIP", func(t *testing.T) { testEgressClientIP(t, data) })
	t.Run("testEgressCRUD", func(t *testing.T) { testEgressCRUD(t, data) })
	t.Run("testEgressUpdateEgressIP", func(t *testing.T) { testEgressUpdateEgressIP(t, data) })
	t.Run("testEgressUpdateNodeSelector", func(t *testing.T) { testEgressUpdateNodeSelector(t, data) })
	t.Run("testEgressNodeFailure", func(t *testing.T) { testEgressNodeFailure(t, data) })
	t.Run("testCreateExternalIPPool", func(t *testing.T) { testCreateExternalIPPool(t, data) })
}

func testCreateExternalIPPool(t *testing.T, data *TestData) {
	eip := v1alpha2.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeExternalIPPool"},
		Spec:       v1alpha2.ExternalIPPoolSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro-"}}},
	}

	_, err := data.crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), &eip, metav1.CreateOptions{})
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

			// Create a http server in another netns to fake an external server connected to the egress Node.
			cmd := fmt.Sprintf(`ip netns add %[1]s && \
ip link add dev %[1]s-a type veth peer name %[1]s-b && \
ip link set dev %[1]s-a netns %[1]s && \
ip addr add %[3]s/%[5]d dev %[1]s-b && \
ip addr add %[4]s/%[5]d dev %[1]s-b && \
ip link set dev %[1]s-b up && \
ip netns exec %[1]s ip addr add %[2]s/%[5]d dev %[1]s-a && \
ip netns exec %[1]s ip link set dev %[1]s-a up && \
ip netns exec %[1]s ip route replace default via %[3]s && \
ip netns exec %[1]s /agnhost netexec
`, tt.fakeServer, tt.serverIP, tt.localIP0, tt.localIP1, tt.ipMaskLen)
			if err := NewPodBuilder(tt.fakeServer, data.testNamespace, agnhostImage).OnNode(egressNode).WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data); err != nil {
				t.Fatalf("Failed to create server Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, tt.fakeServer)
			if err := data.podWaitForRunning(defaultTimeout, tt.fakeServer, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", tt.fakeServer)
			}

			localPod := fmt.Sprintf("localpod%s", tt.name)
			remotePod := fmt.Sprintf("remotepod%s", tt.name)
			if err := data.createBusyboxPodOnNode(localPod, data.testNamespace, egressNode, false); err != nil {
				t.Fatalf("Failed to create local Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, localPod)
			if err := data.podWaitForRunning(defaultTimeout, localPod, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", localPod)
			}
			if err := data.createBusyboxPodOnNode(remotePod, data.testNamespace, workerNodeName(1), false); err != nil {
				t.Fatalf("Failed to create remote Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, remotePod)
			if err := data.podWaitForRunning(defaultTimeout, remotePod, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", remotePod)
			}

			serverIPStr := tt.serverIP
			if utilnet.IsIPv6String(tt.localIP0) {
				serverIPStr = fmt.Sprintf("[%s]", tt.serverIP)
			}

			// getClientIP gets the translated client IP by accessing the API that replies the request's client IP.
			getClientIP := func(pod string) (string, string, error) {
				url := fmt.Sprintf("%s:8080/clientip", serverIPStr)
				return data.runWgetCommandOnBusyboxWithRetry(pod, data.testNamespace, url, 5)
			}

			// assertClientIP asserts the Pod is translated to the provided client IP.
			assertClientIP := func(pod string, clientIPs ...string) {
				var exeErr error
				var stdout, stderr string
				if err := wait.Poll(100*time.Millisecond, 5*time.Second, func() (done bool, err error) {
					stdout, stderr, exeErr = getClientIP(pod)
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
				}); err != nil {
					t.Fatalf("Failed to get expected client IPs %s for Pod %s, stdout: %s, stderr: %s, err: %v", clientIPs, pod, stdout, stderr, exeErr)
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
			assertClientIP(localPod, tt.localIP0, tt.localIP1)
			assertConnError(remotePod)

			t.Logf("Creating an Egress applying to all e2e Pods")
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

			var err error
			err = wait.Poll(time.Millisecond*100, time.Second, func() (bool, error) {
				egress, err = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
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
			cmd = fmt.Sprintf("wget -T 3 -O - %s:8080/clientip | grep %s:", serverIPStr, clientIPStr)
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
			egress.Spec.AppliedTo = v1alpha2.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"antrea-e2e": remotePod},
				},
			}
			egress, err = data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Failed to update Egress %v: %v", egress, err)
			}
			assertClientIP(localPod, tt.localIP0, tt.localIP1)
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

			t.Logf("Updating the Egress's EgressIP to %s", tt.localIP1)
			egress.Spec.EgressIP = tt.localIP1
			egress, err = data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
			if err != nil {
				t.Fatalf("Failed to update Egress %v: %v", egress, err)
			}
			assertClientIP(localPod, tt.localIP1)
			assertConnError(remotePod)

			t.Log("Deleting the Egress")
			err = data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			if err != nil {
				t.Fatalf("Failed to delete Egress %v: %v", egress, err)
			}
			assertClientIP(localPod, tt.localIP0, tt.localIP1)
			assertConnError(remotePod)
		})
	}
}

func testEgressCRUD(t *testing.T, data *TestData) {
	tests := []struct {
		name             string
		ipRange          v1alpha2.IPRange
		nodeSelector     metav1.LabelSelector
		expectedEgressIP string
		expectedNodes    sets.Set[string]
		expectedTotal    int
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
			expectedNodes:    sets.New[string](nodeName(0)),
			expectedTotal:    2,
		},
		{
			name:    "single matching Node with IPv6 range",
			ipRange: v1alpha2.IPRange{CIDR: "2021:1::aaa0/124"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedEgressIP: "2021:1::aaa1",
			expectedNodes:    sets.New[string](nodeName(0)),
			expectedTotal:    15,
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
			expectedNodes:    sets.New[string](nodeName(0), nodeName(1)),
			expectedTotal:    2,
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
			expectedNodes:    sets.New[string](),
			expectedTotal:    2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.expectedEgressIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}
			pool := data.createExternalIPPool(t, "crud-pool-", tt.ipRange, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "crud-egress-", nil, map[string]string{"foo": "bar"}, pool.Name, "")
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
			require.NoError(t, err, "Expected egressIP=%s nodeName in %s, got egressIP=%s nodeName=%s", tt.expectedEgressIP, sets.List(tt.expectedNodes), egress.Spec.EgressIP, egress.Status.EgressNode)
			if egress.Status.EgressNode != "" {
				exists, err := hasIP(data, egress.Status.EgressNode, egress.Spec.EgressIP)
				require.NoError(t, err, "Failed to check if IP exists on Node")
				assert.True(t, exists, "Didn't find desired IP on Node")
			}

			checkEIPStatus := func(expectedUsed int) {
				var gotUsed, gotTotal int
				err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (done bool, err error) {
					pool, err := data.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), pool.Name, metav1.GetOptions{})
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

			err = data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			require.NoError(t, err, "Failed to delete Egress")
			if egress.Status.EgressNode != "" {
				err := wait.PollImmediate(200*time.Millisecond, timeout, func() (done bool, err error) {
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
		originalIPRange  v1alpha2.IPRange
		originalEgressIP string
		newIPRange       v1alpha2.IPRange
		newEgressIP      string
	}{
		{
			name:             "same Node",
			originalNode:     nodeName(0),
			newNode:          nodeName(0),
			originalIPRange:  v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			originalEgressIP: "169.254.100.1",
			newIPRange:       v1alpha2.IPRange{CIDR: "169.254.101.0/30"},
			newEgressIP:      "169.254.101.1",
		},
		{
			name:             "different Nodes",
			originalNode:     nodeName(0),
			newNode:          nodeName(1),
			originalIPRange:  v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			originalEgressIP: "169.254.100.1",
			newIPRange:       v1alpha2.IPRange{CIDR: "169.254.101.0/30"},
			newEgressIP:      "169.254.101.1",
		},
		{
			name:             "different Nodes in IPv6 cluster",
			originalNode:     nodeName(0),
			newNode:          nodeName(1),
			originalIPRange:  v1alpha2.IPRange{CIDR: "2021:2::aaa0/124"},
			originalEgressIP: "2021:2::aaa1",
			newIPRange:       v1alpha2.IPRange{CIDR: "2021:2::bbb0/124"},
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
			originalPool := data.createExternalIPPool(t, "originalpool-", tt.originalIPRange, nil, map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), originalPool.Name, metav1.DeleteOptions{})
			newPool := data.createExternalIPPool(t, "newpool-", tt.newIPRange, nil, map[string]string{v1.LabelHostname: tt.newNode})
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), newPool.Name, metav1.DeleteOptions{})

			egress := data.createEgress(t, "egress-", nil, map[string]string{"foo": "bar"}, originalPool.Name, "")
			defer data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
			egress, err := data.checkEgressState(egress.Name, tt.originalEgressIP, tt.originalNode, "", time.Second)
			require.NoError(t, err)

			// The Egress maybe has been modified.
			toUpdate := egress.DeepCopy()
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				toUpdate.Spec.ExternalIPPool = newPool.Name
				toUpdate.Spec.EgressIP = tt.newEgressIP
				_, err = data.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
				if err != nil && errors.IsConflict(err) {
					toUpdate, _ = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
				}
				return err
			})
			require.NoError(t, err, "Failed to update Egress")

			_, err = data.checkEgressState(egress.Name, tt.newEgressIP, tt.newNode, "", time.Second)
			require.NoError(t, err)
			err = wait.PollImmediate(200*time.Millisecond, timeout, func() (done bool, err error) {
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
	tests := []struct {
		name      string
		ipRange   v1alpha2.IPRange
		ipVersion int
	}{
		{
			name:      "IPv4 cluster",
			ipRange:   v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			ipVersion: 4,
		},
		{
			name:      "IPv6 cluster",
			ipRange:   v1alpha2.IPRange{CIDR: "2021:3::aaa1/124"},
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
				pool, err := data.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
				require.NoError(t, err, "Failed to get ExternalIPPool %v", pool)
				newNodes := sets.New[string](pool.Spec.NodeSelector.MatchExpressions[0].Values...)
				if ensureExists {
					newNodes.Insert(evictNode)
				} else {
					newNodes.Delete(evictNode)
				}
				pool.Spec.NodeSelector.MatchExpressions[0].Values = sets.List(newNodes)
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
			testEgressMigration(t, data, shrinkEgressNodes, restoreEgressNodes, true, time.Second, &tt.ipRange)
		})
	}
}

func testEgressNodeFailure(t *testing.T, data *TestData) {
	tests := []struct {
		name      string
		ipRange   v1alpha2.IPRange
		ipVersion int
	}{
		{
			name:      "IPv4 cluster",
			ipRange:   v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			ipVersion: 4,
		},
		{
			name:      "IPv6 cluster",
			ipRange:   v1alpha2.IPRange{CIDR: "2021:4::aaa1/124"},
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

func testEgressMigration(t *testing.T, data *TestData, triggerFunc, revertFunc func(poolName, evictNode string), checkEvictNode bool, timeout time.Duration, ipRange *v1alpha2.IPRange) {
	nodeCandidates := sets.New[string](nodeName(0), nodeName(1))
	matchExpressions := []metav1.LabelSelectorRequirement{
		{
			Key:      v1.LabelHostname,
			Operator: metav1.LabelSelectorOpIn,
			Values:   sets.List(nodeCandidates),
		},
	}
	externalIPPoolTwoNodes := data.createExternalIPPool(t, "pool-with-two-nodes-", *ipRange, matchExpressions, nil)
	defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), externalIPPoolTwoNodes.Name, metav1.DeleteOptions{})

	egress := data.createEgress(t, "migration-egress-", nil, map[string]string{"foo": "bar"}, externalIPPoolTwoNodes.Name, "")
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
	var egress *v1alpha2.Egress
	var expectedNodeHasIP, otherNodeHasIP bool
	pollErr := wait.PollImmediate(200*time.Millisecond, timeout, func() (bool, error) {
		var err error
		egress, err = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egressName, metav1.GetOptions{})
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
	err := wait.PollImmediate(200*time.Millisecond, waitEgressRealizedTimeout, func() (done bool, err error) {
		egress, err = data.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
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
