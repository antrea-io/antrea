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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	utilnet "k8s.io/utils/net"

	antreaagenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
)

func TestServiceExternalIP(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	cc := func(config *controllerconfig.ControllerConfig) {
		config.FeatureGates["ServiceExternalIP"] = true
	}
	ac := func(config *agentconfig.AgentConfig) {
		config.FeatureGates["ServiceExternalIP"] = true
	}

	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to enable ServiceExternalIP feature: %v", err)
	}

	t.Run("testServiceWithExternalIPCRUD", func(t *testing.T) { testServiceWithExternalIPCRUD(t, data) })
	t.Run("testServiceUpdateExternalIP", func(t *testing.T) { testServiceUpdateExternalIP(t, data) })
	t.Run("testServiceExternalTrafficPolicyLocal", func(t *testing.T) { testServiceExternalTrafficPolicyLocal(t, data) })
	t.Run("testServiceNodeFailure", func(t *testing.T) { testServiceNodeFailure(t, data) })
	t.Run("testExternalIPAccess", func(t *testing.T) { testExternalIPAccess(t, data) })
}

func testServiceExternalTrafficPolicyLocal(t *testing.T, data *TestData) {
	tests := []struct {
		name                    string
		ipRange                 v1alpha2.IPRange
		nodeSelector            metav1.LabelSelector
		originalEndpointSubsets []v1.EndpointSubset
		expectedExternalIP      string
		expectedNodeOrigin      string
		updatedEndpointSubsets  []v1.EndpointSubset
		expectedNodeUpdated     string
	}{
		{
			name:    "endpoint created",
			ipRange: v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedExternalIP:      "169.254.100.1",
			originalEndpointSubsets: nil,
			expectedNodeOrigin:      "",
			updatedEndpointSubsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "192.168.200.1",
							NodeName: stringPtr(nodeName(0)),
						},
					},
				},
			},
			expectedNodeUpdated: nodeName(0),
		},
		{
			name:    "endpoint created IPv6",
			ipRange: v1alpha2.IPRange{CIDR: "2021:1::aaa0/124"},
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedExternalIP:      "2021:1::aaa1",
			originalEndpointSubsets: nil,
			expectedNodeOrigin:      "",
			updatedEndpointSubsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "2021:8::aaa1",
							NodeName: stringPtr(nodeName(0)),
						},
					},
				},
			},
			expectedNodeUpdated: nodeName(0),
		},
		{
			name:    "endpoint changed",
			ipRange: v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedExternalIP: "169.254.100.1",
			originalEndpointSubsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "192.168.100.1",
							NodeName: stringPtr(nodeName(0)),
						},
					},
				},
			},
			expectedNodeOrigin: nodeName(0),
			updatedEndpointSubsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "192.168.100.1",
							NodeName: stringPtr(nodeName(1)),
						},
					},
				},
			},
			expectedNodeUpdated: nodeName(1),
		},
		{
			name:    "endpoint changed IPv6",
			ipRange: v1alpha2.IPRange{CIDR: "2021:1::aaa0/124"},
			nodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      v1.LabelHostname,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{nodeName(0), nodeName(1)},
					},
				},
			},
			expectedExternalIP: "2021:1::aaa1",
			originalEndpointSubsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "2021:8::aaa1",
							NodeName: stringPtr(nodeName(0)),
						},
					},
				},
			},
			expectedNodeOrigin: nodeName(0),
			updatedEndpointSubsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{
							IP:       "2021:8::aaa1",
							NodeName: stringPtr(nodeName(1)),
						},
					},
				},
			},
			expectedNodeUpdated: nodeName(1),
		},
	}
	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.expectedExternalIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}
			var err error
			var service *v1.Service
			var eps *v1.Endpoints
			ipPool := data.createExternalIPPool(t, "test-service-pool-", tt.ipRange, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), ipPool.Name, metav1.DeleteOptions{})

			annotation := map[string]string{
				antreaagenttypes.ServiceExternalIPPoolAnnotationKey: ipPool.Name,
			}
			service, err = data.CreateServiceWithAnnotations(fmt.Sprintf("test-svc-local-%d", idx),
				testNamespace, 80, 80, corev1.ProtocolTCP, nil, false, true, v1.ServiceTypeLoadBalancer, nil, annotation)
			require.NoError(t, err)
			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})

			eps = &v1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      service.Name,
					Namespace: service.Namespace,
					Labels: map[string]string{
						"antrea-e2e": service.Name,
						"app":        service.Name,
					},
				},
				Subsets: tt.originalEndpointSubsets,
			}
			eps, err = data.clientset.CoreV1().Endpoints(eps.Namespace).Create(context.TODO(), eps, metav1.CreateOptions{})
			require.NoError(t, err)
			defer data.clientset.CoreV1().Endpoints(eps.Namespace).Delete(context.TODO(), eps.Name, metav1.DeleteOptions{})

			service, err = data.waitForServiceConfigured(service, tt.expectedExternalIP, tt.expectedNodeOrigin != "", tt.expectedNodeOrigin)
			require.NoError(t, err)
			_, node := getServiceExternalIPAndHost(service)
			assert.Equal(t, tt.expectedNodeOrigin, node)

			epsToUpdate := eps.DeepCopy()
			epsToUpdate.Subsets = tt.updatedEndpointSubsets
			_, err = data.clientset.CoreV1().Endpoints(eps.Namespace).Update(context.TODO(), epsToUpdate, metav1.UpdateOptions{})
			require.NoError(t, err)
			service, err = data.waitForServiceConfigured(service, tt.expectedExternalIP, tt.expectedNodeUpdated != "", tt.expectedNodeUpdated)
			require.NoError(t, err)
			_, node = getServiceExternalIPAndHost(service)
			assert.Equal(t, tt.expectedNodeUpdated, node)
			assert.NoError(t, err)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}

func testServiceWithExternalIPCRUD(t *testing.T, data *TestData) {
	tests := []struct {
		name               string
		ipRange            v1alpha2.IPRange
		nodeSelector       metav1.LabelSelector
		expectedExternalIP string
		expectedNodes      sets.String
		expectedTotal      int
	}{
		{
			name:    "single matching Node",
			ipRange: v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedExternalIP: "169.254.100.1",
			expectedNodes:      sets.NewString(nodeName(0)),
			expectedTotal:      2,
		},
		{
			name:    "single matching Node with IPv6 range",
			ipRange: v1alpha2.IPRange{CIDR: "2021:1::aaa0/124"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					v1.LabelHostname: nodeName(0),
				},
			},
			expectedExternalIP: "2021:1::aaa1",
			expectedNodes:      sets.NewString(nodeName(0)),
			expectedTotal:      15,
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
			expectedExternalIP: "169.254.101.10",
			expectedNodes:      sets.NewString(nodeName(0), nodeName(1)),
			expectedTotal:      2,
		},
		{
			name:    "no matching Node",
			ipRange: v1alpha2.IPRange{CIDR: "169.254.102.0/30"},
			nodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo": "bar",
				},
			},
			expectedExternalIP: "169.254.102.1",
			expectedNodes:      sets.NewString(),
			expectedTotal:      2,
		},
	}
	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.expectedExternalIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}
			var err error
			var service *v1.Service
			ipPool := data.createExternalIPPool(t, "crud-pool-", tt.ipRange, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), ipPool.Name, metav1.DeleteOptions{})

			annotation := map[string]string{
				antreaagenttypes.ServiceExternalIPPoolAnnotationKey: ipPool.Name,
			}
			service, err = data.CreateServiceWithAnnotations(fmt.Sprintf("test-svc-eip-%d", idx),
				testNamespace, 80, 80, corev1.ProtocolTCP, nil, false, false, v1.ServiceTypeLoadBalancer, nil, annotation)
			require.NoError(t, err)

			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})
			waitForNodeConfigured := len(tt.expectedNodes) != 0
			service, err = data.waitForServiceConfigured(service, tt.expectedExternalIP, waitForNodeConfigured, "")
			require.NoError(t, err)

			if len(tt.expectedNodes) > 0 {
				_, assignedNode := getServiceExternalIPAndHost(service)
				assert.True(t, tt.expectedNodes.Has(assignedNode), "expected assigned Node in %s, got %s", tt.expectedNodes, assignedNode)
			}

			checkEIPStatus := func(expectedUsed int) {
				var gotUsed, gotTotal int
				err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (done bool, err error) {
					pool, err := data.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), ipPool.Name, metav1.GetOptions{})
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
			err = data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})
			require.NoError(t, err, "Failed to delete Service")
			checkEIPStatus(0)
		})
	}
}

func testServiceUpdateExternalIP(t *testing.T, data *TestData) {
	tests := []struct {
		name               string
		originalNode       string
		newNode            string
		originalIPRange    v1alpha2.IPRange
		originalExternalIP string
		newIPRange         v1alpha2.IPRange
		newExternalIP      string
	}{
		{
			name:               "same Node",
			originalNode:       nodeName(0),
			newNode:            nodeName(0),
			originalIPRange:    v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			originalExternalIP: "169.254.100.1",
			newIPRange:         v1alpha2.IPRange{CIDR: "169.254.101.0/30"},
			newExternalIP:      "169.254.101.1",
		},
		{
			name:               "different Nodes",
			originalNode:       nodeName(0),
			newNode:            nodeName(1),
			originalIPRange:    v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			originalExternalIP: "169.254.100.1",
			newIPRange:         v1alpha2.IPRange{CIDR: "169.254.101.0/30"},
			newExternalIP:      "169.254.101.1",
		},
		{
			name:               "different Nodes in IPv6 cluster",
			originalNode:       nodeName(0),
			newNode:            nodeName(1),
			originalIPRange:    v1alpha2.IPRange{CIDR: "2021:2::aaa0/124"},
			originalExternalIP: "2021:2::aaa1",
			newIPRange:         v1alpha2.IPRange{CIDR: "2021:2::bbb0/124"},
			newExternalIP:      "2021:2::bbb1",
		},
	}
	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.originalExternalIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}

			originalPool := data.createExternalIPPool(t, "originalpool-", tt.originalIPRange, nil, map[string]string{v1.LabelHostname: tt.originalNode})
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), originalPool.Name, metav1.DeleteOptions{})
			newPool := data.createExternalIPPool(t, "newpool-", tt.newIPRange, nil, map[string]string{v1.LabelHostname: tt.newNode})
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), newPool.Name, metav1.DeleteOptions{})

			annotation := map[string]string{
				antreaagenttypes.ServiceExternalIPPoolAnnotationKey: originalPool.Name,
			}
			service, err := data.CreateServiceWithAnnotations(fmt.Sprintf("test-update-eip-%d", idx),
				testNamespace, 80, 80, corev1.ProtocolTCP, nil, false, false, v1.ServiceTypeLoadBalancer, nil, annotation)
			require.NoError(t, err)
			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})

			service, err = data.waitForServiceConfigured(service, tt.originalExternalIP, true, tt.originalNode)
			require.NoError(t, err)

			toUpdate := service.DeepCopy()
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				toUpdate.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey] = newPool.Name
				_, err = data.clientset.CoreV1().Services(toUpdate.Namespace).Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
				if err != nil && errors.IsConflict(err) {
					toUpdate, _ = data.clientset.CoreV1().Services(toUpdate.Namespace).Get(context.TODO(), toUpdate.Name, metav1.GetOptions{})
				}
				return err
			})
			require.NoError(t, err, "Failed to update Service")

			_, err = data.waitForServiceConfigured(service, tt.newExternalIP, true, tt.newNode)
			assert.NoError(t, err)
		})
	}
}

func testServiceNodeFailure(t *testing.T, data *TestData) {
	if testOptions.providerName != "kind" {
		t.Skipf("Skipping test because root permission is required")
	}
	tests := []struct {
		name       string
		ipRange    v1alpha2.IPRange
		expectedIP string
	}{
		{
			name:       "IPv4 cluster",
			ipRange:    v1alpha2.IPRange{CIDR: "169.254.100.0/30"},
			expectedIP: "169.254.100.1",
		},
		{
			name:       "IPv6 cluster",
			ipRange:    v1alpha2.IPRange{CIDR: "2021:4::aaa0/124"},
			expectedIP: "2021:4::aaa1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if utilnet.IsIPv6String(tt.expectedIP) {
				skipIfNotIPv6Cluster(t)
			} else {
				skipIfNotIPv4Cluster(t)
			}
			signalAgent := func(nodeName, signal string) {
				cmd := fmt.Sprintf("pkill -%s antrea-agent", signal)
				rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
				if rc != 0 || err != nil {
					t.Errorf("Error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
						cmd, nodeName, rc, stdout, stderr, err)
				}
			}
			pauseAgent := func(evictNode string) {
				// Send "STOP" signal to antrea-agent.
				signalAgent(evictNode, "STOP")
			}
			restoreAgent := func(evictNode string) {
				// Send "CONT" signal to antrea-agent.
				signalAgent(evictNode, "CONT")
			}

			nodeCandidates := sets.NewString(nodeName(0), nodeName(1))
			matchExpressions := []metav1.LabelSelectorRequirement{
				{
					Key:      v1.LabelHostname,
					Operator: metav1.LabelSelectorOpIn,
					Values:   nodeCandidates.List(),
				},
			}
			externalIPPoolTwoNodes := data.createExternalIPPool(t, "pool-with-two-nodes-", tt.ipRange, matchExpressions, nil)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), externalIPPoolTwoNodes.Name, metav1.DeleteOptions{})
			annotation := map[string]string{
				antreaagenttypes.ServiceExternalIPPoolAnnotationKey: externalIPPoolTwoNodes.Name,
			}
			service, err := data.CreateServiceWithAnnotations("test-service-node-failure", testNamespace, 80, 80,
				corev1.ProtocolTCP, nil, false, false, v1.ServiceTypeLoadBalancer, nil, annotation)
			require.NoError(t, err)
			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})

			service, err = data.waitForServiceConfigured(service, tt.expectedIP, true, "")
			assert.NoError(t, err)
			_, originalNode := getServiceExternalIPAndHost(service)
			pauseAgent(originalNode)
			defer restoreAgent(originalNode)

			var expectedMigratedNode string
			if originalNode == nodeName(0) {
				expectedMigratedNode = nodeName(1)
			} else {
				expectedMigratedNode = nodeName(0)
			}
			service, err = data.waitForServiceConfigured(service, tt.expectedIP, true, expectedMigratedNode)
			assert.NoError(t, err)
			restoreAgent(originalNode)
			_, err = data.waitForServiceConfigured(service, tt.expectedIP, true, originalNode)
			assert.NoError(t, err)
		})
	}
}

func testExternalIPAccess(t *testing.T, data *TestData) {
	tests := []struct {
		name            string
		externalIPCIDR  string
		clientName      string
		clientIP        string
		localIP         string
		clientIPMaskLen int
	}{
		{
			name:            "IPv4 cluster",
			externalIPCIDR:  "169.254.170.128/25",
			clientName:      "eth-ipv4",
			clientIP:        "169.254.170.1",
			localIP:         "169.254.170.2",
			clientIPMaskLen: 25,
		},
		{
			name:            "IPv6 cluster",
			externalIPCIDR:  "2021:4::aab0/124",
			clientName:      "eth-ipv6",
			clientIP:        "2021:4::aaa1",
			localIP:         "2021:4::aaa2",
			clientIPMaskLen: 124,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipFamily := corev1.IPv4Protocol
			if utilnet.IsIPv6CIDRString(tt.externalIPCIDR) {
				skipIfNotIPv6Cluster(t)
				ipFamily = corev1.IPv6Protocol
			} else {
				skipIfNotIPv4Cluster(t)
			}
			nodes := []string{nodeName(0), nodeName(1)}
			ipRange := v1alpha2.IPRange{CIDR: tt.externalIPCIDR}
			ipPool := data.createExternalIPPool(t, "ippool-", ipRange, nil, nil)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), ipPool.Name, metav1.DeleteOptions{})
			agnhosts := []string{"agnhost-0", "agnhost-1"}
			// Create agnhost Pods on each Node.
			for idx, node := range nodes {
				createAgnhostPod(t, data, agnhosts[idx], node, false)
				defer data.deletePodAndWait(defaultTimeout, agnhosts[idx], testNamespace)
			}
			var port int32 = 8080
			externalIPTestCases := []struct {
				name                       string
				externalTrafficPolicyLocal bool
				serviceName                string
			}{
				{
					name:                       "ExternalTrafficPolicy setting to Cluster",
					externalTrafficPolicyLocal: false,
					serviceName:                "agnhost-cluster",
				},
				{
					name:                       "ExternalTrafficPolicy setting to Local",
					externalTrafficPolicyLocal: true,
					serviceName:                "agnhost-local",
				},
			}
			waitExternalIPConfigured := func(service *v1.Service) (string, string, error) {
				var ip string
				var host string
				err := wait.PollImmediate(200*time.Millisecond, 5*time.Second, func() (done bool, err error) {
					service, err = data.clientset.CoreV1().Services(service.Namespace).Get(context.TODO(), service.Name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					if len(service.Status.LoadBalancer.Ingress) == 0 || service.Status.LoadBalancer.Ingress[0].IP == "" || service.Status.LoadBalancer.Ingress[0].Hostname == "" {
						return false, nil
					}
					ip = service.Status.LoadBalancer.Ingress[0].IP
					host = service.Status.LoadBalancer.Ingress[0].Hostname
					return true, nil
				})
				return ip, host, err
			}
			for _, et := range externalIPTestCases {
				t.Run(et.name, func(t *testing.T) {
					annotations := map[string]string{
						antreaagenttypes.ServiceExternalIPPoolAnnotationKey: ipPool.Name,
					}
					service, err := data.CreateServiceWithAnnotations(et.serviceName, testNamespace, port, port, corev1.ProtocolTCP, map[string]string{"app": "agnhost"}, false, et.externalTrafficPolicyLocal, corev1.ServiceTypeLoadBalancer, &ipFamily, annotations)
					require.NoError(t, err)
					defer data.deleteService(service.Namespace, service.Name)

					externalIP, host, err := waitExternalIPConfigured(service)
					require.NoError(t, err)

					// Create a pod in a different netns with the same subnet of the external IP to mock as another Node in the same subnet.
					cmd := fmt.Sprintf(`ip netns add %[1]s && \
ip link add dev %[1]s-a type veth peer name %[1]s-b && \
ip link set dev %[1]s-a netns %[1]s && \
ip addr add %[3]s/%[4]d dev %[1]s-b && \
ip link set dev %[1]s-b up && \
ip netns exec %[1]s ip addr add %[2]s/%[4]d dev %[1]s-a && \
ip netns exec %[1]s ip link set dev %[1]s-a up && \
ip netns exec %[1]s ip route replace default via %[3]s && \
ip netns exec %[1]s \
sleep 3600`, tt.clientName, tt.clientIP, tt.localIP, tt.clientIPMaskLen)

					baseUrl := net.JoinHostPort(externalIP, strconv.FormatInt(int64(port), 10))

					require.NoError(t, data.createPodOnNode(tt.clientName, testNamespace, host, agnhostImage, []string{"sh", "-c", cmd}, nil, nil, nil, true, func(pod *v1.Pod) {
						privileged := true
						pod.Spec.Containers[0].SecurityContext = &v1.SecurityContext{Privileged: &privileged}
						delete(pod.Labels, "app")
						// curl will exit immediately if the destination IP is unreachable and will NOT retry despite having retry flags set.
						// Use an exec readiness probe to ensure the route is configured to the interface.
						// Refer to https://github.com/curl/curl/issues/1603.
						probeCmd := strings.Split(fmt.Sprintf("ip netns exec %s curl -s %s", tt.clientName, baseUrl), " ")
						pod.Spec.Containers[0].ReadinessProbe = &v1.Probe{
							Handler: v1.Handler{
								Exec: &v1.ExecAction{
									Command: probeCmd,
								},
							},
							InitialDelaySeconds: 1,
							PeriodSeconds:       1,
						}
					}))

					_, err = data.PodWaitFor(defaultTimeout, tt.clientName, testNamespace, func(p *v1.Pod) (bool, error) {
						for _, condition := range p.Status.Conditions {
							if condition.Type == corev1.PodReady {
								return condition.Status == corev1.ConditionTrue, nil
							}
						}
						return false, nil
					})
					require.NoError(t, err)
					defer data.deletePodAndWait(defaultTimeout, tt.clientName, testNamespace)

					hostNameUrl := fmt.Sprintf("%s/%s", baseUrl, "hostname")
					probeCmd := fmt.Sprintf("ip netns exec %s curl --connect-timeout 1 --retry 5 --retry-connrefused %s", tt.clientName, hostNameUrl)
					hostname, stderr, err := data.RunCommandFromPod(testNamespace, tt.clientName, "", []string{"sh", "-c", probeCmd})
					assert.NoError(t, err, "External IP should be able to be connected from remote: %s", stderr)

					if et.externalTrafficPolicyLocal {
						for idx, node := range nodes {
							if node == host {
								assert.Equal(t, agnhosts[idx], hostname, "Hostname should match when ExternalTrafficPolicy setting to Local")
							}
						}
						clientIPUrl := fmt.Sprintf("%s/clientip", baseUrl)
						probeClientIPCmd := fmt.Sprintf("ip netns exec %s curl --connect-timeout 1 --retry 5 --retry-connrefused %s", tt.clientName, clientIPUrl)
						clientIPPort, stderr, err := data.RunCommandFromPod(testNamespace, tt.clientName, "", []string{"sh", "-c", probeClientIPCmd})
						assert.NoError(t, err, "External IP should be able to be connected from remote: %s", stderr)
						clientIP, _, err := net.SplitHostPort(clientIPPort)
						assert.NoError(t, err)
						assert.Equal(t, tt.clientIP, clientIP, "Source IP should be preserved when ExternalTrafficPolicy setting to Local")
					}
				})
			}
		})
	}
}

func getServiceExternalIPAndHost(service *v1.Service) (string, string) {
	if service == nil || len(service.Status.LoadBalancer.Ingress) == 0 {
		return "", ""
	}
	return service.Status.LoadBalancer.Ingress[0].IP, service.Status.LoadBalancer.Ingress[0].Hostname
}

func (data *TestData) waitForServiceConfigured(service *v1.Service, expectedExternalIP string, waitForNodeConfigured bool, expectedNodeName string) (*corev1.Service, error) {
	err := wait.PollImmediate(200*time.Millisecond, 15*time.Second, func() (done bool, err error) {
		service, err = data.clientset.CoreV1().Services(service.Namespace).Get(context.TODO(), service.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if len(service.Status.LoadBalancer.Ingress) == 0 || service.Status.LoadBalancer.Ingress[0].IP != expectedExternalIP {
			return false, nil
		}
		if waitForNodeConfigured || expectedNodeName != "" {
			if service.Status.LoadBalancer.Ingress[0].Hostname == "" {
				return false, nil
			}
		}
		if expectedNodeName != "" && service.Status.LoadBalancer.Ingress[0].Hostname != expectedNodeName {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return service, fmt.Errorf("wait for Service %q configured failed: %v. Expected external IP %s on Node %s, actual status %#v",
			service.Name, err, expectedExternalIP, expectedNodeName, service.Status)
	}
	return service, nil
}
