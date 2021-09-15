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
		t.Fatalf("Failed to enable LB feature: %v", err)
	}

	// t.Run("testServiceWithExternalIPCRUD", func(t *testing.T) { testServiceWithExternalIPCRUD(t, data) })
	// t.Run("testServiceUpdateExternalIP", func(t *testing.T) { testServiceUpdateExternalIP(t, data) })
	// t.Run("testServiceExternalTrafficPolicyLocal", func(t *testing.T) { testServiceExternalTrafficPolicyLocal(t, data) })
	t.Run("testServiceNodeFailure", func(t *testing.T) { testServiceNodeFailure(t, data) })
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
							IP:       "fe80::01",
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
							IP:       "fe80::01",
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
							IP:       "fe80::01",
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

			service, err = data.createService(fmt.Sprintf("test-svc-eip-%d", idx), testNamespace, 80, 80, nil, false, true, v1.ServiceTypeLoadBalancer, nil)
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

			service, err = data.waitForServiceConfigured(service, tt.expectedExternalIP, tt.expectedNodeOrigin)
			require.NoError(t, err)
			_, node := getServiceExternalIPAndHost(service)
			assert.Equal(t, tt.expectedNodeOrigin, node)

			epsToUpdate := eps.DeepCopy()
			epsToUpdate.Subsets = tt.updatedEndpointSubsets
			_, err = data.clientset.CoreV1().Endpoints(eps.Namespace).Update(context.TODO(), epsToUpdate, metav1.UpdateOptions{})
			require.NoError(t, err)
			service, err = data.waitForServiceConfigured(service, tt.expectedExternalIP, tt.expectedNodeUpdated)
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
			pool := data.createExternalIPPool(t, "crud-pool-", tt.ipRange, tt.nodeSelector.MatchExpressions, tt.nodeSelector.MatchLabels)
			defer data.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{})
			service, err = data.createService(fmt.Sprintf("test-lb-%d", idx), testNamespace, 80, 80, nil, false, false, v1.ServiceTypeLoadBalancer, nil)
			require.NoError(t, err)
			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})
			service, err = data.waitForServiceConfigured(service, tt.expectedExternalIP, "")
			require.NoError(t, err)

			if len(tt.expectedNodes) > 0 {
				_, assignedNode := getServiceExternalIPAndHost(service)
				err = data.checkNodesForAssignedIP(t, assignedNode, tt.expectedExternalIP)
				assert.NoError(t, err)
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
			err = data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})
			require.NoError(t, err, "Failed to delete Service")
			checkEIPStatus(0)
		})
	}
}

func (data *TestData) checkNodesForAssignedIP(t *testing.T, node, expectedIP string) error {
	return wait.PollImmediate(200*time.Millisecond, 3*time.Second, func() (done bool, err error) {
		var nodeHaveExpectedIP []string
		for _, n := range clusterInfo.nodes {
			if expectedIP != "" {
				exists, err := hasIP(data, n.name, expectedIP)
				require.NoError(t, err, "Failed to check if IP exists on Node %s", n.name)
				if exists {
					nodeHaveExpectedIP = append(nodeHaveExpectedIP, n.name)
				}
			}
		}
		if len(nodeHaveExpectedIP) != 1 || nodeHaveExpectedIP[0] != node {
			return false, fmt.Errorf("check for expected IP failed. Expected Node %s have IP %s. Actual Nodes have expected IP: %v", node, expectedIP, nodeHaveExpectedIP)
		}
		return true, nil
	})
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
			service, err := data.createServiceWithAnnotations(fmt.Sprintf("test-lb-%d", idx),
				testNamespace, 80, 80, corev1.ProtocolTCP, nil, false, false, v1.ServiceTypeLoadBalancer, nil, annotation)
			require.NoError(t, err)
			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})

			service, err = data.waitForServiceConfigured(service, tt.originalExternalIP, "")
			require.NoError(t, err)

			_, assignedNode := getServiceExternalIPAndHost(service)
			err = data.checkNodesForAssignedIP(t, assignedNode, tt.originalExternalIP)
			assert.NoError(t, err)

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

			toUpdate, err = data.waitForServiceConfigured(service, tt.newExternalIP, "")
			require.NoError(t, err)

			_, assignedNode = getServiceExternalIPAndHost(toUpdate)
			err = data.checkNodesForAssignedIP(t, assignedNode, tt.newExternalIP)
			assert.NoError(t, err)
		})
	}
}

func testServiceNodeFailure(t *testing.T, data *TestData) {
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
				rc, stdout, stderr, err := RunCommandOnNode(nodeName, cmd)
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
			service, err := data.createServiceWithAnnotations("test-service-node-failure", testNamespace, 80, 80,
				corev1.ProtocolTCP, nil, false, false, v1.ServiceTypeLoadBalancer, nil, annotation)
			require.NoError(t, err)
			defer data.clientset.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})

			service, err = data.waitForServiceConfigured(service, tt.expectedIP, "")
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
			_, err = data.waitForServiceConfigured(service, tt.expectedIP, expectedMigratedNode)
			assert.NoError(t, err)
			restoreAgent(originalNode)
			_, err = data.waitForServiceConfigured(service, tt.expectedIP, originalNode)
			assert.NoError(t, err)
		})
	}
}

func getServiceExternalIPAndHost(service *v1.Service) (string, string) {
	if service == nil || len(service.Status.LoadBalancer.Ingress) == 0 {
		return "", ""
	}
	return service.Status.LoadBalancer.Ingress[0].IP, service.Status.LoadBalancer.Ingress[0].Hostname
}

func (data *TestData) waitForServiceConfigured(service *v1.Service, expectedExternalIP, expectedNodeName string) (*v1.Service, error) {
	err := wait.PollImmediate(200*time.Millisecond, 5*time.Second, func() (done bool, err error) {
		service, err = data.clientset.CoreV1().Services(service.Namespace).Get(context.TODO(), service.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if len(service.Status.LoadBalancer.Ingress) == 0 || service.Status.LoadBalancer.Ingress[0].IP != expectedExternalIP {
			return false, nil
		}
		if expectedNodeName != "" && service.Status.LoadBalancer.Ingress[0].Hostname != expectedNodeName {
			return false, nil
		}
		return true, nil

	})
	if err != nil {
		return nil, fmt.Errorf("wait for LB Service %q configured failed: %v. Expected external IP %s on Node %s, actual status %+v",
			service.Name, err, expectedExternalIP, expectedNodeName, service.Status)
	}
	return service, nil
}
