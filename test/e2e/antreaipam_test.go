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
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

var (
	subnetIPv4RangesMap = map[int]crdv1alpha2.IPPool{
		0: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-0",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: 4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.240.100",
					End:   "192.168.240.129",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.240.1",
						PrefixLength: 24,
						VLAN:         "",
					}}},
			},
		},
	}
)

func TestAntreaIPAM(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	ippool, err := createIPPool(t, data, 0)
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ippool.Name)
	annotations := map[string]string{}
	annotations[ipam.AntreaIPAMAnnotationKey] = ippool.Name
	err = data.createNamespaceWithAnnotations(testAntreaIPAMNamespace, annotations)
	if err != nil {
		t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
	}
	defer deleteAntreaIPAMNamespace(t, data)

	// basic test
	t.Run("testAntreaIPAMPodAssignIP", func(t *testing.T) { testPodAssignIP(t, data, testAntreaIPAMNamespace, "192.168.240.0/24", "") })
	t.Run("testDeleteAntreaIPAMPod", func(t *testing.T) { testDeletePod(t, data, testAntreaIPAMNamespace) })
	t.Run("testAntreaIPAMRestart", func(t *testing.T) { testIPAMRestart(t, data, testAntreaIPAMNamespace) })
	t.Run("testAntreaIPAMGratuitousARP", func(t *testing.T) { testGratuitousARP(t, data, testAntreaIPAMNamespace) })

	// connectivity test
	t.Run("testAntreaIPAMPodToAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMPodConnectivitySameNode", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testAntreaIPAMPodConnectivitySameNode(t, data)
	})
	t.Run("testAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testNamespace, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMPodConnectivityDifferentNodes", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testAntreaIPAMPodConnectivityDifferentNodes(t, data)
	})
	t.Run("testAntreaIPAMPodToHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testNamespace)
	})
	t.Run("testAntreaIPAMOVSRestartSameNode", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		skipIfHasWindowsNodes(t)
		testOVSRestartSameNode(t, data, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMPodConnectivityAfterAntreaRestart", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testPodConnectivityAfterAntreaRestart(t, data, testAntreaIPAMNamespace)
	})
	t.Run("testAntreaIPAMOVSFlowReplay", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testOVSFlowReplay(t, data, testAntreaIPAMNamespace)
	})
}

func testAntreaIPAMPodConnectivitySameNode(t *testing.T, data *TestData) {
	numPods := 2 // Two AntreaIPAM Pods, can be increased
	podInfos := make([]podInfo, numPods)
	for idx := range podInfos {
		podInfos[idx].name = randName(fmt.Sprintf("test-antrea-ipam-pod-%d-", idx))
		podInfos[idx].namespace = testAntreaIPAMNamespace
	}
	// One Per-Node IPAM Pod
	podInfos = append(podInfos, podInfo{
		name:      randName("test-pod-0-"),
		namespace: testNamespace,
	})
	workerNode := workerNodeName(1)

	t.Logf("Creating %d agnhost Pods on '%s'", numPods+1, workerNode)
	for i := range podInfos {
		podInfos[i].os = clusterInfo.nodesOS[workerNode]
		if err := data.createAgnhostPodOnNodeWithAnnotations(podInfos[i].name, podInfos[i].namespace, workerNode, nil); err != nil {
			t.Fatalf("Error when creating agnhost test Pod '%s': %v", podInfos[i], err)
		}
		defer deletePodWrapper(t, data, podInfos[i].namespace, podInfos[i].name)
	}

	data.runPingMesh(t, podInfos, agnhostContainerName)
}

func testAntreaIPAMPodConnectivityDifferentNodes(t *testing.T, data *TestData) {
	maxNodes := 3
	podInfos, deletePods := createPodsOnDifferentNodes(t, data, testNamespace, "differentnodes")
	defer deletePods()
	antreaIPAMPodInfos, deleteAntreaIPAMPods := createPodsOnDifferentNodes(t, data, testAntreaIPAMNamespace, "antreaipam-differentnodes")
	defer deleteAntreaIPAMPods()

	if len(podInfos) > maxNodes {
		podInfos = podInfos[:maxNodes]
		antreaIPAMPodInfos = antreaIPAMPodInfos[:maxNodes]
	}
	podInfos = append(podInfos, antreaIPAMPodInfos...)
	data.runPingMesh(t, podInfos, agnhostContainerName)
}

func deleteAntreaIPAMNamespace(tb testing.TB, data *TestData) {
	tb.Logf("Deleting '%s' K8s Namespace", testAntreaIPAMNamespace)
	if err := data.deleteNamespace(testAntreaIPAMNamespace, defaultTimeout); err != nil {
		tb.Logf("Error when tearing down test: %v", err)
	}
}

func createIPPool(tb testing.TB, data *TestData, vlan int) (*crdv1alpha2.IPPool, error) {
	ipv4IPPool := subnetIPv4RangesMap[vlan]
	tb.Logf("Creating IPPool '%s'", ipv4IPPool.Name)
	return data.crdClient.CrdV1alpha2().IPPools().Create(context.TODO(), &ipv4IPPool, metav1.CreateOptions{})
}

func checkIPPoolAllocation(tb testing.TB, data *TestData, IPPoolName, podIPString string) (isBelongTo, isAllocated, isPreallocated bool, err error) {
	IPPool, err := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), IPPoolName, metav1.GetOptions{})
	if err != nil {
		return
	}
	podIP := net.ParseIP(podIPString)
	for _, subnetIPRange := range IPPool.Spec.IPRanges {
		if subnetIPRange.CIDR != "" {
			_, IPNet, _ := net.ParseCIDR(subnetIPRange.CIDR)
			if IPNet.Contains(podIP) {
				isBelongTo = true
				break
			}
		} else {
			if bytes.Compare(podIP, net.ParseIP(subnetIPRange.Start)) >= 0 && bytes.Compare(podIP, net.ParseIP(subnetIPRange.End)) <= 0 {
				isBelongTo = true
				break
			}
		}
	}
	if !isBelongTo {
		return
	}
	for _, IPAddress := range IPPool.Status.IPAddresses {
		if podIP.Equal(net.ParseIP(IPAddress.IPAddress)) {
			switch IPAddress.Phase {
			case crdv1alpha2.IPAddressPhaseAllocated:
				isAllocated = true
			case crdv1alpha2.IPAddressPhasePreallocated:
				isPreallocated = true
			}
			return
		}
	}
	return
}

func deleteIPPoolWrapper(tb testing.TB, data *TestData, name string) {
	tb.Logf("Deleting IPPool '%s'", name)
	if err := data.crdClient.CrdV1alpha2().IPPools().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		tb.Logf("Error when deleting IPPool: %v", err)
	}
}
