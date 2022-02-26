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
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	utilnet "k8s.io/utils/net"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	annotation "antrea.io/antrea/pkg/ipam"
)

var (
	subnetIPv4RangesMap = map[string]crdv1alpha2.IPPool{
		testAntreaIPAMNamespace: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-0",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: crdv1alpha2.IPv4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.240.100",
					End:   "192.168.240.129",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.240.1",
						PrefixLength: 24,
					}}},
			},
		},
		"1": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-1",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: crdv1alpha2.IPv4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.240.130",
					End:   "192.168.240.139",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.240.1",
						PrefixLength: 24,
					}}},
			},
		},
		testAntreaIPAMNamespace11: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-11",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: 4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.241.100",
					End:   "192.168.241.129",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.241.1",
						PrefixLength: 24,
						VLAN:         11,
					}}},
			},
		},
		testAntreaIPAMNamespace12: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-12",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: 4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.242.100",
					End:   "192.168.242.129",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.242.1",
						PrefixLength: 24,
						VLAN:         12,
					}}},
			},
		},
		testAntreaIPAMNamespaceExpand: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-13",
			},
			Spec: crdv1alpha2.IPPoolSpec{
				IPVersion: 4,
				IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
					CIDR:  "",
					Start: "192.168.240.100",
					End:   "192.168.240.106",
				},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "192.168.240.1",
						PrefixLength: 24,
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
	var ipPools []string
	for _, namespace := range []string{testAntreaIPAMNamespace, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12, testAntreaIPAMNamespaceExpand} {
		ipPool, err := createIPPool(t, data, namespace)
		if err != nil {
			t.Fatalf("Creating IPPool failed, err=%+v", err)
		}
		defer deleteIPPoolWrapper(t, data, ipPool.Name)
		ipPools = append(ipPools, ipPool.Name)
		annotations := map[string]string{}
		annotations[annotation.AntreaIPAMAnnotationKey] = ipPool.Name
		err = data.createNamespaceWithAnnotations(namespace, annotations)
		if err != nil {
			t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
		}
		defer deleteAntreaIPAMNamespace(t, data, namespace)
	}
	// Create AntreaIPAM IPPool that would be dedicated to StatefulSet
	ipPool, err := createIPPool(t, data, "1")
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ipPool.Name)
	ipPools = append(ipPools, ipPool.Name)

	// connectivity test with antrea redeploy
	t.Run("testAntreaIPAMPodConnectivityAfterAntreaRestart", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testPodConnectivityAfterAntreaRestart(t, data, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodConnectivityAfterAntreaRestart", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testPodConnectivityAfterAntreaRestart(t, data, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})

	// basic test
	t.Run("testAntreaIPAMPodAssignIP", func(t *testing.T) { testPodAssignIP(t, data, testAntreaIPAMNamespace, "192.168.240.0/24", "") })
	t.Run("testDeleteAntreaIPAMPod", func(t *testing.T) { testDeletePod(t, data, testAntreaIPAMNamespace) })
	t.Run("testAntreaIPAMRestart", func(t *testing.T) { testIPAMRestart(t, data, testAntreaIPAMNamespace) })
	t.Run("testAntreaIPAMGratuitousARP", func(t *testing.T) {
		testGratuitousARP(t, data, testAntreaIPAMNamespace)
		testGratuitousARP(t, data, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})

	// connectivity test
	t.Run("testAntreaIPAMPodConnectivitySameNode", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testAntreaIPAMPodConnectivitySameNode(t, data)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodConnectivityDifferentNodes", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testAntreaIPAMPodConnectivityDifferentNodes(t, data)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMVLAN11HostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace11, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMVLAN12HostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToAntreaIPAMVLAN11HostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace11, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11HostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace11, testNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMOVSRestartSameNode", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		skipIfHasWindowsNodes(t)
		testOVSRestartSameNode(t, data, testAntreaIPAMNamespace)
		testOVSRestartSameNode(t, data, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMOVSFlowReplay", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		testOVSFlowReplay(t, data, testAntreaIPAMNamespace)
		testOVSFlowReplay(t, data, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})

	// StatefulSet test
	dedicatedIPPoolKey := "1"
	t.Run("testAntreaIPAMStatefulSetDedicated", func(t *testing.T) {
		testAntreaIPAMStatefulSet(t, data, &dedicatedIPPoolKey)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMStatefulSetShared", func(t *testing.T) {
		testAntreaIPAMStatefulSet(t, data, nil)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMStatefulSetPreallocateAndExpand", func(t *testing.T) {
		testAntreaIPAMStatefulSetPreallocateAndExpand(t, data)
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
	var podInfos []podInfo
	for _, namespace := range []string{testNamespace, testAntreaIPAMNamespace, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12} {
		createdPodInfos, deletePods := createPodsOnDifferentNodes(t, data, namespace, "differentnodes")
		defer deletePods()
		if len(createdPodInfos) > maxNodes {
			createdPodInfos = createdPodInfos[:maxNodes]
		}
		podInfos = append(podInfos, createdPodInfos...)
	}
	data.runPingMesh(t, podInfos, agnhostContainerName)
}

func testAntreaIPAMStatefulSet(t *testing.T, data *TestData, dedicatedIPPoolKey *string) {
	stsName := randName("sts-test-")
	ipPoolName := subnetIPv4RangesMap[testAntreaIPAMNamespace].Name
	if dedicatedIPPoolKey != nil {
		ipPoolName = subnetIPv4RangesMap[*dedicatedIPPoolKey].Name
	}
	ipOffsets := []int32{0, 1}
	size := len(ipOffsets)
	reservedIPOffsets := ipOffsets
	mutateFunc := func(sts *appsv1.StatefulSet) {
		if sts.Spec.Template.Annotations == nil {
			sts.Spec.Template.Annotations = map[string]string{}
		}
		if dedicatedIPPoolKey != nil {
			sts.Spec.Template.Annotations[annotation.AntreaIPAMAnnotationKey] = ipPoolName
		}
	}
	_, cleanup, err := data.createStatefulSet(stsName, testAntreaIPAMNamespace, int32(size), agnhostContainerName, agnhostImage, []string{"sleep", "3600"}, nil, mutateFunc)
	if err != nil {
		t.Fatalf("Error when creating StatefulSet '%s': %v", stsName, err)
	}
	defer cleanup()
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, 0, ipOffsets, reservedIPOffsets)

	ipOffsets = []int32{0}
	size = len(ipOffsets)
	_, err = data.updateStatefulSetSize(stsName, testAntreaIPAMNamespace, int32(size))
	if err != nil {
		t.Fatalf("Error when updating StatefulSet '%s': %v", stsName, err)
	}
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, 0, ipOffsets, reservedIPOffsets)

	podMutateFunc := func(pod *corev1.Pod) {
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		if dedicatedIPPoolKey != nil {
			pod.Annotations[annotation.AntreaIPAMAnnotationKey] = ipPoolName
		}
	}
	podName := randName("test-standalone-pod-")
	err = data.createPodOnNode(podName, testAntreaIPAMNamespace, controlPlaneNodeName(), agnhostImage, []string{"sleep", "3600"}, nil, nil, nil, false, podMutateFunc)
	if err != nil {
		t.Fatalf("Error when creating Pod '%s': %v", podName, err)
	}
	defer data.deletePodAndWait(defaultTimeout, podName, testAntreaIPAMNamespace)
	podIPs, err := data.podWaitForIPs(defaultTimeout, podName, testAntreaIPAMNamespace)
	if err != nil {
		t.Fatalf("Error when waiting Pod IPs: %v", err)
	}
	isBelongTo, ipAddressState, err := checkIPPoolAllocation(t, data, ipPoolName, podIPs.ipv4.String())
	if err != nil {
		t.Fatalf("Error when checking IPPoolAllocation: %v", err)
	}
	startIPString := subnetIPv4RangesMap[testAntreaIPAMNamespace].Spec.IPRanges[0].Start
	offset := 2
	if dedicatedIPPoolKey != nil {
		startIPString = subnetIPv4RangesMap[*dedicatedIPPoolKey].Spec.IPRanges[0].Start
	}
	expectedPodIP := utilnet.AddIPOffset(utilnet.BigForIP(net.ParseIP(startIPString)), offset)
	assert.True(t, isBelongTo)
	assert.True(t, reflect.DeepEqual(ipAddressState, &crdv1alpha2.IPAddressState{
		IPAddress: expectedPodIP.String(),
		Phase:     crdv1alpha2.IPAddressPhaseAllocated,
		Owner: crdv1alpha2.IPAddressOwner{
			Pod: &crdv1alpha2.PodOwner{
				Name:        podName,
				Namespace:   testAntreaIPAMNamespace,
				ContainerID: ipAddressState.Owner.Pod.ContainerID,
			},
		},
	}))

	ipOffsets = []int32{0, 1, 3}
	size = len(ipOffsets)
	reservedIPOffsets = ipOffsets
	_, err = data.updateStatefulSetSize(stsName, testAntreaIPAMNamespace, int32(size))
	if err != nil {
		t.Fatalf("Error when updating StatefulSet '%s': %v", stsName, err)
	}
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, 0, ipOffsets, reservedIPOffsets)

	data.deletePodAndWait(defaultTimeout, podName, testAntreaIPAMNamespace)
	_, err = data.restartStatefulSet(stsName, testAntreaIPAMNamespace)
	if err != nil {
		t.Fatalf("Error when restarting StatefulSet '%s': %v", stsName, err)
	}
	time.Sleep(time.Second)
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, 0, ipOffsets, reservedIPOffsets)

	cleanup()
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, 0, nil, nil)
}

func testAntreaIPAMStatefulSetPreallocateAndExpand(t *testing.T, data *TestData) {
	stsName := randName("sts-test-")

	// Fragment the continuous IP space by Pod allocation - create three Pods and delete the first two
	for i := 0; i < 3; i++ {
		podName := fmt.Sprintf("sts-test-pod-%d", i)
		err := data.createPodOnNode(podName, testAntreaIPAMNamespaceExpand, controlPlaneNodeName(), agnhostImage, []string{"sleep", "3600"}, nil, nil, nil, false, nil)
		if err != nil {
			t.Fatalf("Error when creating Pod '%s': %v", podName, err)
		}
		defer data.deletePodAndWait(defaultTimeout, podName, testAntreaIPAMNamespaceExpand)
		_, err = data.podWaitForIPs(defaultTimeout, podName, testAntreaIPAMNamespaceExpand)
		if err != nil {
			t.Fatalf("Error when waiting Pod IPs: %v", err)
		}
	}

	data.deletePodAndWait(defaultTimeout, "sts-test-pod-0", testAntreaIPAMNamespaceExpand)
	data.deletePodAndWait(defaultTimeout, "sts-test-pod-1", testAntreaIPAMNamespaceExpand)

	ipPoolName := subnetIPv4RangesMap[testAntreaIPAMNamespaceExpand].Name
	// Since second address is the Pool is taken by the Pod, allocation for StatefuSet will be fragmented
	ipOffsets := []int32{0, 1, 3, 4, 5}
	size := len(ipOffsets)
	_, cleanup, err := data.createStatefulSet(stsName, testAntreaIPAMNamespaceExpand, int32(size), agnhostContainerName, agnhostImage, []string{"sleep", "3600"}, nil, nil)
	if err != nil {
		t.Fatalf("Error when creating StatefulSet '%s': %v", stsName, err)
	}
	defer cleanup()
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespaceExpand); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespaceExpand, ipPoolName, 0, ipOffsets, ipOffsets)

	// Delete the StatefulSet
	cleanup()
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespaceExpand, ipPoolName, 0, nil, nil)

	// Expand IP Pool with additional range
	newRange := crdv1alpha2.SubnetIPRange{IPRange: crdv1alpha2.IPRange{
		CIDR:  "",
		Start: "192.168.240.140",
		End:   "192.168.240.150",
	},
		SubnetInfo: crdv1alpha2.SubnetInfo{
			Gateway:      "192.168.240.1",
			PrefixLength: 24,
		}}

	_, err = expandIPPoolSpec(t, data, testAntreaIPAMNamespaceExpand, &newRange)
	if err != nil {
		t.Fatalf("Failed to expand IP Pool '%s': %v", ipPoolName, err)
	}

	// Now allocation of continuous IP space should succeed
	_, cleanup, err = data.createStatefulSet(stsName, testAntreaIPAMNamespaceExpand, int32(size), agnhostContainerName, agnhostImage, []string{"sleep", "3600"}, nil, nil)
	if err != nil {
		t.Fatalf("Error when creating StatefulSet '%s': %v", stsName, err)
	}
	defer cleanup()
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespaceExpand); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	// No allocations expected in first IP range
	ipOffsets = []int32{0, 1, 2, 3, 4}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespaceExpand, ipPoolName, 0, nil, nil)
	// Continuous allocation expected in second IP range
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespaceExpand, ipPoolName, 1, ipOffsets, ipOffsets)

	cleanup()
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespaceExpand, ipPoolName, 1, nil, nil)
}

func isIPInRange(ip net.IP, start net.IP, end net.IP) bool {
	return bytes.Compare(ip, start) >= 0 && bytes.Compare(ip, end) <= 0
}

func checkStatefulSetIPPoolAllocation(tb testing.TB, data *TestData, name string, namespace string, ipPoolName string, ipRangeIndex int, ipOffsets, reservedIPOffsets []int32) {

	ipPool, err := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), ipPoolName, metav1.GetOptions{})
	if err != nil {
		tb.Fatalf("Failed to get IPPool %s, err: %+v", ipPoolName, err)
	}
	startIP := net.ParseIP(ipPool.Spec.IPRanges[ipRangeIndex].Start)

	offsetIP := func(offset int) string {
		return utilnet.AddIPOffset(utilnet.BigForIP(startIP), offset).String()
	}
	endIP := net.ParseIP(ipPool.Spec.IPRanges[ipRangeIndex].End)
	expectedIPAddressMap := map[string]*crdv1alpha2.IPAddressState{}
	for i, offset := range ipOffsets {
		ipString := offsetIP(int(offset))
		podName := fmt.Sprintf("%s-%d", name, i)
		expectedIPAddressMap[ipString] = &crdv1alpha2.IPAddressState{
			IPAddress: ipString,
			Phase:     crdv1alpha2.IPAddressPhaseAllocated,
			Owner: crdv1alpha2.IPAddressOwner{
				Pod: &crdv1alpha2.PodOwner{
					Name:        podName,
					Namespace:   namespace,
					ContainerID: "",
				},
			},
		}
	}
	for i, offset := range reservedIPOffsets {
		ipString := offsetIP(int(offset))
		stsOwner := &crdv1alpha2.StatefulSetOwner{
			Name:      name,
			Namespace: namespace,
			Index:     i,
		}
		if _, ok := expectedIPAddressMap[ipString]; ok {
			expectedIPAddressMap[ipString].Owner.StatefulSet = stsOwner
		} else {
			expectedIPAddressMap[ipString] = &crdv1alpha2.IPAddressState{
				IPAddress: ipString,
				Phase:     crdv1alpha2.IPAddressPhaseReserved,
				Owner: crdv1alpha2.IPAddressOwner{
					StatefulSet: stsOwner,
				},
			}
		}
	}
	expectedIPAddressJson, _ := json.Marshal(expectedIPAddressMap)
	tb.Logf("expectedIPAddressMap: %s", expectedIPAddressJson)

	err = wait.Poll(time.Second*3, time.Second*15, func() (bool, error) {
		ipPool, err := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), ipPoolName, metav1.GetOptions{})
		if err != nil {
			tb.Fatalf("Failed to get IPPool %s, err: %+v", ipPoolName, err)
		}
		actualIPAddressMap := map[string]*crdv1alpha2.IPAddressState{}
	actualIPAddressLoop:
		for _, ipAddress := range ipPool.Status.IPAddresses {
			addr := net.ParseIP(ipAddress.IPAddress)
			if !isIPInRange(addr, startIP, endIP) {
				continue actualIPAddressLoop
			}
			for expectedIP := range expectedIPAddressMap {
				if ipAddress.IPAddress == expectedIP {
					actualIPAddressMap[expectedIP] = ipAddress.DeepCopy()
					if actualIPAddressMap[expectedIP].Owner.Pod != nil {
						actualIPAddressMap[expectedIP].Owner.Pod.ContainerID = ""
					}
					continue actualIPAddressLoop
				}
			}
			if ipAddress.Owner.Pod != nil && ipAddress.Owner.Pod.Namespace == namespace && strings.HasPrefix(ipAddress.Owner.Pod.Name, name) {
				actualIPAddressMap[ipAddress.IPAddress] = ipAddress.DeepCopy()
				continue
			}
			if ipAddress.Owner.StatefulSet != nil && ipAddress.Owner.StatefulSet.Namespace == namespace && ipAddress.Owner.StatefulSet.Name == name {
				actualIPAddressMap[ipAddress.IPAddress] = ipAddress.DeepCopy()
				continue
			}
		}
		done := reflect.DeepEqual(expectedIPAddressMap, actualIPAddressMap)
		if !done {
			actualIPAddressJson, _ := json.Marshal(ipPool.Status.IPAddresses)
			tb.Logf("IPPool status isn't correct: %s", actualIPAddressJson)
		}
		return done, nil
	})
	require.Nil(tb, err)
}

func deleteAntreaIPAMNamespace(tb testing.TB, data *TestData, namespace string) {
	tb.Logf("Deleting '%s' K8s Namespace", namespace)
	if err := data.DeleteNamespace(namespace, defaultTimeout); err != nil {
		tb.Logf("Error when tearing down test: %v", err)
	}
}

func createIPPool(tb testing.TB, data *TestData, key string) (*crdv1alpha2.IPPool, error) {
	ipv4IPPool := subnetIPv4RangesMap[key]
	tb.Logf("Creating IPPool '%s'", ipv4IPPool.Name)
	return data.crdClient.CrdV1alpha2().IPPools().Create(context.TODO(), &ipv4IPPool, metav1.CreateOptions{})
}

func expandIPPoolSpec(tb testing.TB, data *TestData, key string, ipRange *crdv1alpha2.SubnetIPRange) (*crdv1alpha2.IPPool, error) {
	ipv4IPPool := subnetIPv4RangesMap[key]
	pool, err := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), ipv4IPPool.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	pool.Spec = ipv4IPPool.Spec
	pool.Spec.IPRanges = append(ipv4IPPool.Spec.IPRanges, *ipRange)
	tb.Logf("Updating IPPool '%s'", pool.Name)
	return data.crdClient.CrdV1alpha2().IPPools().Update(context.TODO(), pool, metav1.UpdateOptions{})
}

func checkIPPoolAllocation(tb testing.TB, data *TestData, ipPoolName, podIPString string) (isBelongTo bool, ipAddressState *crdv1alpha2.IPAddressState, err error) {
	ipPool, err := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), ipPoolName, metav1.GetOptions{})
	if err != nil {
		return
	}
	podIP := net.ParseIP(podIPString)
	for _, subnetIPRange := range ipPool.Spec.IPRanges {
		if subnetIPRange.CIDR != "" {
			_, ipNet, _ := net.ParseCIDR(subnetIPRange.CIDR)
			if ipNet.Contains(podIP) {
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
	for _, ipAddress := range ipPool.Status.IPAddresses {
		if podIP.Equal(net.ParseIP(ipAddress.IPAddress)) {
			ipAddressState = ipAddress.DeepCopy()
			return
		}
	}
	return
}

func deleteIPPoolWrapper(tb testing.TB, data *TestData, name string) {
	tb.Logf("Deleting IPPool '%s'", name)
	if err := data.crdClient.CrdV1alpha2().IPPools().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		ipPool, _ := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), name, metav1.GetOptions{})
		ipPoolJson, _ := json.Marshal(ipPool)
		tb.Logf("Error when deleting IPPool, err: %v, data: %s", err, ipPoolJson)
	}
}

func checkIPPoolsEmpty(tb testing.TB, data *TestData, names []string) {
	count := 0
	err := wait.PollImmediate(3*time.Second, defaultTimeout, func() (bool, error) {
		for _, name := range names {
			ipPool, _ := data.crdClient.CrdV1alpha2().IPPools().Get(context.TODO(), name, metav1.GetOptions{})
			if len(ipPool.Status.IPAddresses) > 0 {
				ipPoolJson, _ := json.Marshal(ipPool)
				if count > 20 {
					tb.Logf("IPPool is not empty, data: %s", ipPoolJson)
				}
				count += 1
				return false, nil
			}
		}
		return true, nil
	})
	require.Nil(tb, err)
}
