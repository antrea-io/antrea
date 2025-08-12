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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	utilnet "k8s.io/utils/net"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	annotation "antrea.io/antrea/pkg/ipam"
)

var (
	subnetIPv4RangesMap = map[string]crdv1beta1.IPPool{
		testAntreaIPAMNamespace: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-0",
			},
			Spec: crdv1beta1.IPPoolSpec{
				IPRanges: []crdv1beta1.IPRange{
					{
						CIDR:  "",
						Start: "192.168.240.100",
						End:   "192.168.240.129",
					},
				},
				SubnetInfo: crdv1beta1.SubnetInfo{
					Gateway:      "192.168.240.1",
					PrefixLength: 24,
				},
			},
		},
		"1": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-1",
			},
			Spec: crdv1beta1.IPPoolSpec{
				IPRanges: []crdv1beta1.IPRange{
					{
						CIDR:  "",
						Start: "192.168.240.130",
						End:   "192.168.240.139",
					},
				},
				SubnetInfo: crdv1beta1.SubnetInfo{
					Gateway:      "192.168.240.1",
					PrefixLength: 24,
				},
			},
		},
		testAntreaIPAMNamespace11: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-11",
			},
			Spec: crdv1beta1.IPPoolSpec{
				IPRanges: []crdv1beta1.IPRange{
					{
						CIDR:  "",
						Start: "192.168.241.100",
						End:   "192.168.241.129",
					},
				},
				SubnetInfo: crdv1beta1.SubnetInfo{
					Gateway:      "192.168.241.1",
					PrefixLength: 24,
					VLAN:         11,
				},
			},
		},
		testAntreaIPAMNamespace12: {
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ippool-ipv4-12",
			},
			Spec: crdv1beta1.IPPoolSpec{
				IPRanges: []crdv1beta1.IPRange{
					{
						CIDR:  "",
						Start: "192.168.242.100",
						End:   "192.168.242.129",
					},
				},
				SubnetInfo: crdv1beta1.SubnetInfo{
					Gateway:      "192.168.242.1",
					PrefixLength: 24,
					VLAN:         12,
				},
			},
		},
	}

	v1a1Pool = crdv1alpha2.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ippool-v1alpha1",
		},
		Spec: crdv1alpha2.IPPoolSpec{
			IPVersion: crdv1alpha2.IPv4,
			IPRanges: []crdv1alpha2.SubnetIPRange{
				{
					IPRange: crdv1alpha2.IPRange{
						Start: "10.2.0.12",
						End:   "10.2.0.20",
					},
					SubnetInfo: crdv1alpha2.SubnetInfo{
						Gateway:      "10.2.0.1",
						PrefixLength: 24,
						VLAN:         2,
					},
				},
			},
		},
	}

	v1b1Pool = crdv1beta1.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ippool-v1beta1",
		},
		Spec: crdv1beta1.IPPoolSpec{
			IPRanges: []crdv1beta1.IPRange{
				{
					CIDR: "10.10.1.1/26",
				},
			},
			SubnetInfo: crdv1beta1.SubnetInfo{
				Gateway:      "10.10.1.1",
				PrefixLength: 24,
				VLAN:         2,
			},
		},
	}
)

var (
	antreaIPAMNamespaces = []string{testAntreaIPAMNamespace, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12}
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
	for _, namespace := range antreaIPAMNamespaces {
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
	// Create 2nd AntreaIPAM IPPool
	ipPool, err := createIPPool(t, data, "1")
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ipPool.Name)
	ipPools = append(ipPools, ipPool.Name)

	t.Run("testIPPoolConversion", func(t *testing.T) {
		testIPPoolConversion(t, data)
	})

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
		data.testHostPortPodConnectivity(t, data.testNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace, data.testNamespace)
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
		data.testHostPortPodConnectivity(t, data.testNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToHostPortPodConnectivity", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testHostPortPodConnectivity(t, testAntreaIPAMNamespace11, data.testNamespace)
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

	t.Run("testMulticastWithFlexibleIPAM", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		skipIfNotIPv4Cluster(t)
		runMulticastTestCases(t, data, testAntreaIPAMNamespace)
	})
}

func testIPPoolConversion(t *testing.T, data *TestData) {
	_, err := data.CRDClient.CrdV1alpha2().IPPools().Create(context.TODO(), &v1a1Pool, metav1.CreateOptions{})
	assert.NoError(t, err, "failed to create v1alpha2 IPPool")
	defer deleteIPPoolWrapper(t, data, v1a1Pool.Name)
	v1beta1Pool, err := data.CRDClient.CrdV1beta1().IPPools().Get(context.TODO(), v1a1Pool.Name, metav1.GetOptions{})
	assert.NoError(t, err, "failed to get v1beta1 IPPool")
	assert.Equal(t, v1a1Pool.Name, v1beta1Pool.Name)
	assert.Equal(t, v1a1Pool.Spec.IPRanges[0].Start, v1beta1Pool.Spec.IPRanges[0].Start)
	assert.Equal(t, v1a1Pool.Spec.IPRanges[0].End, v1beta1Pool.Spec.IPRanges[0].End)
	assert.Equal(t, v1a1Pool.Spec.IPRanges[0].Gateway, v1beta1Pool.Spec.SubnetInfo.Gateway)
	assert.Equal(t, v1a1Pool.Spec.IPRanges[0].PrefixLength, v1beta1Pool.Spec.SubnetInfo.PrefixLength)
	assert.Equal(t, int32(v1a1Pool.Spec.IPRanges[0].VLAN), v1beta1Pool.Spec.SubnetInfo.VLAN)

	_, err = data.CRDClient.CrdV1beta1().IPPools().Create(context.TODO(), &v1b1Pool, metav1.CreateOptions{})
	defer deleteIPPoolWrapper(t, data, v1b1Pool.Name)
	assert.NoError(t, err, "failed to create v1beta1 IPPool")
	v1alpha2Pool, err := data.CRDClient.CrdV1alpha2().IPPools().Get(context.TODO(), v1b1Pool.Name, metav1.GetOptions{})
	assert.NoError(t, err, "failed to get v1alpha2 IPPool")
	assert.Equal(t, v1b1Pool.Name, v1alpha2Pool.Name)
	assert.Equal(t, v1b1Pool.Spec.IPRanges[0].CIDR, v1alpha2Pool.Spec.IPRanges[0].CIDR)
	assert.Equal(t, v1b1Pool.Spec.SubnetInfo.Gateway, v1alpha2Pool.Spec.IPRanges[0].Gateway)
	assert.Equal(t, v1b1Pool.Spec.SubnetInfo.PrefixLength, v1alpha2Pool.Spec.IPRanges[0].PrefixLength)
	assert.Equal(t, v1b1Pool.Spec.SubnetInfo.VLAN, int32(v1alpha2Pool.Spec.IPRanges[0].VLAN))

	v1alpha2Pool.Spec.IPRanges[0].PrefixLength = 25
	_, err = data.CRDClient.CrdV1beta1().IPPools().Update(context.TODO(), &v1b1Pool, metav1.UpdateOptions{})
	assert.Error(t, err, "The prefixLength of IPPool should be immutable")

	v1alpha2Pool.Spec.IPRanges[0].Gateway = "10.10.2.1"
	_, err = data.CRDClient.CrdV1beta1().IPPools().Update(context.TODO(), &v1b1Pool, metav1.UpdateOptions{})
	assert.Error(t, err, "The gateway of IPPool should be immutable")
}

func testAntreaIPAMPodConnectivitySameNode(t *testing.T, data *TestData) {
	workerNode := workerNodeName(1)
	numPods := 2 // Two AntreaIPAM Pods, can be increased
	PodInfos := make([]PodInfo, numPods)
	for idx := range PodInfos {
		PodInfos[idx].Name = randName(fmt.Sprintf("test-antrea-ipam-pod-%d-", idx))
		PodInfos[idx].Namespace = testAntreaIPAMNamespace
		PodInfos[idx].NodeName = workerNode
	}
	// One Per-Node IPAM Pod
	PodInfos = append(PodInfos, PodInfo{
		Name:      randName("test-pod-0-"),
		Namespace: data.testNamespace,
		NodeName:  workerNode,
	})

	t.Logf("Creating %d toolbox Pods on '%s'", numPods+1, workerNode)
	for i := range PodInfos {
		PodInfos[i].OS = clusterInfo.nodesOS[workerNode]
		if err := data.createToolboxPodOnNode(PodInfos[i].Name, PodInfos[i].Namespace, workerNode, false); err != nil {
			t.Fatalf("Error when creating toolbox test Pod '%s': %v", PodInfos[i], err)
		}
		defer deletePodWrapper(t, data, PodInfos[i].Namespace, PodInfos[i].Name)
	}

	data.runPingMesh(t, PodInfos, toolboxContainerName, true)

	testAntreaIPAMTraceflowIntraNode(t, data, PodInfos, false)
	testAntreaIPAMTraceflowIntraNode(t, data, PodInfos, true)
}

func testAntreaIPAMTraceflowIntraNode(t *testing.T, data *TestData, podInfos []PodInfo, liveTraffic bool) {
	ipamSrcPodDeniedReason := ""
	if !liveTraffic {
		ipamSrcPodDeniedReason = "using FlexibleIPAM Pod as source in non-live-traffic Traceflow is not supported"
	}
	podIPs := waitForPodIPs(t, data, podInfos)
	testcases := []testcase{}

	namePostfix := "-ipam-ipam"
	srcPodInfo := podInfos[0]
	dstPodInfo := podInfos[1]
	srcPodIP := podIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, true, ipamSrcPodDeniedReason))

	namePostfix = "-ipam-regular"
	srcPodInfo = podInfos[0]
	dstPodInfo = podInfos[2]
	srcPodIP = podIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, true, ipamSrcPodDeniedReason))

	namePostfix = "-regular-ipam"
	srcPodInfo = podInfos[2]
	dstPodInfo = podInfos[0]
	srcPodIP = podIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, true, ""))

	t.Run("traceflowGroupTest", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestTraceflow(t, data, tc)
			})
		}
	})
}

func testAntreaIPAMPodConnectivityDifferentNodes(t *testing.T, data *TestData) {
	maxNodes := 3
	var PodInfos []PodInfo
	var allPodInfos []PodInfo
	for _, namespace := range []string{data.testNamespace, testAntreaIPAMNamespace, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12} {
		createdPodInfos, deletePods := createPodsOnDifferentNodes(t, data, namespace, "differentnodes")
		defer deletePods()
		allPodInfos = append(allPodInfos, createdPodInfos...)
		if len(createdPodInfos) > maxNodes {
			createdPodInfos = createdPodInfos[:maxNodes]
		}
		PodInfos = append(PodInfos, createdPodInfos...)
	}

	testAntreaIPAMTraceflowInterNode(t, data, allPodInfos, false)
	testAntreaIPAMTraceflowInterNode(t, data, allPodInfos, true)

	data.runPingMesh(t, PodInfos, toolboxContainerName, true)
}

func testAntreaIPAMTraceflowInterNode(t *testing.T, data *TestData, podInfos []PodInfo, liveTraffic bool) {
	ipamSrcPodDeniedReason := ""
	if !liveTraffic {
		ipamSrcPodDeniedReason = "using FlexibleIPAM Pod as source in non-live-traffic Traceflow is not supported"
	}
	nodeCount := len(podInfos) / 4
	regularPodInfos := podInfos[0:nodeCount]
	ipamPodInfos := podInfos[nodeCount : nodeCount*2]
	ns11PodInfos := podInfos[nodeCount*2 : nodeCount*3]
	ns12PodInfos := podInfos[nodeCount*3 : nodeCount*4]

	regularPodIPs := waitForPodIPs(t, data, regularPodInfos)
	ipamPodIPs := waitForPodIPs(t, data, ipamPodInfos)
	ns11PodIPs := waitForPodIPs(t, data, ns11PodInfos)
	var testcases []testcase

	namePostfix := "-ipam-ipam"
	srcPodInfo := ipamPodInfos[0]
	dstPodInfo := ipamPodInfos[1]
	srcPodIP := ipamPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-ipam-regular"
	srcPodInfo = ipamPodInfos[0]
	dstPodInfo = regularPodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = regularPodInfos[1]
	}
	srcPodIP = ipamPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-ipam-vlan11-diff"
	srcPodInfo = ipamPodInfos[0]
	dstPodInfo = ns11PodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = ns11PodInfos[1]
	}
	srcPodIP = ipamPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-ipam-vlan11-same"
	srcPodInfo = ipamPodInfos[0]
	for _, podInfo := range ns11PodInfos {
		if podInfo.NodeName == srcPodInfo.NodeName {
			dstPodInfo = podInfo
			break
		}
	}
	srcPodIP = ipamPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	t.Run("traceflowGroupTest1", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestTraceflow(t, data, tc)
			})
		}
	})
	testcases = []testcase{}

	namePostfix = "-vlan11-ipam-diff"
	srcPodInfo = ns11PodInfos[0]
	dstPodInfo = ipamPodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = ipamPodInfos[1]
	}
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-vlan11-ipam-same"
	srcPodInfo = ns11PodInfos[0]
	for _, podInfo := range ipamPodInfos {
		if podInfo.NodeName == srcPodInfo.NodeName {
			dstPodInfo = podInfo
			break
		}
	}
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-vlan11-regular-diff"
	srcPodInfo = ns11PodInfos[0]
	dstPodInfo = regularPodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = regularPodInfos[1]
	}
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-vlan11-regular-same"
	srcPodInfo = ns11PodInfos[0]
	for _, podInfo := range regularPodInfos {
		if podInfo.NodeName == srcPodInfo.NodeName {
			dstPodInfo = podInfo
			break
		}
	}
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-vlan11-vlan11"
	srcPodInfo = ns11PodInfos[0]
	dstPodInfo = ns11PodInfos[1]
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-vlan11-vlan12-diff"
	srcPodInfo = ns11PodInfos[0]
	dstPodInfo = ns12PodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = ns12PodInfos[1]
	}
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	namePostfix = "-vlan11-vlan12-same"
	srcPodInfo = ns11PodInfos[0]
	for _, podInfo := range ns12PodInfos {
		if podInfo.NodeName == srcPodInfo.NodeName {
			dstPodInfo = podInfo
			break
		}
	}
	srcPodIP = ns11PodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ipamSrcPodDeniedReason))

	t.Run("traceflowGroupTest2", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestTraceflow(t, data, tc)
			})
		}
	})
	testcases = []testcase{}

	namePostfix = "-regular-ipam"
	srcPodInfo = regularPodInfos[0]
	dstPodInfo = ipamPodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = ipamPodInfos[1]
	}
	srcPodIP = regularPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ""))

	namePostfix = "-regular-vlan11-diff"
	srcPodInfo = regularPodInfos[0]
	dstPodInfo = ns11PodInfos[0]
	if dstPodInfo.NodeName == srcPodInfo.NodeName {
		dstPodInfo = ns11PodInfos[1]
	}
	srcPodIP = regularPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ""))

	namePostfix = "-regular-vlan11-same"
	srcPodInfo = regularPodInfos[0]
	for _, podInfo := range ns11PodInfos {
		if podInfo.NodeName == srcPodInfo.NodeName {
			dstPodInfo = podInfo
			break
		}
	}
	srcPodIP = regularPodIPs[srcPodInfo.Name].IPv4.String()
	testcases = append(testcases, buildAntreaIPAMTraceflowTestCase(namePostfix, srcPodInfo, dstPodInfo, srcPodIP, liveTraffic, false, ""))

	t.Run("traceflowGroupTest3", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestTraceflow(t, data, tc)
			})
		}
	})
}

func buildAntreaIPAMTraceflowTestCase(postfix string, srcPodInfo PodInfo, dstPodInfo PodInfo, srcPodIP string, liveTraffic bool, intraNode bool, deniedReason string) testcase {
	prefix := "inter"
	if intraNode {
		prefix = "intra"
	}
	transportProtocol := "TCP"
	liveTrafficString := ""
	if liveTraffic {
		transportProtocol = "ICMP"
		liveTrafficString = "Live"
	}
	ipProtocol := "IPv4"
	name := fmt.Sprintf("%sNode%sDstPod%sTraceflow%s%s", prefix, transportProtocol, liveTrafficString, ipProtocol, postfix)

	packet := crdv1beta1.Packet{}
	if !liveTraffic {
		packet = crdv1beta1.Packet{
			IPHeader: &crdv1beta1.IPHeader{
				Protocol: protocolTCP,
			},
			TransportHeader: crdv1beta1.TransportHeader{
				TCP: &crdv1beta1.TCPHeader{
					DstPort: 80,
					SrcPort: 10003,
					Flags:   &tcpFlags,
				},
			},
		}
	}
	expectedResults := []crdv1beta1.NodeResult{
		{
			Node: srcPodInfo.NodeName,
			Observations: []crdv1beta1.Observation{
				{
					Component: crdv1beta1.ComponentSpoofGuard,
					Action:    crdv1beta1.ActionForwarded,
					SrcPodIP:  srcPodIP,
				},
				{
					Component:     crdv1beta1.ComponentForwarding,
					ComponentInfo: "Output",
					Action:        crdv1beta1.ActionForwarded,
				},
			},
		},
		{
			Node: dstPodInfo.NodeName,
			Observations: []crdv1beta1.Observation{
				{
					Component: crdv1beta1.ComponentForwarding,
					Action:    crdv1beta1.ActionReceived,
				},
				{
					Component:     crdv1beta1.ComponentForwarding,
					ComponentInfo: "Output",
					Action:        crdv1beta1.ActionDelivered,
				},
			},
		},
	}
	if intraNode {
		expectedResults = []crdv1beta1.NodeResult{
			{
				Node: srcPodInfo.NodeName,
				Observations: []crdv1beta1.Observation{
					{
						Component: crdv1beta1.ComponentSpoofGuard,
						Action:    crdv1beta1.ActionForwarded,
						SrcPodIP:  srcPodIP,
					},
					{
						Component:     crdv1beta1.ComponentForwarding,
						ComponentInfo: "Output",
						Action:        crdv1beta1.ActionDelivered,
					},
				},
			},
		}
	}
	if deniedReason != "" {
		expectedResults = nil
	}
	return testcase{
		name:      name,
		ipVersion: 4,
		tf: &crdv1beta1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{
				Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", srcPodInfo.Namespace, srcPodInfo.Name, dstPodInfo.Namespace, dstPodInfo.Name)),
			},
			Spec: crdv1beta1.TraceflowSpec{
				Source: crdv1beta1.Source{
					Namespace: srcPodInfo.Namespace,
					Pod:       srcPodInfo.Name,
				},
				Destination: crdv1beta1.Destination{
					Namespace: dstPodInfo.Namespace,
					Pod:       dstPodInfo.Name,
				},
				Packet:      packet,
				LiveTraffic: liveTraffic,
			},
		},
		expectedPhase:   crdv1beta1.Succeeded,
		expectedResults: expectedResults,
		containerName:   toolboxContainerName,
		deniedReason:    deniedReason,
	}
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
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, ipOffsets, reservedIPOffsets)

	ipOffsets = []int32{0}
	size = len(ipOffsets)
	_, err = data.updateStatefulSetSize(stsName, testAntreaIPAMNamespace, int32(size))
	if err != nil {
		t.Fatalf("Error when updating StatefulSet '%s': %v", stsName, err)
	}
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, ipOffsets, reservedIPOffsets)

	stsName2 := randName("sts-test-")
	ipOffsets = []int32{3}
	size = len(ipOffsets)
	reservedIPOffsets = ipOffsets
	startIPString := subnetIPv4RangesMap[testAntreaIPAMNamespace].Spec.IPRanges[0].Start
	offset := int(ipOffsets[0])
	if dedicatedIPPoolKey != nil {
		startIPString = subnetIPv4RangesMap[*dedicatedIPPoolKey].Spec.IPRanges[0].Start
	}
	expectedPodIP := utilnet.AddIPOffset(utilnet.BigForIP(net.ParseIP(startIPString)), offset)
	mutateFunc = func(sts *appsv1.StatefulSet) {
		if sts.Spec.Template.Annotations == nil {
			sts.Spec.Template.Annotations = map[string]string{}
		}
		if dedicatedIPPoolKey != nil {
			sts.Spec.Template.Annotations[annotation.AntreaIPAMAnnotationKey] = ipPoolName
		}
		sts.Spec.Template.Annotations[annotation.AntreaIPAMPodIPAnnotationKey] = expectedPodIP.String()
	}
	_, cleanup2, err := data.createStatefulSet(stsName2, testAntreaIPAMNamespace, int32(size), agnhostContainerName, agnhostImage, []string{"sleep", "3600"}, nil, mutateFunc)
	if err != nil {
		t.Fatalf("Error when creating StatefulSet '%s': %v", stsName2, err)
	}
	defer cleanup2()
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName2, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName2, testAntreaIPAMNamespace, ipPoolName, ipOffsets, reservedIPOffsets)

	podName := randName("test-standalone-pod-")
	podAnnotations := map[string]string{}
	if dedicatedIPPoolKey != nil {
		podAnnotations[annotation.AntreaIPAMAnnotationKey] = ipPoolName
	}
	err = NewPodBuilder(podName, testAntreaIPAMNamespace, agnhostImage).OnNode(controlPlaneNodeName()).WithAnnotations(podAnnotations).Create(data)
	if err != nil {
		t.Fatalf("Error when creating Pod '%s': %v", podName, err)
	}
	defer data.DeletePodAndWait(defaultTimeout, podName, testAntreaIPAMNamespace)
	podIPs, err := data.podWaitForIPs(defaultTimeout, podName, testAntreaIPAMNamespace)
	if err != nil {
		t.Fatalf("Error when waiting Pod IPs: %v", err)
	}
	isBelongTo, ipAddressState, err := checkIPPoolAllocation(t, data, ipPoolName, podIPs.IPv4.String())
	if err != nil {
		t.Fatalf("Error when checking IPPoolAllocation: %v", err)
	}
	startIPString = subnetIPv4RangesMap[testAntreaIPAMNamespace].Spec.IPRanges[0].Start
	offset = 2
	if dedicatedIPPoolKey != nil {
		startIPString = subnetIPv4RangesMap[*dedicatedIPPoolKey].Spec.IPRanges[0].Start
	}
	expectedPodIP = utilnet.AddIPOffset(utilnet.BigForIP(net.ParseIP(startIPString)), offset)
	assert.True(t, isBelongTo)
	assert.True(t, reflect.DeepEqual(ipAddressState, &crdv1beta1.IPAddressState{
		IPAddress: expectedPodIP.String(),
		Phase:     crdv1beta1.IPAddressPhaseAllocated,
		Owner: crdv1beta1.IPAddressOwner{
			Pod: &crdv1beta1.PodOwner{
				Name:        podName,
				Namespace:   testAntreaIPAMNamespace,
				ContainerID: ipAddressState.Owner.Pod.ContainerID,
			},
		},
	}))

	ipOffsets = []int32{0, 1, 4}
	size = len(ipOffsets)
	reservedIPOffsets = ipOffsets
	_, err = data.updateStatefulSetSize(stsName, testAntreaIPAMNamespace, int32(size))
	if err != nil {
		t.Fatalf("Error when updating StatefulSet '%s': %v", stsName, err)
	}
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, ipOffsets, reservedIPOffsets)

	data.DeletePodAndWait(defaultTimeout, podName, testAntreaIPAMNamespace)
	_, err = data.restartStatefulSet(stsName, testAntreaIPAMNamespace)
	if err != nil {
		t.Fatalf("Error when restarting StatefulSet '%s': %v", stsName, err)
	}
	time.Sleep(time.Second)
	if err := data.waitForStatefulSetPods(defaultTimeout, stsName, testAntreaIPAMNamespace); err != nil {
		t.Fatalf("Error when waiting for StatefulSet Pods to get IPs: %v", err)
	}
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, ipOffsets, reservedIPOffsets)

	cleanup()
	checkStatefulSetIPPoolAllocation(t, data, stsName, testAntreaIPAMNamespace, ipPoolName, nil, nil)

	cleanup2()
	checkStatefulSetIPPoolAllocation(t, data, stsName2, testAntreaIPAMNamespace, ipPoolName, nil, nil)
}

func checkStatefulSetIPPoolAllocation(tb testing.TB, data *TestData, name string, namespace string, ipPoolName string, ipOffsets, reservedIPOffsets []int32) {
	ipPool, err := data.CRDClient.CrdV1beta1().IPPools().Get(context.TODO(), ipPoolName, metav1.GetOptions{})
	if err != nil {
		tb.Fatalf("Failed to get IPPool %s, err: %+v", ipPoolName, err)
	}
	startIP := net.ParseIP(ipPool.Spec.IPRanges[0].Start)
	expectedIPAddressMap := map[string]*crdv1beta1.IPAddressState{}
	for i, offset := range ipOffsets {
		ipString := utilnet.AddIPOffset(utilnet.BigForIP(startIP), int(offset)).String()
		podName := fmt.Sprintf("%s-%d", name, i)
		expectedIPAddressMap[ipString] = &crdv1beta1.IPAddressState{
			IPAddress: ipString,
			Phase:     crdv1beta1.IPAddressPhaseAllocated,
			Owner: crdv1beta1.IPAddressOwner{
				Pod: &crdv1beta1.PodOwner{
					Name:        podName,
					Namespace:   namespace,
					ContainerID: "",
				},
			},
		}
	}
	for i, offset := range reservedIPOffsets {
		ipString := utilnet.AddIPOffset(utilnet.BigForIP(startIP), int(offset)).String()
		stsOwner := &crdv1beta1.StatefulSetOwner{
			Name:      name,
			Namespace: namespace,
			Index:     i,
		}
		if _, ok := expectedIPAddressMap[ipString]; ok {
			expectedIPAddressMap[ipString].Owner.StatefulSet = stsOwner
		} else {
			expectedIPAddressMap[ipString] = &crdv1beta1.IPAddressState{
				IPAddress: ipString,
				Phase:     crdv1beta1.IPAddressPhaseReserved,
				Owner: crdv1beta1.IPAddressOwner{
					StatefulSet: stsOwner,
				},
			}
		}
	}
	expectedIPAddressJson, _ := json.Marshal(expectedIPAddressMap)
	tb.Logf("expectedIPAddressMap: %s", expectedIPAddressJson)

	err = wait.PollUntilContextTimeout(context.Background(), time.Second*3, time.Second*15, false, func(ctx context.Context) (bool, error) {
		ipPool, err := data.CRDClient.CrdV1beta1().IPPools().Get(context.TODO(), ipPoolName, metav1.GetOptions{})
		if err != nil {
			tb.Fatalf("Failed to get IPPool %s, err: %+v", ipPoolName, err)
		}
		actualIPAddressMap := map[string]*crdv1beta1.IPAddressState{}
	actualIPAddressLoop:
		for i, ipAddress := range ipPool.Status.IPAddresses {
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
				actualIPAddressMap[ipAddress.IPAddress] = &ipPool.Status.IPAddresses[i]
				continue
			}
			if ipAddress.Owner.StatefulSet != nil && ipAddress.Owner.StatefulSet.Namespace == namespace && ipAddress.Owner.StatefulSet.Name == name {
				actualIPAddressMap[ipAddress.IPAddress] = &ipPool.Status.IPAddresses[i]
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

func createIPPool(tb testing.TB, data *TestData, key string) (*crdv1beta1.IPPool, error) {
	ipv4IPPool := subnetIPv4RangesMap[key]
	tb.Logf("Creating IPPool '%s'", ipv4IPPool.Name)
	return data.CRDClient.CrdV1beta1().IPPools().Create(context.TODO(), &ipv4IPPool, metav1.CreateOptions{})
}

func checkIPPoolAllocation(tb testing.TB, data *TestData, ipPoolName, podIPString string) (isBelongTo bool, ipAddressState *crdv1beta1.IPAddressState, err error) {
	ipPool, err := data.CRDClient.CrdV1beta1().IPPools().Get(context.TODO(), ipPoolName, metav1.GetOptions{})
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
	for i := 0; i < 10; i++ {
		if err := data.CRDClient.CrdV1beta1().IPPools().Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
			ipPool, _ := data.CRDClient.CrdV1beta1().IPPools().Get(context.TODO(), name, metav1.GetOptions{})
			ipPoolJson, _ := json.Marshal(ipPool)
			tb.Logf("Error when deleting IPPool, err: %v, data: %s", err, ipPoolJson)
			time.Sleep(defaultInterval)
		} else {
			break
		}
	}
}

func checkIPPoolsEmpty(tb testing.TB, data *TestData, names []string) {
	count := 0
	err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, defaultTimeout, true, func(ctx context.Context) (bool, error) {
		for _, name := range names {
			ipPool, _ := data.CRDClient.CrdV1beta1().IPPools().Get(context.TODO(), name, metav1.GetOptions{})
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
