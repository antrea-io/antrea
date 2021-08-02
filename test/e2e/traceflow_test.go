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
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

type testcase struct {
	name            string
	tf              *v1alpha1.Traceflow
	expectedPhase   v1alpha1.TraceflowPhase
	expectedResults []v1alpha1.NodeResult
	expectedPktCap  *v1alpha1.Packet
	// required IP version, skip if not match, default is 0 (no restrict)
	ipVersion  int
	skipReason string
	// Source Pod to run ping for live-traffic Traceflow.
	srcPod string
}

// TestTraceflow is the top-level test which contains all subtests for
// Traceflow related test cases so they can share setup, teardown.
func TestTraceflow(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfTraceflowDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testTraceflowIntraNodeANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		testTraceflowIntraNodeANP(t, data)
	})
	t.Run("testTraceflowIntraNode", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		testTraceflowIntraNode(t, data)
	})
	t.Run("testTraceflowInterNode", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testTraceflowInterNode(t, data)
	})
	t.Run("testTraceflowExternalIP", func(t *testing.T) {
		skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)
		testTraceflowExternalIP(t, data)
	})
}

func skipIfTraceflowDisabled(t *testing.T) {
	skipIfFeatureDisabled(t, features.Traceflow, true, true)
}

var (
	protocolICMP   = int32(1)
	protocolTCP    = int32(6)
	protocolUDP    = int32(17)
	protocolICMPv6 = int32(58)
)

// testTraceflowIntraNodeANP verifies if traceflow can trace intra node traffic with some Antrea NetworkPolicy sets.
func testTraceflowIntraNodeANP(t *testing.T, data *TestData) {
	var err error
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)

	node1 := nodeName(0)
	node1Pods, _, node1CleanupFn := createTestBusyboxPods(t, data, 3, testNamespace, node1)
	defer node1CleanupFn()

	var denyIngress *v1alpha1.NetworkPolicy
	denyIngressName := "test-anp-deny-ingress"
	if denyIngress, err = data.createANPDenyIngress("antrea-e2e", node1Pods[1], denyIngressName, false); err != nil {
		t.Fatalf("Error when creating Antrea NetworkPolicy: %v", err)
	}
	defer func() {
		if err = data.deleteAntreaNetworkpolicy(denyIngress); err != nil {
			t.Errorf("Error when deleting Antrea NetworkPolicy: %v", err)
		}
	}()
	var rejectIngress *v1alpha1.NetworkPolicy
	rejectIngressName := "test-anp-reject-ingress"
	if rejectIngress, err = data.createANPDenyIngress("antrea-e2e", node1Pods[2], rejectIngressName, true); err != nil {
		t.Fatalf("Error when creating Antrea NetworkPolicy: %v", err)
	}
	defer func() {
		if err = data.deleteAntreaNetworkpolicy(rejectIngress); err != nil {
			t.Errorf("Error when deleting Antrea NetworkPolicy: %v", err)
		}
	}()
	antreaPod, err := data.getAntreaPodOnNode(node1)
	if err = data.waitForNetworkpolicyRealized(antreaPod, denyIngressName, v1beta2.AntreaNetworkPolicy); err != nil {
		t.Fatal(err)
	}

	testcases := []testcase{
		{
			name:      "ANPDenyIngressIPv4",
			ipVersion: 4,
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
							Protocol: protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressMetric",
							Action:        v1alpha1.ActionDropped,
						},
					},
				},
			},
		},
		{
			name:      "ANPRejectIngressIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", testNamespace, node1Pods[0], testNamespace, node1Pods[2])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       node1Pods[2],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressMetric",
							Action:        v1alpha1.ActionRejected,
						},
					},
				},
			},
		},
		{
			name:      "ANPDenyIngressIPv6",
			ipVersion: 6,
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
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressMetric",
							Action:        v1alpha1.ActionDropped,
						},
					},
				},
			},
		},
	}
	t.Run("traceflowANPGroupTest", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runTestTraceflow(t, data, tc)
			})
		}
	})
}

// testTraceflowIntraNode verifies if traceflow can trace intra node traffic with some NetworkPolicies set.
func testTraceflowIntraNode(t *testing.T, data *TestData) {
	node1 := nodeName(0)

	node1Pods, node1IPs, node1CleanupFn := createTestBusyboxPods(t, data, 3, testNamespace, node1)
	defer node1CleanupFn()
	var pod0IPv4Str, pod1IPv4Str, dstPodIPv4Str, dstPodIPv6Str string
	if node1IPs[0].ipv4 != nil {
		pod0IPv4Str = node1IPs[0].ipv4.String()
	}
	if node1IPs[1].ipv4 != nil {
		pod1IPv4Str = node1IPs[1].ipv4.String()
	}
	if node1IPs[2].ipv4 != nil {
		dstPodIPv4Str = node1IPs[2].ipv4.String()
	}
	if node1IPs[2].ipv6 != nil {
		dstPodIPv6Str = node1IPs[2].ipv6.String()
	}
	gwIPv4Str, gwIPv6Str := nodeGatewayIPs(0)

	// Setup 2 NetworkPolicies:
	// 1. Allow all egress traffic.
	// 2. Deny ingress traffic on pod with label antrea-e2e = node1Pods[1]. So flow node1Pods[0] -> node1Pods[1] will be dropped.
	var allowAllEgress *networkingv1.NetworkPolicy
	var err error
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
	if err = data.waitForNetworkpolicyRealized(antreaPod, allowAllEgressName, v1beta2.K8sNetworkPolicy); err != nil {
		t.Fatal(err)
	}
	if err = data.waitForNetworkpolicyRealized(antreaPod, denyAllIngressName, v1beta2.K8sNetworkPolicy); err != nil {
		t.Fatal(err)
	}

	testcases := []testcase{
		{
			name:      "intraNodeTraceflowIPv4",
			ipVersion: 4,
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
							Protocol: protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressDefaultRule",
							Action:        v1alpha1.ActionDropped,
						},
					},
				},
			},
		},
		{
			name:      "intraNodeUDPDstPodTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], node1Pods[2])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       node1Pods[2],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolUDP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "intraNodeUDPDstIPTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], dstPodIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv4Str,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolUDP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "intraNodeICMPDstIPTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], dstPodIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv4Str,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolICMP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "nonExistingDstPodIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", testNamespace, node1Pods[0], testNamespace, "non-existing-pod")),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       "non-existing-pod",
					},
				},
			},
			expectedPhase: v1alpha1.Failed,
		},
		{
			name:      "intraNodeICMPDstIPLiveTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], dstPodIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv4Str,
					},
					LiveTraffic: true,
				},
			},
			srcPod:        node1Pods[0],
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
			expectedPktCap: &v1alpha1.Packet{
				SrcIP:    pod0IPv4Str,
				DstIP:    dstPodIPv4Str,
				Length:   84, // default ping packet length.
				IPHeader: v1alpha1.IPHeader{Protocol: 1, TTL: 64, Flags: 2},
				TransportHeader: v1alpha1.TransportHeader{
					ICMP: &v1alpha1.ICMPEchoRequestHeader{},
				},
			},
		},
		{
			name:      "intraNodeICMPSrcIPDroppedTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], dstPodIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						IP: pod0IPv4Str,
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       node1Pods[1],
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolICMP,
						},
					},
					LiveTraffic: true,
					DroppedOnly: true,
				},
			},
			srcPod:        node1Pods[0],
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressDefaultRule",
							Action:        v1alpha1.ActionDropped,
						},
					},
				},
			},
			expectedPktCap: &v1alpha1.Packet{
				SrcIP:    pod0IPv4Str,
				DstIP:    pod1IPv4Str,
				Length:   84, // default ping packet length.
				IPHeader: v1alpha1.IPHeader{Protocol: 1, TTL: 64, Flags: 2},
				TransportHeader: v1alpha1.TransportHeader{
					ICMP: &v1alpha1.ICMPEchoRequestHeader{},
				},
			},
		},
		{
			name:      "intraNodeTraceflowIPv6",
			ipVersion: 6,
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
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressDefaultRule",
							Action:        v1alpha1.ActionDropped,
						},
					},
				},
			},
		},
		{
			name:      "intraNodeUDPDstPodTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], node1Pods[2])),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       node1Pods[2],
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolUDP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "intraNodeUDPDstIPTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], strings.ReplaceAll(dstPodIPv6Str, ":", "--"))),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv6Str,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolUDP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "intraNodeICMPDstIPTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], strings.ReplaceAll(dstPodIPv6Str, ":", "--"))),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv6Str,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "nonExistingDstPodIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", testNamespace, node1Pods[0], testNamespace, "non-existing-pod")),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Pod:       "non-existing-pod",
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
						},
					},
				},
			},
			expectedPhase: v1alpha1.Failed,
		},
		{
			name:      "intraNodeICMPDstIPLiveTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], strings.ReplaceAll(dstPodIPv6Str, ":", "--"))),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv6Str,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
						},
					},
					LiveTraffic: true,
				},
			},
			srcPod:        node1Pods[0],
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
	}

	if gwIPv4Str != "" {
		testcases = append(testcases, testcase{
			name:      "localGatewayDestinationIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], gwIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: gwIPv4Str,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolICMP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		})
	}

	if gwIPv6Str != "" {
		testcases = append(testcases, testcase{
			name:      "localGatewayDestinationIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], strings.ReplaceAll(gwIPv6Str, ":", "--"))),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: gwIPv6Str,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		})
	}

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

// testTraceflowInterNode verifies if traceflow can trace inter nodes traffic with some NetworkPolicies set.
func testTraceflowInterNode(t *testing.T, data *TestData) {
	encapMode, err := data.GetEncapMode()
	if err != nil {
		t.Fatalf("Failed to retrieve encap mode: %v", err)
	}
	if encapMode != config.TrafficEncapModeNoEncap {
		// https://github.com/antrea-io/antrea/issues/897
		skipIfProviderIs(t, "kind", "Skipping inter-Node Traceflow test for Kind because of #897")
	}

	node1 := nodeName(0)
	node2 := nodeName(1)

	node1Pods, _, node1CleanupFn := createTestBusyboxPods(t, data, 1, testNamespace, node1)
	node2Pods, node2IPs, node2CleanupFn := createTestBusyboxPods(t, data, 2, testNamespace, node2)
	defer node1CleanupFn()
	defer node2CleanupFn()
	var dstPodIPv4Str, dstPodIPv6Str string
	if node2IPs[0].ipv4 != nil {
		dstPodIPv4Str = node2IPs[0].ipv4.String()
	}
	if node2IPs[0].ipv6 != nil {
		dstPodIPv6Str = node2IPs[0].ipv6.String()
	}

	// Create Service backend Pod. The "hairpin" testcases require the Service to have a single backend Pod,
	// and no more, in order to be deterministic.
	nginxPodName := "nginx"
	require.NoError(t, data.createNginxPodOnNode(nginxPodName, testNamespace, node2))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginxPodName, testNamespace)
	require.NoError(t, err)

	var nginxIPv4Str, nginxIPv6Str, svcIPv4Name, svcIPv6Name string
	if nginxIP.ipv4 != nil {
		nginxIPv4Str = nginxIP.ipv4.String()
		ipv4Protocol := corev1.IPv4Protocol
		svcIPv4, err := data.createNginxClusterIPService("nginx-ipv4", false, &ipv4Protocol)
		require.NoError(t, err)
		svcIPv4Name = svcIPv4.Name
	}
	if nginxIP.ipv6 != nil {
		nginxIPv6Str = nginxIP.ipv6.String()
		ipv6Protocol := corev1.IPv6Protocol
		svcIPv6, err := data.createNginxClusterIPService("nginx-ipv6", false, &ipv6Protocol)
		require.NoError(t, err)
		svcIPv6Name = svcIPv6.Name
	}

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
	if denyAllIngress, err = data.createNPDenyAllIngress("antrea-e2e", node2Pods[1], denyAllIngressName); err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(denyAllIngress); err != nil {
			t.Errorf("Error when deleting network policy: %v", err)
		}
	}()

	antreaPod, err := data.getAntreaPodOnNode(node2)
	if err = data.waitForNetworkpolicyRealized(antreaPod, allowAllEgressName, v1beta2.K8sNetworkPolicy); err != nil {
		t.Fatal(err)
	}
	if err = data.waitForNetworkpolicyRealized(antreaPod, denyAllIngressName, v1beta2.K8sNetworkPolicy); err != nil {
		t.Fatal(err)
	}

	testcases := []testcase{
		{
			name:      "interNodeTraceflowIPv4",
			ipVersion: 4,
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
							Protocol: protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "interNodeUDPDstIPTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], dstPodIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv4Str,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolUDP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "interNodeICMPDstIPTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], dstPodIPv4Str)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv4Str,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolICMP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "serviceTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-svc-%s-", testNamespace, node1Pods[0], svcIPv4Name)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Service:   svcIPv4Name,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:       v1alpha1.ComponentLB,
							Pod:             fmt.Sprintf("%s/%s", testNamespace, nginxPodName),
							TranslatedDstIP: nginxIPv4Str,
							Action:          v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "hairpinServiceTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-svc-%s-", testNamespace, nginxPodName, svcIPv4Name)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       nginxPodName,
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Service:   svcIPv4Name,
					},
					Packet: v1alpha1.Packet{
						IPHeader: v1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
							},
						},
					},
				},
			},
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:       v1alpha1.ComponentLB,
							Pod:             fmt.Sprintf("%s/%s", testNamespace, nginxPodName),
							TranslatedSrcIP: "169.254.169.252",
							TranslatedDstIP: nginxIPv4Str,
							Action:          v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "interNodeICMPDstPodLiveTraceflowIPv4",
			ipVersion: 4,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], node2Pods[0])),
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
					LiveTraffic: true,
				},
			},
			srcPod:        node1Pods[0],
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "interNodeTraceflowIPv6",
			ipVersion: 6,
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
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:       "interNodeUDPDstIPTraceflowIPv6",
			skipReason: "IPv6 testbed issue prevents running this test, we suspect an ESX datapath issue",
			ipVersion:  6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], strings.ReplaceAll(dstPodIPv6Str, ":", "--"))),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv6Str,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolUDP,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "interNodeICMPDstIPTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], strings.ReplaceAll(dstPodIPv6Str, ":", "--"))),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						IP: dstPodIPv6Str,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "serviceTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-svc-%s-", testNamespace, node1Pods[0], svcIPv6Name)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Service:   svcIPv6Name,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
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
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:       v1alpha1.ComponentLB,
							Pod:             fmt.Sprintf("%s/%s", testNamespace, nginxPodName),
							TranslatedDstIP: nginxIPv6Str,
							Action:          v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "hairpinServiceTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-svc-%s-", testNamespace, nginxPodName, svcIPv6Name)),
				},
				Spec: v1alpha1.TraceflowSpec{
					Source: v1alpha1.Source{
						Namespace: testNamespace,
						Pod:       nginxPodName,
					},
					Destination: v1alpha1.Destination{
						Namespace: testNamespace,
						Service:   svcIPv6Name,
					},
					Packet: v1alpha1.Packet{
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: 80,
								Flags:   2,
							},
						},
					},
				},
			},
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:       v1alpha1.ComponentLB,
							Pod:             fmt.Sprintf("%s/%s", testNamespace, nginxPodName),
							TranslatedSrcIP: "fc00::aabb:ccdd:eeff",
							TranslatedDstIP: nginxIPv6Str,
							Action:          v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
						},
					},
				},
			},
		},
		{
			name:      "interNodeICMPDstPodLiveTraceflowIPv6",
			ipVersion: 6,
			tf: &v1alpha1.Traceflow{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-", testNamespace, node1Pods[0], node2Pods[0])),
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
						IPv6Header: &v1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
						},
					},
					LiveTraffic: true,
				},
			},
			srcPod:        node1Pods[0],
			expectedPhase: v1alpha1.Succeeded,
			expectedResults: []v1alpha1.NodeResult{
				{
					Node: node1,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentSpoofGuard,
							Action:    v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "EgressRule",
							Action:        v1alpha1.ActionForwarded,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionForwarded,
						},
					},
				},
				{
					Node: node2,
					Observations: []v1alpha1.Observation{
						{
							Component: v1alpha1.ComponentForwarding,
							Action:    v1alpha1.ActionReceived,
						},
						{
							Component:     v1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							Action:        v1alpha1.ActionDelivered,
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
				runTestTraceflow(t, data, tc)
			})
		}
	})
}

func testTraceflowExternalIP(t *testing.T, data *TestData) {
	node := nodeName(0)
	nodeIP := nodeIP(0)
	podNames, _, cleanupFn := createTestBusyboxPods(t, data, 1, testNamespace, node)
	defer cleanupFn()

	testcase := testcase{
		name:      "nodeIPDestination",
		ipVersion: 4,
		tf: &v1alpha1.Traceflow{
			ObjectMeta: metav1.ObjectMeta{
				Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", testNamespace, podNames[0], testNamespace, strings.ReplaceAll(nodeIP, ":", "--"))),
			},
			Spec: v1alpha1.TraceflowSpec{
				Source: v1alpha1.Source{
					Namespace: testNamespace,
					Pod:       podNames[0],
				},
				Destination: v1alpha1.Destination{
					IP: nodeIP,
				},
				Packet: v1alpha1.Packet{
					IPHeader: v1alpha1.IPHeader{
						Protocol: protocolICMP,
					},
				},
			},
		},
		expectedPhase: v1alpha1.Succeeded,
		expectedResults: []v1alpha1.NodeResult{
			{
				Node: node,
				Observations: []v1alpha1.Observation{
					{
						Component: v1alpha1.ComponentSpoofGuard,
						Action:    v1alpha1.ActionForwarded,
					},
					{
						Component:     v1alpha1.ComponentForwarding,
						ComponentInfo: "Output",
						Action:        v1alpha1.ActionForwardedOutOfOverlay,
					},
				},
			},
		},
	}

	runTestTraceflow(t, data, testcase)
}

func (data *TestData) waitForTraceflow(t *testing.T, name string, phase v1alpha1.TraceflowPhase) (*v1alpha1.Traceflow, error) {
	var tf *v1alpha1.Traceflow
	var err error
	timeout := 15 * time.Second
	if err = wait.PollImmediate(defaultInterval, timeout, func() (bool, error) {
		tf, err = data.crdClient.CrdV1alpha1().Traceflows().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil || tf.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		if tf != nil {
			t.Errorf("Latest Traceflow status: %v", tf.Status)
		}
		return nil, err
	}
	return tf, nil
}

// compareObservations compares expected results and actual results.
func compareObservations(expected v1alpha1.NodeResult, actual v1alpha1.NodeResult) error {
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
			exObs[i].Pod != acObs[i].Pod ||
			exObs[i].TranslatedDstIP != acObs[i].TranslatedDstIP ||
			exObs[i].Action != acObs[i].Action {
			return fmt.Errorf("Observations should be %v, but got %v", exObs, acObs)
		}
	}
	return nil
}

// createANPDenyIngress creates an Antrea NetworkPolicy that denies ingress traffic for pods of specific label.
func (data *TestData) createANPDenyIngress(key string, value string, name string, isReject bool) (*v1alpha1.NetworkPolicy, error) {
	dropACT := v1alpha1.RuleActionDrop
	if isReject {
		dropACT = v1alpha1.RuleActionReject
	}
	anp := v1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-e2e": name,
			},
		},
		Spec: v1alpha1.NetworkPolicySpec{
			Tier:     defaultTierName,
			Priority: 250,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							key: value,
						},
					},
				},
			},
			Ingress: []v1alpha1.Rule{
				{
					Action: &dropACT,
					Ports:  []v1alpha1.NetworkPolicyPort{},
					From:   []v1alpha1.NetworkPolicyPeer{},
					To:     []v1alpha1.NetworkPolicyPeer{},
				},
			},
			Egress: []v1alpha1.Rule{},
		},
	}
	anpCreated, err := k8sUtils.crdClient.CrdV1alpha1().NetworkPolicies(testNamespace).Create(context.TODO(), &anp, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return anpCreated, nil
}

// deleteAntreaNetworkpolicy deletes an Antrea NetworkPolicy.
func (data *TestData) deleteAntreaNetworkpolicy(policy *v1alpha1.NetworkPolicy) error {
	if err := k8sUtils.crdClient.CrdV1alpha1().NetworkPolicies(testNamespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("unable to cleanup policy %v: %v", policy.Name, err)
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
func (data *TestData) waitForNetworkpolicyRealized(pod string, networkpolicy string, npType v1beta2.NetworkPolicyType) error {
	npOption := "K8sNP"
	if npType == v1beta2.AntreaNetworkPolicy {
		npOption = "ANP"
	}
	if err := wait.Poll(200*time.Millisecond, 5*time.Second, func() (bool, error) {
		cmds := []string{"antctl", "get", "networkpolicy", "-S", networkpolicy, "-n", testNamespace, "-T", npOption}
		stdout, stderr, err := runAntctl(pod, cmds, data)
		if err != nil {
			return false, fmt.Errorf("Error when executing antctl get NetworkPolicy, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
		}
		return strings.Contains(stdout, fmt.Sprintf("%s:%s/%s", npType, testNamespace, networkpolicy)), nil
	}); err == wait.ErrWaitTimeout {
		return fmt.Errorf("NetworkPolicy %s isn't realized in time", networkpolicy)
	} else if err != nil {
		return err
	}
	return nil
}

func runTestTraceflow(t *testing.T, data *TestData, tc testcase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}
	if tc.skipReason != "" {
		t.Skip(tc.skipReason)
	}
	if _, err := data.crdClient.CrdV1alpha1().Traceflows().Create(context.TODO(), tc.tf, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating traceflow: %v", err)
	}
	defer func() {
		if err := data.crdClient.CrdV1alpha1().Traceflows().Delete(context.TODO(), tc.tf.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting traceflow: %v", err)
		}
	}()

	if tc.tf.Spec.LiveTraffic {
		// LiveTraffic Traceflow test supports only ICMP traffic from
		// the source Pod to an IP or another Pod.
		var dstPodIPs *PodIPs
		srcPod := tc.srcPod
		if dstIP := tc.tf.Spec.Destination.IP; dstIP != "" {
			ip := net.ParseIP(dstIP)
			if ip.To4() != nil {
				dstPodIPs = &PodIPs{ipv4: &ip}
			} else {
				dstPodIPs = &PodIPs{ipv6: &ip}
			}
		} else {
			dstPod := tc.tf.Spec.Destination.Pod
			podIPs := waitForPodIPs(t, data, []podInfo{{dstPod, "linux"}})
			dstPodIPs = podIPs[dstPod]
		}
		// Give a little time for Nodes to install OVS flows.
		time.Sleep(time.Second * 2)
		// Send an ICMP echo packet from the source Pod to the destination.
		if err := data.runPingCommandFromTestPod(podInfo{srcPod, "linux"}, testNamespace, dstPodIPs, busyboxContainerName, 2, 0); err != nil {
			t.Logf("Ping '%s' -> '%v' failed: ERROR (%v)", srcPod, *dstPodIPs, err)
		}
	}

	tf, err := data.waitForTraceflow(t, tc.tf.Name, tc.expectedPhase)
	if err != nil {
		t.Fatalf("Error: Get Traceflow failed: %v", err)
		return
	}
	if len(tf.Status.Results) != len(tc.expectedResults) {
		t.Fatalf("Error: Traceflow Results should be %v, but got %v", tc.expectedResults, tf.Status.Results)
		return
	}
	if len(tc.expectedResults) == 1 {
		if err = compareObservations(tc.expectedResults[0], tf.Status.Results[0]); err != nil {
			t.Fatal(err)
			return
		}
	} else if len(tc.expectedResults) > 0 {
		if tf.Status.Results[0].Observations[0].Component == v1alpha1.ComponentSpoofGuard {
			if err = compareObservations(tc.expectedResults[0], tf.Status.Results[0]); err != nil {
				t.Fatal(err)
				return
			}
			if err = compareObservations(tc.expectedResults[1], tf.Status.Results[1]); err != nil {
				t.Fatal(err)
				return
			}
		} else {
			if err = compareObservations(tc.expectedResults[0], tf.Status.Results[1]); err != nil {
				t.Fatal(err)
				return
			}
			if err = compareObservations(tc.expectedResults[1], tf.Status.Results[0]); err != nil {
				t.Fatal(err)
				return
			}
		}
	}
	if tc.expectedPktCap != nil {
		pktCap := tf.Status.CapturedPacket
		if tc.expectedPktCap.TransportHeader.ICMP != nil {
			// We cannot predict ICMP echo ID and sequence number.
			pktCap.TransportHeader.ICMP = &v1alpha1.ICMPEchoRequestHeader{}
		}
		if !reflect.DeepEqual(tc.expectedPktCap, pktCap) {
			t.Fatalf("Captured packet should be: %+v, but got: %+v", tc.expectedPktCap, tf.Status.CapturedPacket)
		}
	}
}
