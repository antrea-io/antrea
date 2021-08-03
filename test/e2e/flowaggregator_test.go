// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	secv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/test/e2e/utils"
)

/* Sample output from the collector:
IPFIX-HDR:
  version: 10,  Message Length: 435
  Exported Time: 1608338076 (2020-12-19 00:34:36 +0000 UTC)
  Sequence No.: 3,  Observation Domain ID: 1350683189
DATA SET:
  DATA RECORD-0:
    flowStartSeconds: 1608338066
    flowEndSeconds: 1608338072
    flowEndReason: 2
    sourceTransportPort: 43600
    destinationTransportPort: 5201
    protocolIdentifier: 6
    packetTotalCount: 537924
    octetTotalCount: 23459802093
    packetDeltaCount: 0
    octetDeltaCount: 0
    sourceIPv4Address: 10.10.0.22
    destinationIPv4Address: 10.10.0.23
    reversePacketTotalCount: 444320
    reverseOctetTotalCount: 23108308
    reversePacketDeltaCount: 0
    reverseOctetDeltaCount: 0
    sourcePodName: perftest-a
    sourcePodNamespace: antrea-test
    sourceNodeName: k8s-node-control-plane
    destinationPodName: perftest-b
    destinationPodNamespace: antrea-test
    destinationNodeName: k8s-node-control-plane
    destinationServicePort: 5201
    destinationServicePortName:
    ingressNetworkPolicyName: test-flow-aggregator-networkpolicy-ingress
    ingressNetworkPolicyNamespace: antrea-test
    ingressNetworkPolicyType: 2
    ingressNetworkPolicyRuleName: test-ingress-rule-name
    ingressNetworkPolicyRuleAction: 1
    egressNetworkPolicyName: test-flow-aggregator-networkpolicy-egress
    egressNetworkPolicyNamespace: antrea-test
    egressNetworkPolicyType: 2
    egressNetworkPolicyRuleName: test-egress-rule-name
    egressNetworkPolicyRuleAction: 1
    flowType: 1
    destinationClusterIPv4: 0.0.0.0
    originalExporterIPv4Address: 10.10.0.1
    originalObservationDomainId: 2134708971
    octetDeltaCountFromSourceNode: 0
    octetTotalCountFromSourceNode: 23459802093
    packetDeltaCountFromSourceNode: 0
    packetTotalCountFromSourceNode: 537924
    reverseOctetDeltaCountFromSourceNode: 0
    reverseOctetTotalCountFromSourceNode: 23108308
    reversePacketDeltaCountFromSourceNode: 0
    reversePacketTotalCountFromSourceNode: 444320
    octetDeltaCountFromDestinationNode: 0
    octetTotalCountFromDestinationNode: 23459802093
    packetDeltaCountFromDestinationNode: 0
    packetTotalCountFromDestinationNode: 537924
    reverseOctetDeltaCountFromDestinationNode: 0
    reverseOctetTotalCountFromDestinationNode: 23108308
    reversePacketDeltaCountFromDestinationNode: 0
    reversePacketTotalCountFromDestinationNode: 444320
	sourcePodLabels: {"antrea-e2e":"perftest-a","app":"perftool"}
	destinationPodLabels: {"antrea-e2e":"perftest-b","app":"perftool"}

Intra-Node: Flow record information is complete for source and destination e.g. sourcePodName, destinationPodName
Inter-Node: Flow record from destination Node is ignored, so only flow record from the source Node has its K8s info e.g., sourcePodName, sourcePodNamespace, sourceNodeName etc.
AntreaProxy enabled (Intra-Node): Flow record information is complete for source and destination along with K8s service info such as destinationClusterIP, destinationServicePort, destinationServicePortName etc.
AntreaProxy enabled (Inter-Node): Flow record from destination Node is ignored, so only flow record from the source Node has its K8s info like in Inter-Node case along with K8s Service info such as destinationClusterIP, destinationServicePort, destinationServicePortName etc.
*/

const (
	ingressAllowNetworkPolicyName  = "test-flow-aggregator-networkpolicy-ingress-allow"
	ingressRejectANPName           = "test-flow-aggregator-anp-ingress-reject"
	ingressDropANPName             = "test-flow-aggregator-anp-ingress-drop"
	ingressDenyNPName              = "test-flow-aggregator-np-ingress-deny"
	egressAllowNetworkPolicyName   = "test-flow-aggregator-networkpolicy-egress-allow"
	egressRejectANPName            = "test-flow-aggregator-anp-egress-reject"
	egressDropANPName              = "test-flow-aggregator-anp-egress-drop"
	egressDenyNPName               = "test-flow-aggregator-np-egress-deny"
	ingressAntreaNetworkPolicyName = "test-flow-aggregator-antrea-networkpolicy-ingress"
	egressAntreaNetworkPolicyName  = "test-flow-aggregator-antrea-networkpolicy-egress"
	testIngressRuleName            = "test-ingress-rule-name"
	testEgressRuleName             = "test-egress-rule-name"
	iperfTimeSec                   = 12
)

var (
	// Single iperf run results in two connections with separate ports (control connection and actual data connection).
	// As 2s is the export active timeout of flow exporter and iperf traffic runs for 12s, we expect totally 12 records
	// exporting to the flow aggregator at time 2s, 4s, 6s, 8s, 10s, and 12s after iperf traffic begins.
	// Since flow aggregator will aggregate records based on 5-tuple connection key and active timeout is 3.5 seconds,
	// we expect 3 records at time 5.5s, 9s, and 12.5s after iperf traffic begins.
	expectedNumDataRecords = 3
)

type testFlow struct {
	srcIP      string
	dstIP      string
	srcPodName string
	dstPodName string
}

func TestFlowAggregator(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, v4Enabled, v6Enabled, err := setupTestWithIPFIXCollector(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	defer teardownFlowAggregator(t, data)

	if testOptions.providerName == "kind" {
		// Currently, in Kind clusters, OVS userspace datapath does not support
		// packet statistics in the conntrack entries. Because of that Flow Exporter
		// at Antrea agent cannot consider flows to be active and keep sending active
		// records. Currently, Flow Exporter sends two records for a iperf flow
		// in kind cluster with a duration of 12s: 1. A new iperf connection gets
		// idled out after exporter idle timeout, which is after 1s in the test.
		// In this case, flow aggregator sends the record after 4.5s 2. When the
		// connection dies and TCP state becomes TIME_WAIT, which is
		// at 12s in the test. Here, Flow Aggregator sends the record at 15.5s.
		// We will remove this workaround once OVS userspace datapath supports packet
		// statistics in conntrack entries.
		expectedNumDataRecords = 2
	}

	k8sUtils, err = NewKubernetesUtils(data)
	if err != nil {
		t.Fatalf("Error when creating Kubernetes utils client: %v", err)
	}

	podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, err := createPerftestPods(data)
	if err != nil {
		t.Fatalf("Error when creating perftest Pods: %v", err)
	}

	if v4Enabled {
		t.Run("IPv4", func(t *testing.T) { testHelper(t, data, podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, false) })
	}

	if v6Enabled {
		t.Run("IPv6", func(t *testing.T) { testHelper(t, data, podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, true) })
	}
}

func testHelper(t *testing.T, data *TestData, podAIPs, podBIPs, podCIPs, podDIPs, podEIPs *PodIPs, isIPv6 bool) {
	svcB, svcC, err := createPerftestServices(data, isIPv6)
	if err != nil {
		t.Fatalf("Error when creating perftest Services: %v", err)
	}
	defer deletePerftestServices(t, data)
	// Wait for the Service to be realized.
	time.Sleep(3 * time.Second)

	// OVS userspace implementation of conntrack doesn't maintain packet or byte counter statistics, so we ignore the bandwidth test in Kind cluster.
	checkBandwidth := testOptions.providerName != "kind"
	// IntraNodeFlows tests the case, where Pods are deployed on same Node
	// and their flow information is exported as IPFIX flow records.
	// K8s network policies are being tested here.
	t.Run("IntraNodeFlows", func(t *testing.T) {
		np1, np2 := deployK8sNetworkPolicies(t, data, "perftest-a", "perftest-b")
		defer func() {
			if np1 != nil {
				if err = data.deleteNetworkpolicy(np1); err != nil {
					t.Errorf("Error when deleting network policy: %v", err)
				}
			}
			if np2 != nil {
				if err = data.deleteNetworkpolicy(np2); err != nil {
					t.Errorf("Error when deleting network policy: %v", err)
				}
			}
		}()
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), podBIPs.ipv4.String(), isIPv6, true, false, true, false, checkBandwidth)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), podBIPs.ipv6.String(), isIPv6, true, false, true, false, checkBandwidth)
		}
	})

	// IntraNodeDenyConnIngressANP tests the case, where Pods are deployed on same Node with an Antrea ingress deny policy rule
	// applied to destination Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-b (Ingress reject), perftest-a -> perftest-d (Ingress drop)
	t.Run("IntraNodeDenyConnIngressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-b", "perftest-d", true)
		defer func() {
			if anp1 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp1); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
			if anp2 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp2); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
		}()
		testFlow1 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-b",
		}
		testFlow2 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-d",
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv4.String(), podBIPs.ipv4.String(), podAIPs.ipv4.String(), podDIPs.ipv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv6.String(), podBIPs.ipv6.String(), podAIPs.ipv6.String(), podDIPs.ipv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true)
		}
	})

	// IntraNodeDenyConnEgressANP tests the case, where Pods are deployed on same Node with an Antrea egress deny policy rule
	// applied to source Pods (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a (Egress reject) -> perftest-b , perftest-a (Egress drop) -> perftest-d
	t.Run("IntraNodeDenyConnEgressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-b", "perftest-d", false)
		defer func() {
			if anp1 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp1); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
			if anp2 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp2); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
		}()
		testFlow1 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-b",
		}
		testFlow2 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-d",
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv4.String(), podBIPs.ipv4.String(), podAIPs.ipv4.String(), podDIPs.ipv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv6.String(), podBIPs.ipv6.String(), podAIPs.ipv6.String(), podDIPs.ipv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true)
		}
	})

	// IntraNodeDenyConnNP tests the case, where Pods are deployed on same Node with an ingress and an egress deny policy rule
	// applied to one destination Pod, one source Pod, respectively and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-b (Ingress deny), perftest-d (Egress deny) -> perftest-a
	t.Run("IntraNodeDenyConnNP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		np1, np2 := deployDenyNetworkPolicies(t, data, "perftest-b", "perftest-d")
		defer func() {
			if np1 != nil {
				if err = data.deleteNetworkpolicy(np1); err != nil {
					t.Errorf("Error when deleting Network Policy: %v", err)
				}
			}
			if np2 != nil {
				if err = data.deleteNetworkpolicy(np2); err != nil {
					t.Errorf("Error when deleting Network Policy: %v", err)
				}
			}
		}()
		testFlow1 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-b",
		}
		testFlow2 := testFlow{
			srcPodName: "perftest-d",
			dstPodName: "perftest-a",
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv4.String(), podBIPs.ipv4.String(), podDIPs.ipv4.String(), podAIPs.ipv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, false)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv6.String(), podBIPs.ipv6.String(), podDIPs.ipv6.String(), podAIPs.ipv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, false)
		}
	})

	// InterNodeFlows tests the case, where Pods are deployed on different Nodes
	// and their flow information is exported as IPFIX flow records.
	// Antrea network policies are being tested here.
	t.Run("InterNodeFlows", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		anp1, anp2 := deployAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c")
		defer func() {
			if anp1 != nil {
				k8sUtils.DeleteANP(testNamespace, anp1.Name)
			}
			if anp2 != nil {
				k8sUtils.DeleteANP(testNamespace, anp2.Name)
			}
		}()
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), podCIPs.ipv4.String(), isIPv6, false, false, false, true, checkBandwidth)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), podCIPs.ipv6.String(), isIPv6, false, false, false, true, checkBandwidth)
		}
	})

	// InterNodeDenyConnIngressANP tests the case, where Pods are deployed on different Nodes with an Antrea ingress deny policy rule
	// applied to destination Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-c (Ingress reject), perftest-a -> perftest-e (Ingress drop)
	t.Run("InterNodeDenyConnIngressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", "perftest-e", true)
		defer func() {
			if anp1 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp1); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
			if anp2 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp2); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
		}()
		testFlow1 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-c",
		}
		testFlow2 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-e",
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv4.String(), podCIPs.ipv4.String(), podAIPs.ipv4.String(), podEIPs.ipv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv6.String(), podCIPs.ipv6.String(), podAIPs.ipv6.String(), podEIPs.ipv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true)
		}
	})

	// InterNodeDenyConnEgressANP tests the case, where Pods are deployed on different Nodes with an Antrea egress deny policy rule
	// applied to source Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a (Egress reject) -> perftest-c, perftest-a (Egress drop)-> perftest-e
	t.Run("InterNodeDenyConnEgressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", "perftest-e", false)
		defer func() {
			if anp1 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp1); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
			if anp2 != nil {
				if err = data.deleteAntreaNetworkpolicy(anp2); err != nil {
					t.Errorf("Error when deleting Antrea Network Policy: %v", err)
				}
			}
		}()
		testFlow1 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-c",
		}
		testFlow2 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-e",
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv4.String(), podCIPs.ipv4.String(), podAIPs.ipv4.String(), podEIPs.ipv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv6.String(), podCIPs.ipv6.String(), podAIPs.ipv6.String(), podEIPs.ipv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true)
		}
	})

	// InterNodeDenyConnNP tests the case, where Pods are deployed on different Nodes with an ingress and an egress deny policy rule
	// applied to one destination Pod, one source Pod, respectively and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-c (Ingress deny), perftest-b (Egress deny) -> perftest-e
	t.Run("InterNodeDenyConnNP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		np1, np2 := deployDenyNetworkPolicies(t, data, "perftest-c", "perftest-b")
		defer func() {
			if np1 != nil {
				if err = data.deleteNetworkpolicy(np1); err != nil {
					t.Errorf("Error when deleting Network Policy: %v", err)
				}
			}
			if np2 != nil {
				if err = data.deleteNetworkpolicy(np2); err != nil {
					t.Errorf("Error when deleting Network Policy: %v", err)
				}
			}
		}()
		testFlow1 := testFlow{
			srcPodName: "perftest-a",
			dstPodName: "perftest-c",
		}
		testFlow2 := testFlow{
			srcPodName: "perftest-b",
			dstPodName: "perftest-e",
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv4.String(), podCIPs.ipv4.String(), podBIPs.ipv4.String(), podEIPs.ipv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, false)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.ipv6.String(), podCIPs.ipv6.String(), podBIPs.ipv6.String(), podEIPs.ipv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, false)
		}
	})

	// ToExternalFlows tests the export of IPFIX flow records when a source Pod
	// sends traffic to an external IP
	t.Run("ToExternalFlows", func(t *testing.T) {
		// Creating an agnhost server as a host network Pod
		serverPodPort := int32(80)
		_, serverIPs, cleanupFunc := createAndWaitForPod(t, data, func(name string, ns string, nodeName string) error {
			return data.createServerPod(name, testNamespace, "", serverPodPort, false, true)
		}, "test-server-", "", testNamespace)
		defer cleanupFunc()

		clientName, clientIPs, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", nodeName(0), testNamespace)
		defer cleanupFunc()

		if !isIPv6 {
			if clientIPs.ipv4 != nil && serverIPs.ipv4 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.ipv4.String(), serverIPs.ipv4.String(), serverPodPort, isIPv6)
			}
		} else {
			if clientIPs.ipv6 != nil && serverIPs.ipv6 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.ipv6.String(), serverIPs.ipv6.String(), serverPodPort, isIPv6)
			}
		}
	})

	// LocalServiceAccess tests the case, where Pod and Service are deployed on the same Node and their flow information is exported as IPFIX flow records.
	t.Run("LocalServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t)
		// In dual stack cluster, Service IP can be assigned as different IP family from specified.
		// In that case, source IP and destination IP will align with IP family of Service IP.
		// For IPv4-only and IPv6-only cluster, IP family of Service IP will be same as Pod IPs.
		isServiceIPv6 := net.ParseIP(svcB.Spec.ClusterIP).To4() == nil
		if isServiceIPv6 {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), svcB.Spec.ClusterIP, isServiceIPv6, true, true, false, false, checkBandwidth)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), svcB.Spec.ClusterIP, isServiceIPv6, true, true, false, false, checkBandwidth)
		}
	})

	// RemoteServiceAccess tests the case, where Pod and Service are deployed on different Nodes and their flow information is exported as IPFIX flow records.
	t.Run("RemoteServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t)
		// In dual stack cluster, Service IP can be assigned as different IP family from specified.
		// In that case, source IP and destination IP will align with IP family of Service IP.
		// For IPv4-only and IPv6-only cluster, IP family of Service IP will be same as Pod IPs.
		isServiceIPv6 := net.ParseIP(svcC.Spec.ClusterIP).To4() == nil
		if isServiceIPv6 {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), svcC.Spec.ClusterIP, isServiceIPv6, false, true, false, false, checkBandwidth)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), svcC.Spec.ClusterIP, isServiceIPv6, false, true, false, false, checkBandwidth)
		}
	})
}

func checkRecordsForFlows(t *testing.T, data *TestData, srcIP string, dstIP string, isIPv6 bool, isIntraNode bool, checkService bool, checkK8sNetworkPolicy bool, checkAntreaNetworkPolicy bool, checkBandwidth bool) {
	timeStart := time.Now()
	timeStartSec := timeStart.Unix()
	var cmdStr string
	if !isIPv6 {
		cmdStr = fmt.Sprintf("iperf3 -c %s -t %d", dstIP, iperfTimeSec)
	} else {
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s -t %d", dstIP, iperfTimeSec)
	}
	stdout, _, err := data.runCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", cmdStr})
	if err != nil {
		t.Errorf("Error when running iperf3 client: %v", err)
	}
	bwSlice, srcPort := getBandwidthAndSourcePort(stdout)
	// bandwidth from iperf output
	bandwidthInFloat, err := strconv.ParseFloat(bwSlice[0], 64)
	require.NoErrorf(t, err, "Error when converting iperf bandwidth %s to float64 type", bwSlice[0])
	var bandwidthInMbps float64
	if strings.Contains(bwSlice[1], "Mbits") {
		bandwidthInMbps = bandwidthInFloat
	} else if strings.Contains(bwSlice[1], "Gbits") {
		bandwidthInMbps = bandwidthInFloat * float64(1024)
	} else {
		t.Fatalf("Unit of the traffic bandwidth reported by iperf should either be Mbits or Gbits, failing the test.")
	}

	collectorOutput, recordSlices := getCollectorOutput(t, srcIP, dstIP, srcPort, timeStart, true)
	// Iterate over recordSlices and build some results to test with expected results
	dataRecordsCount := 0
	var octetTotalCount uint64
	for _, record := range recordSlices {
		// Check the source port along with source and destination IPs as there
		// are flow records for control flows during the iperf  with same IPs
		// and destination port.
		if strings.Contains(record, srcIP) && strings.Contains(record, dstIP) && strings.Contains(record, srcPort) {
			dataRecordsCount = dataRecordsCount + 1
			// Check if record has both Pod name of source and destination Pod.
			if isIntraNode {
				checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-b", controlPlaneNodeName())
				checkFlowType(t, record, ipfixregistry.FlowTypeIntraNode)
			} else {
				checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-c", workerNodeName(1))
				checkFlowType(t, record, ipfixregistry.FlowTypeInterNode)
			}
			assert := assert.New(t)
			if checkService {
				if isIntraNode {
					assert.Contains(record, "antrea-test/perftest-b", "Record with ServiceIP does not have Service name")
				} else {
					assert.Contains(record, "antrea-test/perftest-c", "Record with ServiceIP does not have Service name")
				}
			}
			if checkK8sNetworkPolicy {
				// Check if records have both ingress and egress network policies.
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyName: %s", ingressAllowNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the ingress rule")
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", testNamespace), "Record does not have the correct NetworkPolicy Namespace with the ingress rule")
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeK8sNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyName: %s", egressAllowNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the egress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", testNamespace), "Record does not have the correct NetworkPolicy Namespace with the egress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeK8sNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress rule")
			}
			if checkAntreaNetworkPolicy {
				// Check if records have both ingress and egress network policies.
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyName: %s", ingressAntreaNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the ingress rule")
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", testNamespace), "Record does not have the correct NetworkPolicy Namespace with the ingress rule")
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress rule")
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleName: %s", testIngressRuleName), "Record does not have the correct NetworkPolicy RuleName with the ingress rule")
				assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionAllow), "Record does not have the correct NetworkPolicy RuleAction with the ingress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyName: %s", egressAntreaNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the egress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", testNamespace), "Record does not have the correct NetworkPolicy Namespace with the egress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyRuleName: %s", testEgressRuleName), "Record does not have the correct NetworkPolicy RuleName with the egress rule")
				assert.Contains(record, fmt.Sprintf("egressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionAllow), "Record does not have the correct NetworkPolicy RuleAction with the egress rule")
			}

			// Skip the bandwidth check for the iperf control flow records which have 0 delta count.
			if checkBandwidth && !strings.Contains(record, "octetDeltaCount: 0") {
				exportTime := int64(getUnit64FieldFromRecord(t, record, "flowEndSeconds"))
				curOctetTotalCount := getUnit64FieldFromRecord(t, record, "octetTotalCountFromSourceNode")
				if curOctetTotalCount > octetTotalCount {
					octetTotalCount = curOctetTotalCount
				}
				curOctetDeltaCount := getUnit64FieldFromRecord(t, record, "octetDeltaCountFromSourceNode")
				// Check the bandwidth using octetDeltaCountFromSourceNode, if this record
				// is not either the first record or the last in the stream of records.
				if curOctetDeltaCount != curOctetTotalCount && exportTime < timeStartSec+iperfTimeSec {
					t.Logf("Check the bandwidth using octetDeltaCountFromSourceNode in data record.")
					// This middle record should aggregate two records from Flow Exporter
					checkBandwidthByInterval(t, bandwidthInMbps, curOctetDeltaCount, float64(2*exporterActiveFlowExportTimeout/time.Second), "octetDeltaCountFromSourceNode")
				}
			}
		}
	}
	// Average bandwidth check is done after iterating through all records using the largest octetTotalCountFromSourceNode.
	if checkBandwidth && octetTotalCount > 0 {
		t.Logf("Check the average bandwidth using octetTotalCountFromSourceNode %v in data record.", octetTotalCount)
		checkBandwidthByInterval(t, bandwidthInMbps, octetTotalCount, float64(iperfTimeSec), "octetTotalCountFromSourceNode")
	}
	// Checking only data records as data records cannot be decoded without template
	// record.
	assert.GreaterOrEqualf(t, dataRecordsCount, expectedNumDataRecords, "IPFIX collector should receive expected number of flow records. Considered records: %s \n Collector output: %s", recordSlices, collectorOutput)
}

func checkRecordsForToExternalFlows(t *testing.T, data *TestData, srcNodeName string, srcPodName string, srcIP string, dstIP string, dstPort int32, isIPv6 bool) {
	timeStart := time.Now()
	var cmd string
	if !isIPv6 {
		cmd = fmt.Sprintf("wget -O- %s:%d", dstIP, dstPort)
	} else {
		cmd = fmt.Sprintf("wget -O- [%s]:%d", dstIP, dstPort)
	}
	stdout, stderr, err := data.runCommandFromPod(testNamespace, srcPodName, busyboxContainerName, strings.Fields(cmd))
	require.NoErrorf(t, err, "Error when running wget command, stdout: %s, stderr: %s", stdout, stderr)

	_, recordSlices := getCollectorOutput(t, srcIP, dstIP, "", timeStart, false)
	for _, record := range recordSlices {
		if strings.Contains(record, srcIP) && strings.Contains(record, dstIP) {
			checkPodAndNodeData(t, record, srcPodName, srcNodeName, "", "")
			checkFlowType(t, record, ipfixregistry.FlowTypeToExternal)
			// Since the OVS userspace conntrack implementation doesn't maintain
			// packet or byte counter statistics, skip the check for Kind clusters
			if testOptions.providerName != "kind" {
				assert.NotContains(t, record, "octetDeltaCount: 0", "octetDeltaCount should be non-zero")
			}
		}
	}
}

func checkRecordsForDenyFlows(t *testing.T, data *TestData, testFlow1, testFlow2 testFlow, isIPv6 bool, isIntraNode bool, isANP bool) {
	timeStart := time.Now()
	var cmdStr1, cmdStr2 string
	if !isIPv6 {
		cmdStr1 = fmt.Sprintf("iperf3 -c %s -n 1", testFlow1.dstIP)
		cmdStr2 = fmt.Sprintf("iperf3 -c %s -n 1", testFlow2.dstIP)
	} else {
		cmdStr1 = fmt.Sprintf("iperf3 -6 -c %s -n 1", testFlow1.dstIP)
		cmdStr2 = fmt.Sprintf("iperf3 -6 -c %s -n 1", testFlow2.dstIP)
	}
	_, _, err := data.runCommandFromPod(testNamespace, testFlow1.srcPodName, "", []string{"timeout", "2", "bash", "-c", cmdStr1})
	assert.Error(t, err)
	_, _, err = data.runCommandFromPod(testNamespace, testFlow2.srcPodName, "", []string{"timeout", "2", "bash", "-c", cmdStr2})
	assert.Error(t, err)

	_, recordSlices := getCollectorOutput(t, testFlow1.srcIP, testFlow2.srcIP, "", timeStart, false)
	// Iterate over recordSlices and build some results to test with expected results
	for _, record := range recordSlices {
		var srcPodName, dstPodName string
		if strings.Contains(record, testFlow1.srcIP) && strings.Contains(record, testFlow1.dstIP) {
			srcPodName = testFlow1.srcPodName
			dstPodName = testFlow1.dstPodName
		} else if strings.Contains(record, testFlow2.srcIP) && strings.Contains(record, testFlow2.dstIP) {
			srcPodName = testFlow2.srcPodName
			dstPodName = testFlow2.dstPodName
		}
		if (strings.Contains(record, testFlow1.srcIP) && strings.Contains(record, testFlow1.dstIP)) || (strings.Contains(record, testFlow2.srcIP) && strings.Contains(record, testFlow2.dstIP)) {
			ingressRejectStr := fmt.Sprintf("ingressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionReject)
			ingressDropStr := fmt.Sprintf("ingressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionDrop)
			egressRejectStr := fmt.Sprintf("egressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionReject)
			egressDropStr := fmt.Sprintf("egressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionDrop)

			if isIntraNode {
				checkPodAndNodeData(t, record, srcPodName, controlPlaneNodeName(), dstPodName, controlPlaneNodeName())
				checkFlowType(t, record, ipfixregistry.FlowTypeIntraNode)
			} else {
				checkPodAndNodeData(t, record, srcPodName, controlPlaneNodeName(), dstPodName, workerNodeName(1))
				checkFlowType(t, record, ipfixregistry.FlowTypeInterNode)
			}
			assert := assert.New(t)
			if !isANP { // K8s Network Policies
				if strings.Contains(record, ingressDropStr) && !strings.Contains(record, ingressDropANPName) {
					assert.Contains(record, testFlow1.dstIP)
				} else if strings.Contains(record, egressDropStr) && !strings.Contains(record, egressDropANPName) {
					assert.Contains(record, testFlow2.dstIP)
				}
			} else { // Antrea Network Policies
				if strings.Contains(record, ingressRejectStr) {
					assert.Contains(record, ingressRejectANPName, "Record does not have Antrea NetworkPolicy name with ingress reject rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", testNamespace), "Record does not have correct ingressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress reject rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleName: %s", testIngressRuleName), "Record does not have the correct NetworkPolicy RuleName with the ingress reject rule")
				} else if strings.Contains(record, ingressDropStr) {
					assert.Contains(record, ingressDropANPName, "Record does not have Antrea NetworkPolicy name with ingress drop rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", testNamespace), "Record does not have correct ingressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress drop rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleName: %s", testIngressRuleName), "Record does not have the correct NetworkPolicy RuleName with the ingress drop rule")
				} else if strings.Contains(record, egressRejectStr) {
					assert.Contains(record, egressRejectANPName, "Record does not have Antrea NetworkPolicy name with egress reject rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", testNamespace), "Record does not have correct egressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress reject rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyRuleName: %s", testEgressRuleName), "Record does not have the correct NetworkPolicy RuleName with the egress reject rule")
				} else if strings.Contains(record, egressDropStr) {
					assert.Contains(record, egressDropANPName, "Record does not have Antrea NetworkPolicy name with egress drop rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", testNamespace), "Record does not have correct egressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress drop rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyRuleName: %s", testEgressRuleName), "Record does not have the correct NetworkPolicy RuleName with the egress drop rule")
				}
			}

		}
	}
}

func checkBandwidthByInterval(t *testing.T, bandwidthInMbps float64, octetCount uint64, interval float64, field string) {
	recBandwidth := float64(octetCount) * 8 / 1000000 / interval
	t.Logf("Iperf throughput: %.2f Mbits/s, IPFIX record throughput calculated through %s: %.2f Mbits/s", bandwidthInMbps, field, recBandwidth)
	assert.InDeltaf(t, recBandwidth, bandwidthInMbps, bandwidthInMbps*0.15, "Difference between Iperf bandwidth and IPFIX record bandwidth calculated through %s should be lower than 15%%", field)
}

func checkPodAndNodeData(t *testing.T, record, srcPod, srcNode, dstPod, dstNode string) {
	assert := assert.New(t)
	assert.Contains(record, srcPod, "Record with srcIP does not have Pod name")
	assert.Contains(record, fmt.Sprintf("sourcePodNamespace: %s", testNamespace), "Record does not have correct sourcePodNamespace")
	assert.Contains(record, fmt.Sprintf("sourceNodeName: %s", srcNode), "Record does not have correct sourceNodeName")
	// For Pod-To-External flow type, we send traffic to an external address,
	// so we skip the verification of destination Pod info.
	// Also, source Pod labels are different for Pod-To-External flow test.
	if dstPod != "" {
		assert.Contains(record, dstPod, "Record with dstIP does not have Pod name")
		assert.Contains(record, fmt.Sprintf("destinationPodNamespace: %s", testNamespace), "Record does not have correct destinationPodNamespace")
		assert.Contains(record, fmt.Sprintf("destinationNodeName: %s", dstNode), "Record does not have correct destinationNodeName")
		assert.Contains(record, fmt.Sprintf("{\"antrea-e2e\":\"%s\",\"app\":\"perftool\"}", srcPod), "Record does not have correct label for source Pod")
		assert.Contains(record, fmt.Sprintf("{\"antrea-e2e\":\"%s\",\"app\":\"perftool\"}", dstPod), "Record does not have correct label for destination Pod")
	} else {
		assert.Contains(record, fmt.Sprintf("{\"antrea-e2e\":\"%s\",\"app\":\"busybox\"}", srcPod), "Record does not have correct label for source Pod")
	}
}

func checkFlowType(t *testing.T, record string, flowType uint8) {
	assert.Containsf(t, record, fmt.Sprintf("flowType: %d", flowType), "Record does not have correct flowType")
}

func getUnit64FieldFromRecord(t *testing.T, record string, field string) uint64 {
	if strings.Contains(record, "TEMPLATE SET") {
		return 0
	}
	splitLines := strings.Split(record, "\n")
	for _, line := range splitLines {
		if strings.Contains(line, field) {
			lineSlice := strings.Split(line, ":")
			value, err := strconv.ParseUint(strings.TrimSpace(lineSlice[1]), 10, 64)
			require.NoError(t, err, "Error when converting %s to uint64 type", field)
			return value
		}
	}
	return 0
}

// getCollectorOutput polls the output of go-ipfix collector and checks if we have
// received all the expected records for a given flow with source IP, destination IP
// and source port. We send source port to ignore the control flows during the
// iperf test.
func getCollectorOutput(t *testing.T, srcIP, dstIP, srcPort string, timeStart time.Time, checkAllRecords bool) (string, []string) {
	var collectorOutput string
	var recordSlices []string
	err := wait.PollImmediate(500*time.Millisecond, aggregatorInactiveFlowRecordTimeout, func() (bool, error) {
		var rc int
		var err error
		// `pod-running-timeout` option is added to cover scenarios where ipfix flow-collector has crashed after being deployed
		rc, collectorOutput, _, err = provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl logs --pod-running-timeout=%v ipfix-collector -n antrea-test", aggregatorInactiveFlowRecordTimeout.String()))
		if err != nil || rc != 0 {
			return false, err
		}
		// Checking that all the data records which correspond to the iperf flow are received
		recordSlices = getRecordsFromOutput(collectorOutput)
		if checkAllRecords {
			for _, record := range recordSlices {
				exportTime := int64(getUnit64FieldFromRecord(t, record, "flowEndSeconds"))
				if strings.Contains(record, srcIP) && strings.Contains(record, dstIP) && strings.Contains(record, srcPort) {
					if exportTime >= timeStart.Unix()+iperfTimeSec {
						return true, nil
					}
				}
			}
			return false, nil
		} else {
			return strings.Contains(collectorOutput, srcIP) && strings.Contains(collectorOutput, dstIP) && strings.Contains(collectorOutput, srcPort), nil
		}
	})
	require.NoErrorf(t, err, "IPFIX collector did not receive the expected records in collector output: %v time start: %s iperf source port: %s", collectorOutput, timeStart.String(), srcPort)
	return collectorOutput, recordSlices
}

func getRecordsFromOutput(output string) []string {
	re := regexp.MustCompile("(?m)^.*" + "#" + ".*$[\r\n]+")
	output = re.ReplaceAllString(output, "")
	output = strings.TrimSpace(output)
	recordSlices := strings.Split(output, "IPFIX-HDR:")
	return recordSlices
}

func deployK8sNetworkPolicies(t *testing.T, data *TestData, srcPod, dstPod string) (np1 *networkingv1.NetworkPolicy, np2 *networkingv1.NetworkPolicy) {
	// Add K8s NetworkPolicy between two iperf Pods.
	var err error
	np1, err = data.createNetworkPolicy(ingressAllowNetworkPolicyName, &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": srcPod,
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Errorf("Error when creating Network Policy: %v", err)
	}
	np2, err = data.createNetworkPolicy(egressAllowNetworkPolicyName, &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": dstPod,
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Errorf("Error when creating Network Policy: %v", err)
	}
	// Wait for network policies to be realized.
	if err := WaitNetworkPolicyRealize(2, data); err != nil {
		t.Errorf("Error when waiting for Network Policy to be realized: %v", err)
	}
	t.Log("Network Policies are realized.")
	return np1, np2
}

func deployAntreaNetworkPolicies(t *testing.T, data *TestData, srcPod, dstPod string) (anp1 *secv1alpha1.NetworkPolicy, anp2 *secv1alpha1.NetworkPolicy) {
	builder1 := &utils.AntreaNetworkPolicySpecBuilder{}
	// apply anp to dstPod, allow ingress from srcPod
	builder1 = builder1.SetName(testNamespace, ingressAntreaNetworkPolicyName).
		SetPriority(2.0).
		SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": dstPod}}})
	builder1 = builder1.AddIngress(corev1.ProtocolTCP, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{},
		nil, nil, nil, secv1alpha1.RuleActionAllow, testIngressRuleName)
	anp1 = builder1.Get()
	anp1, err1 := k8sUtils.CreateOrUpdateANP(anp1)
	if err1 != nil {
		failOnError(fmt.Errorf("Error when creating Antrea Network Policy: %v", err1), t)
	}

	builder2 := &utils.AntreaNetworkPolicySpecBuilder{}
	// apply anp to srcPod, allow egress to dstPod
	builder2 = builder2.SetName(testNamespace, egressAntreaNetworkPolicyName).
		SetPriority(2.0).
		SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
	builder2 = builder2.AddEgress(corev1.ProtocolTCP, nil, nil, nil, nil, map[string]string{"antrea-e2e": dstPod}, map[string]string{},
		nil, nil, nil, secv1alpha1.RuleActionAllow, testEgressRuleName)
	anp2 = builder2.Get()
	anp2, err2 := k8sUtils.CreateOrUpdateANP(anp2)
	if err2 != nil {
		failOnError(fmt.Errorf("Error when creating Network Policy: %v", err2), t)
	}

	// Wait for network policies to be realized.
	if err := WaitNetworkPolicyRealize(2, data); err != nil {
		t.Errorf("Error when waiting for Antrea Network Policy to be realized: %v", err)
	}
	t.Log("Antrea Network Policies are realized.")
	return anp1, anp2
}

func deployDenyAntreaNetworkPolicies(t *testing.T, data *TestData, srcPod, podReject, podDrop string, isIngress bool) (anp1 *secv1alpha1.NetworkPolicy, anp2 *secv1alpha1.NetworkPolicy) {
	var err error
	builder1 := &utils.AntreaNetworkPolicySpecBuilder{}
	builder2 := &utils.AntreaNetworkPolicySpecBuilder{}
	if isIngress {
		// apply reject and drop ingress rule to destination pods
		builder1 = builder1.SetName(testNamespace, ingressRejectANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": podReject}}})
		builder1 = builder1.AddIngress(corev1.ProtocolTCP, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionReject, testIngressRuleName)
		builder2 = builder2.SetName(testNamespace, ingressDropANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": podDrop}}})
		builder2 = builder2.AddIngress(corev1.ProtocolTCP, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionDrop, testIngressRuleName)
	} else {
		// apply reject and drop egress rule to source pod
		builder1 = builder1.SetName(testNamespace, egressRejectANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
		builder1 = builder1.AddEgress(corev1.ProtocolTCP, nil, nil, nil, nil, map[string]string{"antrea-e2e": podReject}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionReject, testEgressRuleName)
		builder2 = builder2.SetName(testNamespace, egressDropANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
		builder2 = builder2.AddEgress(corev1.ProtocolTCP, nil, nil, nil, nil, map[string]string{"antrea-e2e": podDrop}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionDrop, testEgressRuleName)
	}
	anp1 = builder1.Get()
	anp1, err = k8sUtils.CreateOrUpdateANP(anp1)
	if err != nil {
		failOnError(fmt.Errorf("Error when creating Antrea Network Policy: %v", err), t)
	}
	anp2 = builder2.Get()
	anp2, err = k8sUtils.CreateOrUpdateANP(anp2)
	if err != nil {
		failOnError(fmt.Errorf("Error when creating Antrea Network Policy: %v", err), t)
	}
	// Wait for Antrea NetworkPolicy to be realized.
	if err := WaitNetworkPolicyRealize(2, data); err != nil {
		t.Errorf("Error when waiting for Antrea Network Policy to be realized: %v", err)
	}
	t.Log("Antrea Network Policies are realized.")
	return anp1, anp2
}

func deployDenyNetworkPolicies(t *testing.T, data *TestData, pod1, pod2 string) (np1 *networkingv1.NetworkPolicy, np2 *networkingv1.NetworkPolicy) {
	np1, err := data.createNetworkPolicy(ingressDenyNPName, &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": pod1,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{},
	})
	if err != nil {
		t.Errorf("Error when creating Network Policy: %v", err)
	}
	np2, err = data.createNetworkPolicy(egressDenyNPName, &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": pod2,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress:      []networkingv1.NetworkPolicyEgressRule{},
	})
	if err != nil {
		t.Errorf("Error when creating Network Policy: %v", err)
	}
	// Wait for NetworkPolicy to be realized.
	if err := WaitNetworkPolicyRealize(2, data); err != nil {
		t.Errorf("Error when waiting for Network Policies to be realized: %v", err)
	}
	t.Log("Network Policies are realized.")
	return np1, np2
}

func createPerftestPods(data *TestData) (podAIPs *PodIPs, podBIPs *PodIPs, podCIPs *PodIPs, podDIPs *PodIPs, podEIPs *PodIPs, err error) {
	if err := data.createPodOnNode("perftest-a", testNamespace, controlPlaneNodeName(), perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest client Pod: %v", err)
	}
	podAIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-a", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when waiting for the perftest client Pod: %v", err)
	}

	if err := data.createPodOnNode("perftest-b", testNamespace, controlPlaneNodeName(), perftoolImage, nil, nil, nil, []corev1.ContainerPort{{Protocol: corev1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podBIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-c", testNamespace, workerNodeName(1), perftoolImage, nil, nil, nil, []corev1.ContainerPort{{Protocol: corev1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podCIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-c", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-d", testNamespace, controlPlaneNodeName(), perftoolImage, nil, nil, nil, []corev1.ContainerPort{{Protocol: corev1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podDIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-d", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-e", testNamespace, workerNodeName(1), perftoolImage, nil, nil, nil, []corev1.ContainerPort{{Protocol: corev1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podEIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-e", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	return podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, nil
}

func createPerftestServices(data *TestData, isIPv6 bool) (svcB *corev1.Service, svcC *corev1.Service, err error) {
	svcIPFamily := corev1.IPv4Protocol
	if isIPv6 {
		svcIPFamily = corev1.IPv6Protocol
	}

	svcB, err = data.createService("perftest-b", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"}, false, corev1.ServiceTypeClusterIP, &svcIPFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when creating perftest-b Service: %v", err)
	}

	svcC, err = data.createService("perftest-c", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-c"}, false, corev1.ServiceTypeClusterIP, &svcIPFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when creating perftest-c Service: %v", err)
	}

	return svcB, svcC, nil
}

func deletePerftestServices(t *testing.T, data *TestData) {
	for _, serviceName := range []string{"perftest-b", "perftest-c"} {
		err := data.deleteService(serviceName)
		if err != nil {
			t.Logf("Error when deleting %s Service: %v", serviceName, err)
		}
	}
}

// getBandwidthAndSourcePort parses iperf commands output and returns bandwidth
// and source port. Bandwidth is returned as a slice containing two strings (bandwidth
// value and bandwidth unit).
func getBandwidthAndSourcePort(iperfStdout string) ([]string, string) {
	var bandwidth []string
	var srcPort string
	outputLines := strings.Split(iperfStdout, "\n")
	for _, line := range outputLines {
		if strings.Contains(line, "sender") {
			fields := strings.Fields(line)
			bandwidth = fields[6:8]
		}
		if strings.Contains(line, "connected") {
			fields := strings.Fields(line)
			srcPort = fields[5]
		}
	}
	return bandwidth, srcPort
}
