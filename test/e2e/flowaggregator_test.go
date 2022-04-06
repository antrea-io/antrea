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
	"encoding/json"
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

	"antrea.io/antrea/pkg/antctl"
	"antrea.io/antrea/pkg/antctl/runtime"
	secv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/test/e2e/utils"
)

/* Sample output from the collector:
IPFIX-HDR:
  version: 10,  Message Length: 617
  Exported Time: 1637706974 (2021-11-23 22:36:14 +0000 UTC)
  Sequence No.: 27,  Observation Domain ID: 2569248951
DATA SET:
  DATA RECORD-0:
    flowStartSeconds: 1637706961
    flowEndSeconds: 1637706973
    flowEndReason: 3
    sourceTransportPort: 44752
    destinationTransportPort: 5201
    protocolIdentifier: 6
    packetTotalCount: 823188
    octetTotalCount: 30472817041
    packetDeltaCount: 241333
    octetDeltaCount: 8982624938
    sourceIPv4Address: 10.10.0.79
    destinationIPv4Address: 10.10.0.80
    reversePacketTotalCount: 471111
    reverseOctetTotalCount: 24500996
    reversePacketDeltaCount: 136211
    reverseOctetDeltaCount: 7083284
    sourcePodName: perftest-a
    sourcePodNamespace: antrea-test
    sourceNodeName: k8s-node-control-plane
    destinationPodName: perftest-b
    destinationPodNamespace: antrea-test
    destinationNodeName: k8s-node-control-plane
    destinationServicePort: 0
    destinationServicePortName:
    ingressNetworkPolicyName: test-flow-aggregator-networkpolicy-ingress-allow
    ingressNetworkPolicyNamespace: antrea-test
    ingressNetworkPolicyType: 1
    ingressNetworkPolicyRuleName:
    ingressNetworkPolicyRuleAction: 1
    egressNetworkPolicyName: test-flow-aggregator-networkpolicy-egress-allow
    egressNetworkPolicyNamespace: antrea-test
    egressNetworkPolicyType: 1
    egressNetworkPolicyRuleName:
    egressNetworkPolicyRuleAction: 1
    tcpState: TIME_WAIT
    flowType: 1
    destinationClusterIPv4: 0.0.0.0
    octetDeltaCountFromSourceNode: 8982624938
    octetDeltaCountFromDestinationNode: 8982624938
    octetTotalCountFromSourceNode: 30472817041
    octetTotalCountFromDestinationNode: 30472817041
    packetDeltaCountFromSourceNode: 241333
    packetDeltaCountFromDestinationNode: 241333
    packetTotalCountFromSourceNode: 823188
    packetTotalCountFromDestinationNode: 823188
    reverseOctetDeltaCountFromSourceNode: 7083284
    reverseOctetDeltaCountFromDestinationNode: 7083284
    reverseOctetTotalCountFromSourceNode: 24500996
    reverseOctetTotalCountFromDestinationNode: 24500996
    reversePacketDeltaCountFromSourceNode: 136211
    reversePacketDeltaCountFromDestinationNode: 136211
    reversePacketTotalCountFromSourceNode: 471111
    reversePacketTotalCountFromDestinationNode: 471111
    flowEndSecondsFromSourceNode: 1637706973
    flowEndSecondsFromDestinationNode: 1637706973
    throughput: 15902813472
    throughputFromSourceNode: 15902813472
    throughputFromDestinationNode: 15902813472
    reverseThroughput: 12381344
    reverseThroughputFromSourceNode: 12381344
    reverseThroughputFromDestinationNode: 12381344
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
	protocolIdentifierTCP          = 6
	// Set target bandwidth(bits/sec) of iPerf traffic to a relatively small value
	// (default unlimited for TCP), to reduce the variances caused by network performance
	// during 12s, and make the throughput test more stable.
	iperfBandwidth = "10m"
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
	defer func() {
		teardownTest(t, data)
		if err := data.disableAntreaFlowExporter(); err != nil {
			t.Errorf("Failed to disable flow exporter in Antrea Agent: %v", err)
		}
		// Execute teardownFlowAggregator later than teardownTest to ensure that the log
		// of Flow Aggregator has been exported.
		teardownFlowAggregator(t, data)
	}()

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
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), podBIPs.ipv4.String(), isIPv6, true, false, true, false)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), podBIPs.ipv6.String(), isIPv6, true, false, true, false)
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
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), podCIPs.ipv4.String(), isIPv6, false, false, false, true)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), podCIPs.ipv6.String(), isIPv6, false, false, false, true)
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
		_, serverIPs, cleanupFunc := createAndWaitForPod(t, data, func(name string, ns string, nodeName string, hostNetwork bool) error {
			return data.createServerPod(name, testNamespace, "", serverPodPort, false, true)
		}, "test-server-", "", testNamespace, false)
		defer cleanupFunc()

		clientName, clientIPs, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", nodeName(0), testNamespace, false)
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
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), svcB.Spec.ClusterIP, isServiceIPv6, true, true, false, false)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), svcB.Spec.ClusterIP, isServiceIPv6, true, true, false, false)
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
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), svcC.Spec.ClusterIP, isServiceIPv6, false, true, false, false)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), svcC.Spec.ClusterIP, isServiceIPv6, false, true, false, false)
		}
	})

	// Antctl tests ensure antctl is available in a Flow Aggregator Pod
	// and check the output of antctl commands.
	t.Run("Antctl", func(t *testing.T) {
		skipIfNotRequired(t, "mode-irrelevant")
		flowAggPod, err := data.getFlowAggregator()
		if err != nil {
			t.Fatalf("Error when getting flow-aggregator Pod: %v", err)
		}
		podName := flowAggPod.Name
		for _, args := range antctl.CommandList.GetDebugCommands(runtime.ModeFlowAggregator) {
			command := []string{}
			if testOptions.enableCoverage {
				antctlCovArgs := antctlCoverageArgs("antctl-coverage")
				command = append(antctlCovArgs, args...)
			} else {
				command = append([]string{"antctl", "-v"}, args...)
			}
			t.Logf("Run command: %s", command)

			t.Run(strings.Join(command, " "), func(t *testing.T) {
				stdout, stderr, err := runAntctl(podName, command, data)
				require.NoErrorf(t, err, "Error when running 'antctl %s' from %s: %v\n%s", args, podName, err, antctlOutput(stdout, stderr))
			})
		}
		t.Run("GetFlowRecordsJson", func(t *testing.T) {
			checkAntctlGetFlowRecordsJson(t, data, podName, podAIPs, podBIPs, isIPv6)
		})
	})
}

func checkAntctlGetFlowRecordsJson(t *testing.T, data *TestData, podName string, podAIPs, podBIPs *PodIPs, isIPv6 bool) {
	// A shorter iperfTime that provides stable test results, at which the first record ready in the AggregationProcess but not sent.
	const iperfTimeSecShort = 5
	var cmdStr, srcIP, dstIP string
	// trigger a flow with iperf
	if !isIPv6 {
		srcIP = podAIPs.ipv4.String()
		dstIP = podBIPs.ipv4.String()
		cmdStr = fmt.Sprintf("iperf3 -c %s -t %d", dstIP, iperfTimeSecShort)
	} else {
		srcIP = podAIPs.ipv6.String()
		dstIP = podBIPs.ipv6.String()
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s -t %d", dstIP, iperfTimeSecShort)
	}
	stdout, _, err := data.RunCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", cmdStr})
	require.NoErrorf(t, err, "Error when running iperf3 client: %v", err)
	_, srcPort, dstPort := getBandwidthAndPorts(stdout)

	// run antctl command on flow aggregator to get flow records
	var command []string
	args := []string{"get", "flowrecords", "-o", "json", "--srcip", srcIP, "--srcport", srcPort}
	if testOptions.enableCoverage {
		antctlCovArgs := antctlCoverageArgs("antctl-coverage")
		command = append(antctlCovArgs, args...)
	} else {
		command = append([]string{"antctl"}, args...)
	}
	t.Logf("Run command: %s", command)
	stdout, stderr, err := runAntctl(podName, command, data)
	require.NoErrorf(t, err, "Error when running 'antctl get flowrecords -o json' from %s: %v\n%s", podName, err, antctlOutput(stdout, stderr))

	var records []map[string]interface{}
	err = json.Unmarshal([]byte(stdout), &records)
	require.NoErrorf(t, err, "Error when parsing flow records from antctl: %v", err)
	require.Len(t, records, 1)

	checkAntctlRecord(t, records[0], srcIP, dstIP, srcPort, dstPort, isIPv6)
}

func checkAntctlRecord(t *testing.T, record map[string]interface{}, srcIP, dstIP, srcPort, dstPort string, isIPv6 bool) {
	assert := assert.New(t)
	if isIPv6 {
		assert.Equal(srcIP, record["sourceIPv6Address"], "The record from antctl does not have correct sourceIPv6Address")
		assert.Equal(dstIP, record["destinationIPv6Address"], "The record from antctl does not have correct destinationIPv6Address")
	} else {
		assert.Equal(srcIP, record["sourceIPv4Address"], "The record from antctl does not have correct sourceIPv4Address")
		assert.Equal(dstIP, record["destinationIPv4Address"], "The record from antctl does not have correct destinationIPv4Address")
	}
	srcPortNum, err := strconv.Atoi(srcPort)
	require.NoErrorf(t, err, "error when converting the iperf srcPort to int type: %s", srcPort)
	assert.EqualValues(srcPortNum, record["sourceTransportPort"], "The record from antctl does not have correct sourceTransportPort")
	assert.Equal("perftest-a", record["sourcePodName"], "The record from antctl does not have correct sourcePodName")
	assert.Equal("antrea-test", record["sourcePodNamespace"], "The record from antctl does not have correct sourcePodNamespace")
	assert.Equal(controlPlaneNodeName(), record["sourceNodeName"], "The record from antctl does not have correct sourceNodeName")

	dstPortNum, err := strconv.Atoi(dstPort)
	require.NoErrorf(t, err, "error when converting the iperf dstPort to int type: %s", dstPort)
	assert.EqualValues(dstPortNum, record["destinationTransportPort"], "The record from antctl does not have correct destinationTransportPort")
	assert.Equal("perftest-b", record["destinationPodName"], "The record from antctl does not have correct destinationPodName")
	assert.Equal("antrea-test", record["destinationPodNamespace"], "The record from antctl does not have correct destinationPodNamespace")
	assert.Equal(controlPlaneNodeName(), record["destinationNodeName"], "The record from antctl does not have correct destinationNodeName")

	assert.EqualValues(ipfixregistry.FlowTypeIntraNode, record["flowType"], "The record from antctl does not have correct flowType")
	assert.EqualValues(protocolIdentifierTCP, record["protocolIdentifier"], "The record from antctl does not have correct protocolIdentifier")
}

func checkRecordsForFlows(t *testing.T, data *TestData, srcIP string, dstIP string, isIPv6 bool, isIntraNode bool, checkService bool, checkK8sNetworkPolicy bool, checkAntreaNetworkPolicy bool) {
	var cmdStr string
	if !isIPv6 {
		cmdStr = fmt.Sprintf("iperf3 -c %s -t %d -b %s", dstIP, iperfTimeSec, iperfBandwidth)
	} else {
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s -t %d -b %s", dstIP, iperfTimeSec, iperfBandwidth)
	}
	stdout, _, err := data.RunCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", cmdStr})
	require.NoErrorf(t, err, "Error when running iperf3 client: %v", err)
	bwSlice, srcPort, _ := getBandwidthAndPorts(stdout)
	require.Equal(t, 2, len(bwSlice), "bandwidth value and / or bandwidth unit are not available")
	// bandwidth from iperf output
	bandwidthInFloat, err := strconv.ParseFloat(bwSlice[0], 64)
	require.NoErrorf(t, err, "Error when converting iperf bandwidth %s to float64 type", bwSlice[0])
	var bandwidthInMbps float64
	if strings.Contains(bwSlice[1], "Mbits") {
		bandwidthInMbps = bandwidthInFloat
	} else {
		t.Fatalf("Unit of the traffic bandwidth reported by iperf should be Mbits.")
	}

	collectorOutput, recordSlices := getCollectorOutput(t, srcIP, dstIP, srcPort, checkService, true, isIPv6, data)
	// Iterate over recordSlices and build some results to test with expected results
	dataRecordsCount := 0
	src, dst := matchSrcAndDstAddress(srcIP, dstIP, checkService, isIPv6)
	for _, record := range recordSlices {
		// Check the source port along with source and destination IPs as there
		// are flow records for control flows during the iperf  with same IPs
		// and destination port.
		if strings.Contains(record, src) && strings.Contains(record, dst) && strings.Contains(record, srcPort) {
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

			// Skip the bandwidth check for the iperf control flow records which have 0 throughput.
			if !strings.Contains(record, "throughput: 0") {
				flowStartTime := int64(getUint64FieldFromRecord(t, record, "flowStartSeconds"))
				exportTime := int64(getUint64FieldFromRecord(t, record, "flowEndSeconds"))
				flowEndReason := int64(getUint64FieldFromRecord(t, record, "flowEndReason"))
				var recBandwidth float64
				// flowEndReason == 3 means the end of flow detected
				if exportTime >= flowStartTime+iperfTimeSec || flowEndReason == 3 {
					// Check average bandwidth on the last record.
					octetTotalCount := getUint64FieldFromRecord(t, record, "octetTotalCount")
					recBandwidth = float64(octetTotalCount) * 8 / float64(iperfTimeSec) / 1000000
				} else {
					// Check bandwidth with the field "throughput" except for the last record,
					// as their throughput may be significantly lower than the average Iperf throughput.
					throughput := getUint64FieldFromRecord(t, record, "throughput")
					recBandwidth = float64(throughput) / 1000000
				}
				t.Logf("Throughput check on record with flowEndSeconds-flowStartSeconds: %v, Iperf throughput: %.2f Mbits/s, IPFIX record throughput: %.2f Mbits/s", exportTime-flowStartTime, bandwidthInMbps, recBandwidth)
				assert.InDeltaf(recBandwidth, bandwidthInMbps, bandwidthInMbps*0.15, "Difference between Iperf bandwidth and IPFIX record bandwidth should be lower than 15%%, record: %s", record)
			}
		}
	}
	// Checking only data records as data records cannot be decoded without template
	// record.
	assert.GreaterOrEqualf(t, dataRecordsCount, expectedNumDataRecords, "IPFIX collector should receive expected number of flow records. Considered records: %s \n Collector output: %s", recordSlices, collectorOutput)
}

func checkRecordsForToExternalFlows(t *testing.T, data *TestData, srcNodeName string, srcPodName string, srcIP string, dstIP string, dstPort int32, isIPv6 bool) {
	var cmd string
	if !isIPv6 {
		cmd = fmt.Sprintf("wget -O- %s:%d", dstIP, dstPort)
	} else {
		cmd = fmt.Sprintf("wget -O- [%s]:%d", dstIP, dstPort)
	}
	stdout, stderr, err := data.RunCommandFromPod(testNamespace, srcPodName, busyboxContainerName, strings.Fields(cmd))
	require.NoErrorf(t, err, "Error when running wget command, stdout: %s, stderr: %s", stdout, stderr)

	_, recordSlices := getCollectorOutput(t, srcIP, dstIP, "", false, false, isIPv6, data)
	for _, record := range recordSlices {
		if strings.Contains(record, srcIP) && strings.Contains(record, dstIP) {
			checkPodAndNodeData(t, record, srcPodName, srcNodeName, "", "")
			checkFlowType(t, record, ipfixregistry.FlowTypeToExternal)
			assert.NotContains(t, record, "octetDeltaCount: 0", "octetDeltaCount should be non-zero")
		}
	}
}

func checkRecordsForDenyFlows(t *testing.T, data *TestData, testFlow1, testFlow2 testFlow, isIPv6 bool, isIntraNode bool, isANP bool) {
	var cmdStr1, cmdStr2 string
	if !isIPv6 {
		cmdStr1 = fmt.Sprintf("iperf3 -c %s -n 1", testFlow1.dstIP)
		cmdStr2 = fmt.Sprintf("iperf3 -c %s -n 1", testFlow2.dstIP)
	} else {
		cmdStr1 = fmt.Sprintf("iperf3 -6 -c %s -n 1", testFlow1.dstIP)
		cmdStr2 = fmt.Sprintf("iperf3 -6 -c %s -n 1", testFlow2.dstIP)
	}
	_, _, err := data.RunCommandFromPod(testNamespace, testFlow1.srcPodName, "", []string{"timeout", "2", "bash", "-c", cmdStr1})
	assert.Error(t, err)
	_, _, err = data.RunCommandFromPod(testNamespace, testFlow2.srcPodName, "", []string{"timeout", "2", "bash", "-c", cmdStr2})
	assert.Error(t, err)

	_, recordSlices1 := getCollectorOutput(t, testFlow1.srcIP, testFlow1.dstIP, "", false, false, isIPv6, data)
	_, recordSlices2 := getCollectorOutput(t, testFlow2.srcIP, testFlow2.dstIP, "", false, false, isIPv6, data)
	recordSlices := append(recordSlices1, recordSlices2...)
	src_flow1, dst_flow1 := matchSrcAndDstAddress(testFlow1.srcIP, testFlow1.dstIP, false, isIPv6)
	src_flow2, dst_flow2 := matchSrcAndDstAddress(testFlow2.srcIP, testFlow2.dstIP, false, isIPv6)
	// Iterate over recordSlices and build some results to test with expected results
	for _, record := range recordSlices {
		var srcPodName, dstPodName string
		if strings.Contains(record, src_flow1) && strings.Contains(record, dst_flow1) {
			srcPodName = testFlow1.srcPodName
			dstPodName = testFlow1.dstPodName
		} else if strings.Contains(record, src_flow2) && strings.Contains(record, dst_flow2) {
			srcPodName = testFlow2.srcPodName
			dstPodName = testFlow2.dstPodName
		}
		if strings.Contains(record, src_flow1) && strings.Contains(record, dst_flow1) || strings.Contains(record, src_flow2) && strings.Contains(record, dst_flow2) {
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

func checkPodAndNodeData(t *testing.T, record, srcPod, srcNode, dstPod, dstNode string) {
	assert := assert.New(t)
	assert.Contains(record, srcPod, "Record with srcIP does not have Pod name: %s", srcPod)
	assert.Contains(record, fmt.Sprintf("sourcePodNamespace: %s", testNamespace), "Record does not have correct sourcePodNamespace: %s", testNamespace)
	assert.Contains(record, fmt.Sprintf("sourceNodeName: %s", srcNode), "Record does not have correct sourceNodeName: %s", srcNode)
	// For Pod-To-External flow type, we send traffic to an external address,
	// so we skip the verification of destination Pod info.
	// Also, source Pod labels are different for Pod-To-External flow test.
	if dstPod != "" {
		assert.Contains(record, dstPod, "Record with dstIP does not have Pod name: %s", dstPod)
		assert.Contains(record, fmt.Sprintf("destinationPodNamespace: %s", testNamespace), "Record does not have correct destinationPodNamespace: %s", testNamespace)
		assert.Contains(record, fmt.Sprintf("destinationNodeName: %s", dstNode), "Record does not have correct destinationNodeName: %s", dstNode)
		assert.Contains(record, fmt.Sprintf("{\"antrea-e2e\":\"%s\",\"app\":\"perftool\"}", srcPod), "Record does not have correct label for source Pod")
		assert.Contains(record, fmt.Sprintf("{\"antrea-e2e\":\"%s\",\"app\":\"perftool\"}", dstPod), "Record does not have correct label for destination Pod")
	} else {
		assert.Contains(record, fmt.Sprintf("{\"antrea-e2e\":\"%s\",\"app\":\"busybox\"}", srcPod), "Record does not have correct label for source Pod")
	}
}

func checkFlowType(t *testing.T, record string, flowType uint8) {
	assert.Containsf(t, record, fmt.Sprintf("flowType: %d", flowType), "Record does not have correct flowType")
}

func getUint64FieldFromRecord(t *testing.T, record string, field string) uint64 {
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
func getCollectorOutput(t *testing.T, srcIP, dstIP, srcPort string, isDstService bool, checkAllRecords bool, isIPv6 bool, data *TestData) (string, []string) {
	var collectorOutput string
	var recordSlices []string
	// In the ToExternalFlows test, flow record will arrive 5.5s (exporterActiveFlowExportTimeout+aggregatorActiveFlowRecordTimeout) after executing wget command
	// We set the timeout to 9s (5.5s plus one more aggregatorActiveFlowRecordTimeout) to make the ToExternalFlows test more stable
	err := wait.PollImmediate(500*time.Millisecond, exporterActiveFlowExportTimeout+aggregatorActiveFlowRecordTimeout*2, func() (bool, error) {
		var rc int
		var err error
		// `pod-running-timeout` option is added to cover scenarios where ipfix flow-collector has crashed after being deployed
		rc, collectorOutput, _, err = data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl logs --pod-running-timeout=%v ipfix-collector -n antrea-test", aggregatorInactiveFlowRecordTimeout.String()))
		if err != nil || rc != 0 {
			return false, err
		}
		// Checking that all the data records which correspond to the iperf flow are received
		recordSlices = getRecordsFromOutput(collectorOutput)
		src, dst := matchSrcAndDstAddress(srcIP, dstIP, isDstService, isIPv6)
		if checkAllRecords {
			for _, record := range recordSlices {
				flowStartTime := int64(getUint64FieldFromRecord(t, record, "flowStartSeconds"))
				exportTime := int64(getUint64FieldFromRecord(t, record, "flowEndSeconds"))
				flowEndReason := int64(getUint64FieldFromRecord(t, record, "flowEndReason"))
				if strings.Contains(record, src) && strings.Contains(record, dst) && strings.Contains(record, srcPort) {
					// flowEndReason == 3 means the end of flow detected
					if exportTime >= flowStartTime+iperfTimeSec || flowEndReason == 3 {
						return true, nil
					}
				}
			}
			return false, nil
		}
		return strings.Contains(collectorOutput, src) && strings.Contains(collectorOutput, dst) && strings.Contains(collectorOutput, srcPort), nil
	})
	require.NoErrorf(t, err, "IPFIX collector did not receive the expected records in collector output: %v iperf source port: %s", collectorOutput, srcPort)
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
	builder1 = builder1.AddIngress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{},
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
	builder2 = builder2.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": dstPod}, map[string]string{},
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
		builder1 = builder1.AddIngress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionReject, testIngressRuleName)
		builder2 = builder2.SetName(testNamespace, ingressDropANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": podDrop}}})
		builder2 = builder2.AddIngress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionDrop, testIngressRuleName)
	} else {
		// apply reject and drop egress rule to source pod
		builder1 = builder1.SetName(testNamespace, egressRejectANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
		builder1 = builder1.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": podReject}, map[string]string{},
			nil, nil, nil, secv1alpha1.RuleActionReject, testEgressRuleName)
		builder2 = builder2.SetName(testNamespace, egressDropANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
		builder2 = builder2.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": podDrop}, map[string]string{},
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

	svcB, err = data.CreateService("perftest-b", testNamespace, iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"}, false, false, corev1.ServiceTypeClusterIP, &svcIPFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when creating perftest-b Service: %v", err)
	}

	svcC, err = data.CreateService("perftest-c", testNamespace, iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-c"}, false, false, corev1.ServiceTypeClusterIP, &svcIPFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when creating perftest-c Service: %v", err)
	}

	return svcB, svcC, nil
}

func deletePerftestServices(t *testing.T, data *TestData) {
	for _, serviceName := range []string{"perftest-b", "perftest-c"} {
		err := data.deleteService(testNamespace, serviceName)
		if err != nil {
			t.Logf("Error when deleting %s Service: %v", serviceName, err)
		}
	}
}

// getBandwidthAndPorts parses iperf commands output and returns bandwidth,
// source port and destination port. Bandwidth is returned as a slice containing
// two strings (bandwidth value and bandwidth unit).
func getBandwidthAndPorts(iperfStdout string) ([]string, string, string) {
	var bandwidth []string
	var srcPort, dstPort string
	outputLines := strings.Split(iperfStdout, "\n")
	for _, line := range outputLines {
		if strings.Contains(line, "sender") {
			fields := strings.Fields(line)
			bandwidth = fields[6:8]
		}
		if strings.Contains(line, "connected") {
			fields := strings.Fields(line)
			srcPort = fields[5]
			dstPort = fields[10]
		}
	}
	return bandwidth, srcPort, dstPort
}

func matchSrcAndDstAddress(srcIP string, dstIP string, isDstService bool, isIPv6 bool) (string, string) {
	srcField := fmt.Sprintf("sourceIPv4Address: %s", srcIP)
	dstField := fmt.Sprintf("destinationIPv4Address: %s", dstIP)
	if isDstService {
		dstField = fmt.Sprintf("destinationClusterIPv4: %s", dstIP)
	}
	if isIPv6 {
		srcField = fmt.Sprintf("sourceIPv6Address: %s", srcIP)
		dstField = fmt.Sprintf("destinationIPv6Address: %s", dstIP)
		if isDstService {
			dstField = fmt.Sprintf("destinationClusterIPv6: %s", dstIP)
		}
	}
	return srcField, dstField
}
