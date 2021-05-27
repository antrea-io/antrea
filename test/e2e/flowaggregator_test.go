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
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	secv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
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
    egressNetworkPolicyName: test-flow-aggregator-networkpolicy-egress
    egressNetworkPolicyNamespace: antrea-test
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

Intra-Node: Flow record information is complete for source and destination e.g. sourcePodName, destinationPodName
Inter-Node: Flow record from destination Node is ignored, so only flow record from the source Node has its K8s info e.g., sourcePodName, sourcePodNamespace, sourceNodeName etc.
AntreaProxy enabled (Intra-Node): Flow record information is complete for source and destination along with K8s service info such as destinationClusterIP, destinationServicePort, destinationServicePortName etc.
AntreaProxy enabled (Inter-Node): Flow record from destination Node is ignored, so only flow record from the source Node has its K8s info like in Inter-Node case along with K8s Service info such as destinationClusterIP, destinationServicePort, destinationServicePortName etc.
*/

const (
	ingressAllowNetworkPolicyName = "test-flow-aggregator-networkpolicy-ingress-allow"
	ingressRejectANPName          = "test-flow-aggregator-anp-ingress-reject"
	ingressDropANPName            = "test-flow-aggregator-anp-ingress-drop"
	ingressDenyNPName             = "test-flow-aggregator-np-ingress-deny"
	egressAllowNetworkPolicyName  = "test-flow-aggregator-networkpolicy-egress-allow"
	egressRejectANPName           = "test-flow-aggregator-anp-engress-reject"
	egressDropANPName             = "test-flow-aggregator-anp-engress-drop"
	egressDenyNPName              = "test-flow-aggregator-np-egress-deny"
	collectorCheckTimeout         = 10 * time.Second
	// Single iperf run results in two connections with separate ports (control connection and actual data connection).
	// As 5s is export interval and iperf traffic runs for 10s, we expect about 4 records exporting to the flow aggregator.
	// Since flow aggregator will aggregate records based on 5-tuple connection key, we expect 2 records.
	expectedNumDataRecords = 2
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

	// IntraNodeFlows tests the case, where Pods are deployed on same Node and their flow information is exported as IPFIX flow records.
	t.Run("IntraNodeFlows", func(t *testing.T) {
		np1, np2 := deployNetworkPolicies(t, data, "perftest-a", "perftest-b")
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
		// TODO: Skipping bandwidth check for Intra-Node flows as it is flaky.
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
		skipIfAntreaPolicyDisabled(t, data)
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
		skipIfAntreaPolicyDisabled(t, data)
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
		skipIfAntreaPolicyDisabled(t, data)
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
	t.Run("InterNodeFlows", func(t *testing.T) {
		np1, np2 := deployNetworkPolicies(t, data, "perftest-a", "perftest-c")
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
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), podCIPs.ipv4.String(), isIPv6, false, false, true, true)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), podCIPs.ipv6.String(), isIPv6, false, false, true, true)
		}
	})

	// InterNodeDenyConnIngressANP tests the case, where Pods are deployed on different Nodes with an Antrea ingress deny policy rule
	// applied to destination Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-c (Ingress reject), perftest-a -> perftest-e (Ingress drop)
	t.Run("InterNodeDenyConnIngressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t, data)
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
		skipIfAntreaPolicyDisabled(t, data)
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
		skipIfAntreaPolicyDisabled(t, data)
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

	// LocalServiceAccess tests the case, where Pod and Service are deployed on the same Node and their flow information is exported as IPFIX flow records.
	t.Run("LocalServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t, data)
		// TODO: Skipping bandwidth check for LocalServiceAccess flows as it is flaky.
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), svcB.Spec.ClusterIP, isIPv6, true, true, false, false)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), svcB.Spec.ClusterIP, isIPv6, true, true, false, false)
		}
	})

	// RemoteServiceAccess tests the case, where Pod and Service are deployed on different Nodes and their flow information is exported as IPFIX flow records.
	t.Run("RemoteServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t, data)
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIPs.ipv4.String(), svcC.Spec.ClusterIP, isIPv6, false, true, false, true)
		} else {
			checkRecordsForFlows(t, data, podAIPs.ipv6.String(), svcC.Spec.ClusterIP, isIPv6, false, true, false, true)
		}
	})
}

func checkRecordsForFlows(t *testing.T, data *TestData, srcIP string, dstIP string, isIPv6 bool, isIntraNode bool, checkService bool, checkNetworkPolicy bool, checkBandwidth bool) {
	timeStart := time.Now()
	var cmdStr string
	if !isIPv6 {
		cmdStr = fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", dstIP)
	} else {
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s|grep sender|awk '{print $7,$8}'", dstIP)
	}
	stdout, _, err := data.runCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", cmdStr})
	if err != nil {
		t.Errorf("Error when running iperf3 client: %v", err)
	}
	bandwidth := strings.TrimSpace(stdout)

	// Polling to make sure all the data records corresponding to the iperf flow
	// are received.
	err = wait.Poll(250*time.Millisecond, collectorCheckTimeout, func() (bool, error) {
		rc, collectorOutput, _, err := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl logs --since=%v ipfix-collector -n antrea-test", time.Since(timeStart).String()))
		if err != nil || rc != 0 {
			return false, err
		}
		return strings.Count(collectorOutput, srcIP) >= expectedNumDataRecords && strings.Count(collectorOutput, dstIP) >= expectedNumDataRecords, nil
	})
	require.NoErrorf(t, err, "IPFIX collector did not receive the expected records and timed out with error: %v", err)

	rc, collectorOutput, _, err := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl logs --since=%v ipfix-collector -n antrea-test", time.Since(timeStart).String()))
	if err != nil || rc != 0 {
		t.Errorf("Error when getting logs %v, rc: %v", err, rc)
	}

	// Iterate over recordSlices and build some results to test with expected results
	recordSlices := getRecordsFromOutput(collectorOutput)
	dataRecordsCount := 0
	for _, record := range recordSlices {
		if strings.Contains(record, srcIP) && strings.Contains(record, dstIP) {
			dataRecordsCount = dataRecordsCount + 1
			// In Kind clusters, there are two flow records for the iperf flow.
			// One of them has no bytes and we ignore that flow record.
			if !strings.Contains(record, "octetDeltaCount: 0") {
				// Check if record has both Pod name of source and destination pod.
				if isIntraNode {
					checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-b", controlPlaneNodeName())
					checkFlowType(t, record, ipfixregistry.FlowTypeIntraNode)
				} else {
					checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-c", workerNodeName(1))
					checkFlowType(t, record, ipfixregistry.FlowTypeInterNode)
				}

				if checkService {
					if isIntraNode {
						if !strings.Contains(record, "antrea-test/perftest-b") {
							t.Errorf("Record with ServiceIP does not have Service name")
						}
					} else {
						if !strings.Contains(record, "antrea-test/perftest-c") {
							t.Errorf("Record with ServiceIP does not have Service name")
						}
					}
				}
				if checkNetworkPolicy {
					// Check if records have both ingress and egress network policies.
					if !strings.Contains(record, ingressAllowNetworkPolicyName) {
						t.Errorf("Record does not have NetworkPolicy name with ingress rule")
					}
					if !strings.Contains(record, fmt.Sprintf("%s: %s", "ingressNetworkPolicyNamespace", testNamespace)) {
						t.Errorf("Record does not have correct ingressNetworkPolicyNamespace")
					}
					if !strings.Contains(record, egressAllowNetworkPolicyName) {
						t.Errorf("Record does not have NetworkPolicy name with egress rule")
					}
					if !strings.Contains(record, fmt.Sprintf("%s: %s", "egressNetworkPolicyNamespace", testNamespace)) {
						t.Errorf("Record does not have correct egressNetworkPolicyNamespace")
					}
				}
				// Check the bandwidth using octetDeltaCount in data record.
				if checkBandwidth {
					checkBandwidthFromRecord(t, record, bandwidth)
				}
			}
		}
	}
	// Checking only data records as data records cannot be decoded without template
	// record.
	assert.GreaterOrEqualf(t, dataRecordsCount, expectedNumDataRecords, "IPFIX collector should receive expected number of flow records. Considered records: ", len(recordSlices))
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

	err = wait.Poll(250*time.Millisecond, collectorCheckTimeout, func() (bool, error) {
		rc, collectorOutput, _, err := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl logs --since=%v ipfix-collector -n antrea-test", time.Since(timeStart).String()))
		if err != nil || rc != 0 {
			return false, err
		}
		return strings.Contains(collectorOutput, testFlow1.srcIP) && strings.Contains(collectorOutput, testFlow2.srcIP), nil
	})
	require.NoErrorf(t, err, "IPFIX collector did not receive the expected records and timed out with error: %v", err)

	rc, collectorOutput, _, err := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl logs --since=%v ipfix-collector -n antrea-test", time.Since(timeStart).String()))
	if err != nil || rc != 0 {
		t.Errorf("Error when getting logs %v, rc: %v", err, rc)
	}

	// Iterate over recordSlices and build some results to test with expected results
	recordSlices := getRecordsFromOutput(collectorOutput)
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

			if !isANP { // K8s Network Policies
				if strings.Contains(record, ingressDropStr) && !strings.Contains(record, ingressDropANPName) {
					assert.Contains(t, record, testFlow1.dstIP)
				} else if strings.Contains(record, egressDropStr) && !strings.Contains(record, egressDropANPName) {
					assert.Contains(t, record, testFlow2.dstIP)
				}
			} else { // Antrea Network Policies
				if strings.Contains(record, ingressRejectStr) {
					assert.Contains(t, record, ingressRejectANPName, "Record does not have Antrea NetworkPolicy name with ingress reject rule")
					assert.Contains(t, record, fmt.Sprintf("%s: %s", "ingressNetworkPolicyNamespace", testNamespace), "Record does not have correct ingressNetworkPolicyNamespace")
				} else if strings.Contains(record, ingressDropStr) {
					assert.Contains(t, record, ingressDropANPName, "Record does not have Antrea NetworkPolicy name with ingress drop rule")
					assert.Contains(t, record, fmt.Sprintf("%s: %s", "ingressNetworkPolicyNamespace", testNamespace), "Record does not have correct ingressNetworkPolicyNamespace")
				} else if strings.Contains(record, egressRejectStr) {
					assert.Contains(t, record, egressRejectANPName, "Record does not have Antrea NetworkPolicy name with egress reject rule")
					assert.Contains(t, record, fmt.Sprintf("%s: %s", "egressNetworkPolicyNamespace", testNamespace), "Record does not have correct egressNetworkPolicyNamespace")
				} else if strings.Contains(record, egressDropStr) {
					assert.Contains(t, record, egressDropANPName, "Record does not have Antrea NetworkPolicy name with egress drop rule")
					assert.Contains(t, record, fmt.Sprintf("%s: %s", "egressNetworkPolicyNamespace", testNamespace), "Record does not have correct egressNetworkPolicyNamespace")
				}
			}

		}
	}
}

func checkPodAndNodeData(t *testing.T, record, srcPod, srcNode, dstPod, dstNode string) {
	if !strings.Contains(record, srcPod) {
		t.Errorf("Record with srcIP does not have Pod name")
	}
	if !strings.Contains(record, fmt.Sprintf("%s: %s", "sourcePodNamespace", testNamespace)) {
		t.Errorf("Record does not have correct sourcePodNamespace")
	}
	if !strings.Contains(record, fmt.Sprintf("%s: %s", "sourceNodeName", srcNode)) {
		t.Errorf("Record does not have correct sourceNodeName")
	}
	if !strings.Contains(record, dstPod) {
		t.Errorf("Record with dstIP does not have Pod name")
	}
	if !strings.Contains(record, fmt.Sprintf("%s: %s", "destinationPodNamespace", testNamespace)) {
		t.Errorf("Record does not have correct destinationPodNamespace")
	}
	if !strings.Contains(record, fmt.Sprintf("%s: %s", "destinationNodeName", dstNode)) {
		t.Errorf("Record does not have correct destinationNodeName")
	}
}

func checkBandwidthFromRecord(t *testing.T, record, bandwidth string) {
	// Split the record in lines to compute bandwidth
	splitLines := strings.Split(record, "\n")
	for _, line := range splitLines {
		if strings.Contains(line, "octetDeltaCount:") {
			lineSlice := strings.Split(line, ":")
			deltaBytes, err := strconv.ParseFloat(strings.TrimSpace(lineSlice[1]), 64)
			if err != nil {
				t.Errorf("Error in converting octetDeltaCount to float type")
			}
			// Flow Aggregator uses 5s as export interval; we use
			// 2s as export interval for Flow Exporter.
			recBandwidth := (deltaBytes * 8.0) / float64(5*time.Second.Nanoseconds())
			// bandwidth from iperf output
			bwSlice := strings.Split(bandwidth, " ")
			iperfBandwidth, err := strconv.ParseFloat(bwSlice[0], 64)
			if err != nil {
				t.Errorf("Error in converting iperf bandwidth to float64 type")
			}
			if strings.Contains(bwSlice[1], "Mbits") {
				iperfBandwidth = iperfBandwidth / float64(1000)
			}
			t.Logf("Iperf bandwidth: %v", iperfBandwidth)
			t.Logf("IPFIX record bandwidth: %v", recBandwidth)
			// TODO: Make bandwidth test more robust.
			assert.InDeltaf(t, recBandwidth, iperfBandwidth, 10, "Difference between Iperf bandwidth and IPFIX record bandwidth should be lower than 10")
			break
		}
	}
}

// TODO: Add a test that checks the functionality of Pod-To-External flow.
func checkFlowType(t *testing.T, record string, flowType uint8) {
	assert.Containsf(t, record, fmt.Sprintf("%s: %d", "flowType", flowType), "Record does not have correct flowType")
}

func getRecordsFromOutput(output string) []string {
	re := regexp.MustCompile("(?m)^.*" + "#" + ".*$[\r\n]+")
	output = re.ReplaceAllString(output, "")
	output = strings.TrimSpace(output)
	recordSlices := strings.Split(output, "IPFIX-HDR:")
	// Delete the first element from recordSlices
	recordSlices[0] = recordSlices[len(recordSlices)-1]
	recordSlices[len(recordSlices)-1] = ""
	recordSlices = recordSlices[:len(recordSlices)-1]
	return recordSlices
}

func deployNetworkPolicies(t *testing.T, data *TestData, srcPod, dstPod string) (np1 *networkingv1.NetworkPolicy, np2 *networkingv1.NetworkPolicy) {
	// Add NetworkPolicy between two iperf Pods.
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

func deployDenyAntreaNetworkPolicies(t *testing.T, data *TestData, srcPod, podReject, podDrop string, isIngress bool) (anp1 *secv1alpha1.NetworkPolicy, anp2 *secv1alpha1.NetworkPolicy) {
	var err error
	k8sUtils, _ = NewKubernetesUtils(data)
	if isIngress {
		if anp1, err = data.createANPDenyIngress("antrea-e2e", podReject, ingressRejectANPName, true); err != nil {
			t.Fatalf("Error when creating Antrea NetworkPolicy: %v", err)
		}
		if anp2, err = data.createANPDenyIngress("antrea-e2e", podDrop, ingressDropANPName, false); err != nil {
			t.Fatalf("Error when creating Antrea NetworkPolicy: %v", err)
		}
	} else {
		if anp1, err = data.createANPDenyEgress(srcPod, podReject, egressRejectANPName, true); err != nil {
			t.Fatalf("Error when creating Antrea NetworkPolicy: %v", err)
		}
		if anp2, err = data.createANPDenyEgress(srcPod, podDrop, egressDropANPName, false); err != nil {
			t.Fatalf("Error when creating Antrea NetworkPolicy: %v", err)
		}
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
	if err := data.createPodOnNode("perftest-a", controlPlaneNodeName(), perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest client Pod: %v", err)
	}
	podAIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-a", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when waiting for the perftest client Pod: %v", err)
	}

	if err := data.createPodOnNode("perftest-b", controlPlaneNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podBIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-c", workerNodeName(1), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podCIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-c", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-d", controlPlaneNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podDIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-d", testNamespace)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-e", workerNodeName(1), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
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

	svcB, err = data.createService("perftest-b", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"}, false, v1.ServiceTypeClusterIP, &svcIPFamily)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when creating perftest-b Service: %v", err)
	}

	svcC, err = data.createService("perftest-c", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-c"}, false, v1.ServiceTypeClusterIP, &svcIPFamily)
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

// createANPDenyEgress creates an Antrea NetworkPolicy that denies egress traffic for pods of specific label.
func (data *TestData) createANPDenyEgress(srcPod, dstPod, name string, isReject bool) (*secv1alpha1.NetworkPolicy, error) {
	dropACT := secv1alpha1.RuleActionDrop
	if isReject {
		dropACT = secv1alpha1.RuleActionReject
	}
	anp := secv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-e2e": srcPod,
			},
		},
		Spec: secv1alpha1.NetworkPolicySpec{
			Tier:     defaultTierName,
			Priority: 250,
			AppliedTo: []secv1alpha1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"antrea-e2e": srcPod,
						},
					},
				},
			},
			Ingress: []secv1alpha1.Rule{},
			Egress: []secv1alpha1.Rule{
				{
					Action: &dropACT,
					Ports:  []secv1alpha1.NetworkPolicyPort{},
					From:   []secv1alpha1.NetworkPolicyPeer{},
					To: []secv1alpha1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"antrea-e2e": dstPod,
								},
							},
						},
					},
				},
			},
		},
	}
	anpCreated, err := k8sUtils.crdClient.CrdV1alpha1().NetworkPolicies(testNamespace).Create(context.TODO(), &anp, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return anpCreated, nil
}
