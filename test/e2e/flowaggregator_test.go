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
	ingressNetworkPolicyName = "test-flow-aggregator-networkpolicy-ingress"
	egressNetworkPolicyName  = "test-flow-aggregator-networkpolicy-egress"
	collectorCheckTimeout    = 10 * time.Second
	// Single iperf run results in two connections with separate ports (control connection and actual data connection).
	// As 5s is export interval and iperf traffic runs for 10s, we expect about 4 records exporting to the flow aggregator.
	// Since flow aggregator will aggregate records based on 5-tuple connection key, we expect 2 records.
	expectedNumDataRecords = 2
)

func TestFlowAggregator(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, v4Enabled, v6Enabled, err := setupTestWithIPFIXCollector(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	defer teardownFlowAggregator(t, data)

	podAIPs, podBIPs, podCIPs, err := createPerftestPods(data)
	if err != nil {
		t.Fatalf("Error when creating perftest Pods: %v", err)
	}

	if v4Enabled {
		t.Run("IPv4", func(t *testing.T) { testHelper(t, data, podAIPs, podBIPs, podCIPs, false) })
	}

	if v6Enabled {
		t.Run("IPv6", func(t *testing.T) { testHelper(t, data, podAIPs, podBIPs, podCIPs, true) })
	}
}

func testHelper(t *testing.T, data *TestData, podAIPs *PodIPs, podBIPs *PodIPs, podCIPs *PodIPs, isIPv6 bool) {
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
					checkFlowType(t, record, ipfixregistry.IntraNode)
				} else {
					checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-c", workerNodeName(1))
					checkFlowType(t, record, ipfixregistry.InterNode)
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
					if !strings.Contains(record, ingressNetworkPolicyName) {
						t.Errorf("Record does not have NetworkPolicy name with ingress rule")
					}
					if !strings.Contains(record, fmt.Sprintf("%s: %s", "ingressNetworkPolicyNamespace", testNamespace)) {
						t.Errorf("Record does not have correct ingressNetworkPolicyNamespace")
					}
					if !strings.Contains(record, egressNetworkPolicyName) {
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
	np1, err = data.createNetworkPolicy(ingressNetworkPolicyName, &networkingv1.NetworkPolicySpec{
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
	np2, err = data.createNetworkPolicy(egressNetworkPolicyName, &networkingv1.NetworkPolicySpec{
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

func createPerftestPods(data *TestData) (podAIPs *PodIPs, podBIPs *PodIPs, podCIPs *PodIPs, err error) {
	if err := data.createPodOnNode("perftest-a", controlPlaneNodeName(), perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("Error when creating the perftest client Pod: %v", err)
	}
	podAIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-a", testNamespace)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when waiting for the perftest client Pod: %v", err)
	}

	if err := data.createPodOnNode("perftest-b", controlPlaneNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podBIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}

	if err := data.createPodOnNode("perftest-c", workerNodeName(1), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podCIPs, err = data.podWaitForIPs(defaultTimeout, "perftest-c", testNamespace)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when getting the perftest server Pod's IPs: %v", err)
	}
	return podAIPs, podBIPs, podCIPs, nil
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
