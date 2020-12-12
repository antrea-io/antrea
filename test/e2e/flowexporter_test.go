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

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

/* Sample output from the collector:
IPFIX-HDR:
  version: 10,  Message Length: 288
  Exported Time: 1605749238 (2020-11-19 01:27:18 +0000 UTC)
  Sequence No.: 9,  Observation Domain ID: 2134708971
DATA SET:
  DATA RECORD-0:
    flowStartSeconds: 1605749227
    flowEndSeconds: 2288912640
    sourceIPv4Address: 10.10.0.27
    destinationIPv4Address: 10.10.0.28
    sourceTransportPort: 34540
    destinationTransportPort: 5201
    protocolIdentifier: 6
    packetTotalCount: 1037047
    octetTotalCount: 45371902943
    packetDeltaCount: 410256
    octetDeltaCount: 18018632100
    reversePacketTotalCount: 854967
    reverseOctetTotalCount: 44461736
    reversePacketDeltaCount: 330362
    reverseOctetDeltaCount: 17180264
    sourcePodName: perftest-a
    sourcePodNamespace: antrea-test
    sourceNodeName: k8s-node-master
    destinationPodName: perftest-b
    destinationPodNamespace: antrea-test
    destinationNodeName: k8s-node-master
    destinationClusterIPv4: 10.103.234.179
    destinationServicePortName: antrea-test/perftest-b:
    ingressNetworkPolicyName: test-networkpolicy-ingress
    ingressNetworkPolicyNamespace: antrea-test
    egressNetworkPolicyName: test-networkpolicy-egress
    egressNetworkPolicyNamespace: antrea-test

Intra-Node: Flow record information is complete for source and destination e.g. sourcePodName, destinationPodName
Inter-Node: Flow record from destination Node is ignored, so only flow record from the source Node has its K8s info e.g., sourcePodName, sourcePodNamespace, sourceNodeName etc.
AntreaProxy enabled (Intra-Node): Flow record information is complete for source and destination along with K8s service info such as destinationClusterIP, destinationServicePort, destinationServicePortName etc.
AntreaProxy enabled (Inter-Node): Flow record from destination Node is ignored, so only flow record from the source Node has its K8s info like in Inter-Node case along with K8s Service info such as destinationClusterIP, destinationServicePort, destinationServicePortName etc.
*/

func TestFlowExporter(t *testing.T) {
	// Should I add skipBenchmark as this runs iperf?
	data, err, isIPv6 := setupTestWithIPFIXCollector(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	if err := data.createPodOnNode("perftest-a", masterNodeName(), perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		t.Errorf("Error when creating the perftest client Pod: %v", err)
	}
	podAIP, err := data.podWaitForIPs(defaultTimeout, "perftest-a", testNamespace)
	if err != nil {
		t.Errorf("Error when waiting for the perftest client Pod: %v", err)
	}

	svcB, err := data.createService("perftest-b", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"}, false, v1.ServiceTypeClusterIP)
	if err != nil {
		t.Errorf("Error when creating perftest service: %v", err)
	}

	if err := data.createPodOnNode("perftest-b", masterNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podBIP, err := data.podWaitForIPs(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		t.Errorf("Error when getting the perftest server Pod's IP: %v", err)
	}

	svcC, err := data.createService("perftest-c", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-c"}, false, v1.ServiceTypeClusterIP)
	if err != nil {
		t.Errorf("Error when creating perftest service: %v", err)
	}

	if err := data.createPodOnNode("perftest-c", workerNodeName(1), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Errorf("Error when creating the perftest server Pod: %v", err)
	}
	podCIP, err := data.podWaitForIPs(defaultTimeout, "perftest-c", testNamespace)
	if err != nil {
		t.Errorf("Error when getting the perftest server Pod's IP: %v", err)
	}

	// IntraNodeFlows tests the case, where Pods are deployed on same Node and their flow information is exported as IPFIX flow records.
	t.Run("IntraNodeFlows", func(t *testing.T) {
		np1, np2 := deployNetworkPolicies(t, data)
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
			checkRecordsForFlows(t, data, podAIP.ipv4.String(), podBIP.ipv4.String(), isIPv6, true, false, true)
		} else {
			checkRecordsForFlows(t, data, podAIP.ipv6.String(), podBIP.ipv6.String(), isIPv6, true, false, true)
		}
	})
	// InterNodeFlows tests the case, where Pods are deployed on different Nodes and their flow information is exported as IPFIX flow records.
	t.Run("InterNodeFlows", func(t *testing.T) {
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIP.ipv4.String(), podCIP.ipv4.String(), isIPv6, false, false, false)
		} else {
			checkRecordsForFlows(t, data, podAIP.ipv6.String(), podCIP.ipv6.String(), isIPv6, false, false, false)
		}
	})

	// LocalServiceAccess tests the case, where Pod and Service are deployed on the same Node and their flow information is exported as IPFIX flow records.
	t.Run("LocalServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t, data)
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIP.ipv4.String(), svcB.Spec.ClusterIP, isIPv6, true, true, false)
		} else {
			checkRecordsForFlows(t, data, podAIP.ipv6.String(), svcB.Spec.ClusterIP, isIPv6, true, true, false)
		}
	})

	// RemoteServiceAccess tests the case, where Pod and Service are deployed on different Nodes and their flow information is exported as IPFIX flow records.
	t.Run("RemoteServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t, data)
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIP.ipv4.String(), svcC.Spec.ClusterIP, isIPv6, false, true, false)
		} else {
			checkRecordsForFlows(t, data, podAIP.ipv6.String(), svcC.Spec.ClusterIP, isIPv6, false, true, false)
		}
	})
}

func checkRecordsForFlows(t *testing.T, data *TestData, srcIP string, dstIP string, isIPv6 bool, isIntraNode bool, checkService bool, checkNetworkPolicy bool) {
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

	// Adding some delay to make sure all the data records corresponding to iperf flow are received.
	time.Sleep(250 * time.Millisecond)

	rc, collectorOutput, _, err := provider.RunCommandOnNode(masterNodeName(), fmt.Sprintf("kubectl logs ipfix-collector -n antrea-test"))
	if err != nil || rc != 0 {
		t.Errorf("Error when getting logs %v, rc: %v", err, rc)
	}
	recordSlices := getRecordsFromOutput(collectorOutput)
	// Iterate over recordSlices and build some results to test with expected results
	templateRecords := 0
	dataRecordsCount := 0
	for _, record := range recordSlices {
		if strings.Contains(record, "TEMPLATE RECORD") {
			templateRecords = templateRecords + 1
		}

		if strings.Contains(record, srcIP) && strings.Contains(record, dstIP) {
			dataRecordsCount = dataRecordsCount + 1
			// Check if records have both Pod name and Pod namespace or not.
			if !strings.Contains(record, "perftest-a") {
				t.Errorf("Records with srcIP does not have Pod name")
			}
			if !strings.Contains(record, "perftest-b") && isIntraNode {
				t.Errorf("Records with dstIP does not have Pod name")
			}
			if checkService {
				if !strings.Contains(record, "antrea-test/perftest-b") && isIntraNode {
					t.Errorf("Records with ServiceIP does not have Service name")
				}
				if !strings.Contains(record, "antrea-test/perftest-c") && !isIntraNode {
					t.Errorf("Records with ServiceIP does not have Service name")
				}
			}
			if !strings.Contains(record, testNamespace) {
				t.Errorf("Records do not have Pod Namespace")
			}
			// In Kind clusters, there are two flow records for the iperf flow.
			// One of them has no bytes and we ignore that flow record.
			if checkNetworkPolicy && !strings.Contains(record, "octetDeltaCount: 0") {
				// Check if records have both ingress and egress network policies.
				if !strings.Contains(record, "test-flow-exporter-networkpolicy-ingress") {
					t.Errorf("Records does not have NetworkPolicy name with ingress rule")
				}
				if !strings.Contains(record, "test-flow-exporter-networkpolicy-egress") {
					t.Errorf("Records does not have NetworkPolicy name with egress rule")
				}
			}
			// Check the bandwidth using octetDeltaCount in data records sent in second ipfix interval
			if strings.Contains(record, "seqno=2") || strings.Contains(record, "seqno=3") {
				// In Kind clusters, there are two flow records for the iperf flow.
				// One of them has no bytes and we ignore that flow record.
				if !strings.Contains(record, "octetDeltaCount: 0") {
					//split the record in lines to compute bandwidth
					splitLines := strings.Split(record, "\n")
					for _, line := range splitLines {
						if strings.Contains(line, "octetDeltaCount") {
							lineSlice := strings.Split(line, ":")
							deltaBytes, err := strconv.ParseFloat(strings.TrimSpace(lineSlice[1]), 64)
							if err != nil {
								t.Errorf("Error in converting octetDeltaCount to int type")
							}
							// compute the bandwidth using 5s as interval
							recBandwidth := (deltaBytes * 8.0) / float64(5*time.Second.Nanoseconds())
							// bandwidth from iperf output
							bwSlice := strings.Split(bandwidth, " ")
							iperfBandwidth, err := strconv.ParseFloat(bwSlice[0], 64)
							if err != nil {
								t.Errorf("Error in converting iperf bandwidth to float64 type")
							}
							t.Logf("Iperf bandwidth: %v", iperfBandwidth)
							t.Logf("IPFIX record bandwidth: %v", recBandwidth)
							assert.InDeltaf(t, recBandwidth, iperfBandwidth, 5, "Difference between Iperf bandwidth and IPFIX record bandwidth should be less than 5Gb/s")
							break
						}
					}
				}
			}
		}
	}
	expectedNumTemplateRecords := clusterInfo.numNodes
	if len(clusterInfo.podV4NetworkCIDR) != 0 && len(clusterInfo.podV6NetworkCIDR) != 0 {
		expectedNumTemplateRecords = clusterInfo.numNodes * 2
	}
	assert.Equal(t, expectedNumTemplateRecords, templateRecords, "Each agent should send out a template record per supported family address")

	// Single iperf resulting in two connections with separate ports. Suspecting second flow to be control flow to exchange
	// stats info. As 5s is export interval and iperf traffic runs for 10s, we expect 4 records.
	assert.GreaterOrEqual(t, dataRecordsCount, 4, "Iperf flow should have expected number of flow records")
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

func deployNetworkPolicies(t *testing.T, data *TestData) (np1 *networkingv1.NetworkPolicy, np2 *networkingv1.NetworkPolicy) {
	// Add NetworkPolicy between two iperf Pods.
	var err error
	np1, err = data.createNetworkPolicy("test-flow-exporter-networkpolicy-ingress", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": "perftest-a",
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Errorf("Error when creating Network Policy: %v", err)
	}
	np2, err = data.createNetworkPolicy("test-flow-exporter-networkpolicy-egress", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": "perftest-b",
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
