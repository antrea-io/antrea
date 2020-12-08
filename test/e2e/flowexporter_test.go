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
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestFlowExporter runs flow exporter to export flow records for flows.
// Flows are deployed between Pods on same node.
func TestFlowExporter(t *testing.T) {
	// TODO: remove this limitation after flow_exporter supports IPv6
	skipIfIPv6Cluster(t)
	skipIfNotIPv4Cluster(t)
	data, err := setupTestWithIPFIXCollector(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	if err := data.createPodOnNode("perftest-a", masterNodeName(), perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	podAIP, err := data.podWaitForIPs(defaultTimeout, "perftest-a", testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	if err := data.createPodOnNode("perftest-b", masterNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Fatalf("Error when creating the perftest server Pod: %v", err)
	}
	podBIP, err := data.podWaitForIPs(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
	}

	// Add NetworkPolicy between two iperf Pods.
	np1, err := data.createNetworkPolicy("test-flow-exporter-networkpolicy-ingress", &networkingv1.NetworkPolicySpec{
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
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np1); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()
	np2, err := data.createNetworkPolicy("test-flow-exporter-networkpolicy-egress", &networkingv1.NetworkPolicySpec{
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
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np2); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()
	// Wait for network policies to be realized.
	if err := WaitNetworkPolicyRealize(1, data); err != nil {
		t.Fatalf("Error when waiting for network policy to be realized: %v", err)
	}
	t.Log("Network policies are realized.")
	podAIPStr := podAIP.ipv4.String()
	podBIPStr := podBIP.ipv4.String()
	checkRecordsWithPodIPs(t, data, podAIPStr, podBIPStr, false)
}

func checkRecordsWithPodIPs(t *testing.T, data *TestData, podAIP string, podBIP string, isIPv6 bool) {
	var cmdStr string
	if !isIPv6 {
		cmdStr = fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", podBIP)
	} else {
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s|grep sender|awk '{print $7,$8}'", podBIP)
	}
	stdout, _, err := data.runCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", cmdStr})
	if err != nil {
		t.Fatalf("Error when running iperf3 client: %v", err)
	}
	bandwidth := strings.TrimSpace(stdout)

	// Adding some delay to make sure all the data records corresponding to iperf flow are received.
	time.Sleep(250 * time.Millisecond)

	rc, collectorOutput, _, err := provider.RunCommandOnNode(masterNodeName(), fmt.Sprintf("kubectl logs ipfix-collector -n antrea-test"))
	if err != nil || rc != 0 {
		t.Fatalf("Error when getting logs %v, rc: %v", err, rc)
	}

	/* Parse through IPFIX collector output. Sample output is given below:
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
	    destinationClusterIPv4: 0.0.0.0
	    destinationServicePortName:
	    ingressNetworkPolicyName: test-networkpolicy-ingress
	    ingressNetworkPolicyNamespace: antrea-test
	    egressNetworkPolicyName: test-networkpolicy-egress
	    egressNetworkPolicyNamespace: antrea-test
	*/
	re := regexp.MustCompile("(?m)^.*" + "#" + ".*$[\r\n]+")
	collectorOutput = re.ReplaceAllString(collectorOutput, "")
	collectorOutput = strings.TrimSpace(collectorOutput)
	recordSlices := strings.Split(collectorOutput, "IPFIX-HDR:")
	// Delete the first element from recordSlices
	recordSlices[0] = recordSlices[len(recordSlices)-1]
	recordSlices[len(recordSlices)-1] = ""
	recordSlices = recordSlices[:len(recordSlices)-1]
	// Iterate over recordSlices and build some results to test with expected results
	templateRecords := 0
	dataRecordsIntraNode := 0
	for _, records := range recordSlices {
		if strings.Contains(records, "TEMPLATE RECORD") {
			templateRecords = templateRecords + 1
		}
		for _, record := range strings.Split(records, "DATA RECORD") {
			if strings.Contains(record, podAIP) && strings.Contains(record, podBIP) {
				dataRecordsIntraNode = dataRecordsIntraNode + 1
				// Check if records have both Pod name and Pod namespace or not.
				if !strings.Contains(record, "perftest-a") {
					t.Fatalf("Records with PodAIP does not have Pod name")
				}
				if !strings.Contains(record, "perftest-b") {
					t.Fatalf("Records with PodBIP does not have Pod name")
				}
				if !strings.Contains(record, testNamespace) {
					t.Fatalf("Records with PodAIP and PodBIP does not have Pod Namespace")
				}
				// In Kind clusters, there are two flow records for the iperf flow.
				// One of them has no bytes and we ignore that flow record.
				if !strings.Contains(record, "octetDeltaCount: 0") {
					// Check if records have both ingress and egress network policies.
					if !strings.Contains(record, "test-flow-exporter-networkpolicy-ingress") {
						t.Fatalf("Records does not have NetworkPolicy name with ingress rule")
					}
					if !strings.Contains(record, "test-flow-exporter-networkpolicy-egress") {
						t.Fatalf("Records does not have NetworkPolicy name with egress rule")
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
									t.Fatalf("Error in converting octetDeltaCount to int type")
								}
								// compute the bandwidth using 5s as interval
								recBandwidth := (deltaBytes * 8.0) / float64(5*time.Second.Nanoseconds())
								// bandwidth from iperf output
								bwSlice := strings.Split(bandwidth, " ")
								iperfBandwidth, err := strconv.ParseFloat(bwSlice[0], 64)
								if err != nil {
									t.Fatalf("Error in converting iperf bandwidth to float64 type")
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
	}
	assert.Equal(t, templateRecords, clusterInfo.numNodes, "Each agent should send out template record")
	// Single iperf resulting in two connections with separate ports. Suspecting second flow to be control flow to exchange
	// stats info. As 5s is export interval and iperf traffic runs for 10s, we expect 4 records.
	assert.GreaterOrEqual(t, dataRecordsIntraNode, 4, "Iperf flow should have expected number of flow records")
}
