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
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/strings/slices"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	antreaagenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/antctl"
	"antrea.io/antrea/pkg/antctl/runtime"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/flowaggregator/apiserver/handlers/recordmetrics"
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
    sourcePodNamespace: testflowaggregator-b6mjmbpl
    sourceNodeName: k8s-node-control-plane
    destinationPodName: perftest-b
    destinationPodNamespace: testflowaggregator-b6mjmbpl
    destinationNodeName: k8s-node-control-plane
    destinationServicePort: 0
    destinationServicePortName:
    ingressNetworkPolicyName: test-flow-aggregator-networkpolicy-ingress-allow
    ingressNetworkPolicyNamespace: testflowaggregator-b6mjmbpl
    ingressNetworkPolicyType: 1
    ingressNetworkPolicyRuleName:
    ingressNetworkPolicyRuleAction: 1
    egressNetworkPolicyName: test-flow-aggregator-networkpolicy-egress-allow
    egressNetworkPolicyNamespace: testflowaggregator-b6mjmbpl
    egressNetworkPolicyType: 1
    egressNetworkPolicyRuleName:
    egressNetworkPolicyRuleAction: 1
    tcpState: TIME_WAIT
    flowType: 1
    egressName: test-egressbkclk
    egressIP: 172.18.0.2
    appProtocolName: http
    httpVals: mockHttpString
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
    sourcePodLabels: {"antrea-e2e":"perftest-a","app":"iperf"}
    destinationPodLabels: {"antrea-e2e":"perftest-b","app":"iperf"}
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
	clickHousePodName              = "chi-clickhouse-clickhouse-0-0-0"
	iperfTimeSec                   = 12
	protocolIdentifierTCP          = 6
	// Set target bandwidth(bits/sec) of iPerf traffic to a relatively small value
	// (default unlimited for TCP), to reduce the variances caused by network performance
	// during 12s, and make the throughput test more stable.
	iperfBandwidth                  = "10m"
	antreaEgressTableInitFlowCount  = 3
	antreaIngressTableInitFlowCount = 6
	ingressTableInitFlowCount       = 1
	egressTableInitFlowCount        = 1
	serverPodPort                   = int32(80)
)

var (
	// Single iperf run results in two connections with separate ports (control connection and actual data connection).
	// As 2s is the export active timeout of flow exporter and iperf traffic runs for 12s, we expect totally 12 records
	// exporting to the flow aggregator at time 2s, 4s, 6s, 8s, 10s, and 12s after iperf traffic begins.
	// Since flow aggregator will aggregate records based on 5-tuple connection key and active timeout is 3.5 seconds,
	// we expect 3 records at time 5.5s, 9s, and 12.5s after iperf traffic begins.
	expectedNumDataRecords                      = 3
	podAIPs, podBIPs, podCIPs, podDIPs, podEIPs *PodIPs
	serviceNames                                = []string{"perftest-a", "perftest-b", "perftest-c", "perftest-d", "perftest-e"}
	podNames                                    = serviceNames
)

type testFlow struct {
	srcIP       string
	dstIP       string
	srcPodName  string
	dstPodName  string
	svcIP       string
	checkDstSvc bool
}

type IPFIXCollectorResponse struct {
	FlowRecords []string `json:"flowRecords"`
}

func TestFlowAggregatorSecureConnection(t *testing.T) {
	skipIfNotFlowVisibilityTest(t)
	skipIfHasWindowsNodes(t)
	testCases := []struct {
		flowVisibilityTestOptions
		name string
	}{
		{
			flowVisibilityTestOptions: flowVisibilityTestOptions{
				databaseURL:      "tcp://clickhouse-clickhouse.flow-visibility.svc:9000",
				secureConnection: false,
			},
			name: "tcp",
		},
		{
			flowVisibilityTestOptions: flowVisibilityTestOptions{
				databaseURL:      "http://clickhouse-clickhouse.flow-visibility.svc:8123",
				secureConnection: false,
			},
			name: "http",
		},
		{
			flowVisibilityTestOptions: flowVisibilityTestOptions{
				databaseURL:      "tls://clickhouse-clickhouse.flow-visibility.svc:9440",
				secureConnection: true,
			},
			name: "tls",
		},
		{
			flowVisibilityTestOptions: flowVisibilityTestOptions{
				databaseURL:      "https://clickhouse-clickhouse.flow-visibility.svc:8443",
				secureConnection: true,
			},
			name: "https",
		},
	}
	for _, o := range testCases {
		data, v4Enabled, v6Enabled, err := setupTestForFlowAggregator(t, o.flowVisibilityTestOptions)
		if err != nil {
			t.Fatalf("Error when setting up test: %v", err)
		}
		t.Run(o.name, func(t *testing.T) {
			defer func() {
				teardownTest(t, data)
				// Execute teardownFlowAggregator later than teardownTest to ensure that the log
				// of Flow Aggregator has been exported.
				teardownFlowAggregator(t, data)
			}()
			podAIPs, podBIPs, _, _, _, err = createPerftestPods(data)
			if err != nil {
				t.Fatalf("Error when creating perftest Pods: %v", err)
			}
			if v4Enabled {
				checkIntraNodeFlows(t, data, podAIPs, podBIPs, false, "")
			}
			if v6Enabled {
				checkIntraNodeFlows(t, data, podAIPs, podBIPs, true, "")
			}
		})
	}
}

func TestFlowAggregator(t *testing.T) {
	skipIfNotFlowVisibilityTest(t)
	skipIfHasWindowsNodes(t)

	data, v4Enabled, v6Enabled, err := setupTestForFlowAggregator(t, flowVisibilityTestOptions{
		databaseURL: defaultCHDatabaseURL,
	})
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	if err := getAndCheckFlowAggregatorMetrics(t, data); err != nil {
		t.Fatalf("Error when checking metrics of Flow Aggregator: %v", err)
	}
	defer func() {
		teardownTest(t, data)
		// Execute teardownFlowAggregator later than teardownTest to ensure that the log
		// of Flow Aggregator has been exported.
		teardownFlowAggregator(t, data)
	}()

	k8sUtils, err = NewKubernetesUtils(data)
	if err != nil {
		t.Fatalf("Error when creating Kubernetes utils client: %v", err)
	}

	podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, err = createPerftestPods(data)
	if err != nil {
		t.Fatalf("Error when creating perftest Pods: %v", err)
	}

	if v4Enabled {
		t.Run("IPv4", func(t *testing.T) { testHelper(t, data, false) })
		t.Run("L7FlowExporterController_IPv4", func(t *testing.T) {
			testL7FlowExporterController(t, data, false)
		})
	}

	if v6Enabled {
		t.Run("IPv6", func(t *testing.T) { testHelper(t, data, true) })
		t.Run("L7FlowExporterController_IPv6", func(t *testing.T) {
			testL7FlowExporterController(t, data, true)
		})
	}

}

func checkIntraNodeFlows(t *testing.T, data *TestData, podAIPs, podBIPs *PodIPs, isIPv6 bool, labelFilter string) {
	np1, np2 := deployK8sNetworkPolicies(t, data, "perftest-a", "perftest-b")
	defer func() {
		if np1 != nil {
			if err := data.deleteNetworkpolicy(np1); err != nil {
				t.Errorf("Error when deleting network policy: %v", err)
			}
		}
		if np2 != nil {
			if err := data.deleteNetworkpolicy(np2); err != nil {
				t.Errorf("Error when deleting network policy: %v", err)
			}
		}
	}()
	if !isIPv6 {
		checkRecordsForFlows(t, data, podAIPs.IPv4.String(), podBIPs.IPv4.String(), isIPv6, true, false, true, false, labelFilter)
	} else {
		checkRecordsForFlows(t, data, podAIPs.IPv6.String(), podBIPs.IPv6.String(), isIPv6, true, false, true, false, labelFilter)
	}
}

func testHelper(t *testing.T, data *TestData, isIPv6 bool) {
	_, svcB, svcC, svcD, svcE, err := createPerftestServices(data, isIPv6)
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
		label := "IntraNodeFlows"
		// As we use the same perftest Pods to generate traffic across all test cases, there's a potential for collecting
		// records from previous subtests. To mitigate this, we add a different label to perftest Pods during each subtest
		// before initiating traffic. This label is then employed as a filter when collecting records from either the
		// ClickHouse or the IPFIX collector Pod.
		addLabelToTestPods(t, data, label, podNames)
		checkIntraNodeFlows(t, data, podAIPs, podBIPs, isIPv6, label)
	})

	// IntraNodeDenyConnIngressANP tests the case, where Pods are deployed on same Node with an Antrea ingress deny policy rule
	// applied to destination Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-b (Ingress reject), perftest-a -> perftest-d (Ingress drop)
	t.Run("IntraNodeDenyConnIngressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "IntraNodeDenyConnIngressANP"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-b", "perftest-d", controlPlaneNodeName(), controlPlaneNodeName(), true)
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
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podBIPs.IPv4.String(), podAIPs.IPv4.String(), podDIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, false, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podBIPs.IPv6.String(), podAIPs.IPv6.String(), podDIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, false, label)
		}
	})

	// IntraNodeDenyConnEgressANP tests the case, where Pods are deployed on same Node with an Antrea egress deny policy rule
	// applied to source Pods (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a (Egress reject) -> perftest-b , perftest-a (Egress drop) -> perftest-d
	t.Run("IntraNodeDenyConnEgressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "IntraNodeDenyConnEgressANP"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-b", "perftest-d", controlPlaneNodeName(), controlPlaneNodeName(), false)
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
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podBIPs.IPv4.String(), podAIPs.IPv4.String(), podDIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, false, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podBIPs.IPv6.String(), podAIPs.IPv6.String(), podDIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, false, label)
		}
	})

	// IntraNodeDenyConnNP tests the case, where Pods are deployed on same Node with an ingress and an egress deny policy rule
	// applied to one destination Pod, one source Pod, respectively and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-b (Ingress deny), perftest-d (Egress deny) -> perftest-a
	t.Run("IntraNodeDenyConnNP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "IntraNodeDenyConnNP"
		addLabelToTestPods(t, data, label, podNames)
		np1, np2 := deployDenyNetworkPolicies(t, data, "perftest-b", "perftest-d", controlPlaneNodeName(), controlPlaneNodeName())
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
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podBIPs.IPv4.String(), podDIPs.IPv4.String(), podAIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, false, false, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podBIPs.IPv6.String(), podDIPs.IPv6.String(), podAIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, false, false, label)
		}
	})

	// IntraNodeDenyConnIngressANPThroughSvc tests the case, where Pods are deployed on same Node with an Antrea
	// ingress deny policy rule applied to destination Pod (one reject rule, one drop rule) and their flow information
	// is exported as IPFIX flow records. The test also verify if the service information is well filled in the record.
	// perftest-a -> svcB -> perftest-b (Ingress reject), perftest-a -> svcD ->perftest-d (Ingress drop)
	t.Run("IntraNodeDenyConnIngressANPThroughSvc", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "IntraNodeDenyConnIngressANPThroughSvc"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-b", "perftest-d", controlPlaneNodeName(), controlPlaneNodeName(), true)
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
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-b",
			svcIP:       svcB.Spec.ClusterIP,
			checkDstSvc: true,
		}
		testFlow2 := testFlow{
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-d",
			svcIP:       svcD.Spec.ClusterIP,
			checkDstSvc: true,
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podBIPs.IPv4.String(), podAIPs.IPv4.String(), podDIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, true, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podBIPs.IPv6.String(), podAIPs.IPv6.String(), podDIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, true, label)
		}
	})

	// IntraNodeDenyConnEgressANPThroughSvc tests the case, where Pods are deployed on same Node with an Antrea
	// egress deny policy rule applied to source Pod (one reject rule, one drop rule) and their flow information
	// is exported as IPFIX flow records. The test also verify if the service information is well filled in the record.
	// perftest-a (Egress reject) -> svcB ->perftest-b, perftest-a (Egress drop) -> svcD -> perftest-d
	t.Run("IntraNodeDenyConnEgressANPThroughSvc", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "IntraNodeDenyConnEgressANPThroughSvc"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-b", "perftest-d", controlPlaneNodeName(), controlPlaneNodeName(), false)
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
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-b",
			svcIP:       svcB.Spec.ClusterIP,
			checkDstSvc: true,
		}
		testFlow2 := testFlow{
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-d",
			svcIP:       svcD.Spec.ClusterIP,
			checkDstSvc: true,
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podBIPs.IPv4.String(), podAIPs.IPv4.String(), podDIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, true, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podBIPs.IPv6.String(), podAIPs.IPv6.String(), podDIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, true, true, true, label)
		}
	})

	// InterNodeFlows tests the case, where Pods are deployed on different Nodes
	// and their flow information is exported as IPFIX flow records.
	// Antrea network policies are being tested here.
	t.Run("InterNodeFlows", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "InterNodeFlows"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", controlPlaneNodeName(), workerNodeName(1))
		defer func() {
			if anp1 != nil {
				k8sUtils.DeleteANNP(data.testNamespace, anp1.Name)
			}
			if anp2 != nil {
				k8sUtils.DeleteANNP(data.testNamespace, anp2.Name)
			}
		}()
		if !isIPv6 {
			checkRecordsForFlows(t, data, podAIPs.IPv4.String(), podCIPs.IPv4.String(), isIPv6, false, false, false, true, label)
		} else {
			checkRecordsForFlows(t, data, podAIPs.IPv6.String(), podCIPs.IPv6.String(), isIPv6, false, false, false, true, label)
		}
	})

	// InterNodeDenyConnIngressANP tests the case, where Pods are deployed on different Nodes with an Antrea ingress deny policy rule
	// applied to destination Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-c (Ingress reject), perftest-a -> perftest-e (Ingress drop)
	t.Run("InterNodeDenyConnIngressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "InterNodeDenyConnIngressANP"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", "perftest-e", controlPlaneNodeName(), workerNodeName(1), true)
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
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podCIPs.IPv4.String(), podAIPs.IPv4.String(), podEIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, false, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podCIPs.IPv6.String(), podAIPs.IPv6.String(), podEIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, false, label)
		}
	})

	// InterNodeDenyConnEgressANP tests the case, where Pods are deployed on different Nodes with an Antrea egress deny policy rule
	// applied to source Pod (one reject rule, one drop rule) and their flow information is exported as IPFIX flow records.
	// perftest-a (Egress reject) -> perftest-c, perftest-a (Egress drop)-> perftest-e
	t.Run("InterNodeDenyConnEgressANP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "InterNodeDenyConnEgressANP"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", "perftest-e", controlPlaneNodeName(), workerNodeName(1), false)
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
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podCIPs.IPv4.String(), podAIPs.IPv4.String(), podEIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, false, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podCIPs.IPv6.String(), podAIPs.IPv6.String(), podEIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, false, label)
		}
	})

	// InterNodeDenyConnNP tests the case, where Pods are deployed on different Nodes with an ingress and an egress deny policy rule
	// applied to one destination Pod, one source Pod, respectively and their flow information is exported as IPFIX flow records.
	// perftest-a -> perftest-c (Ingress deny), perftest-b (Egress deny) -> perftest-e
	t.Run("InterNodeDenyConnNP", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "InterNodeDenyConnNP"
		addLabelToTestPods(t, data, label, podNames)
		np1, np2 := deployDenyNetworkPolicies(t, data, "perftest-c", "perftest-b", workerNodeName(1), controlPlaneNodeName())
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
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podCIPs.IPv4.String(), podBIPs.IPv4.String(), podEIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, false, false, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podCIPs.IPv6.String(), podBIPs.IPv6.String(), podEIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, false, false, label)
		}
	})

	// InterNodeDenyConnIngressANPThroughSvc tests the case, where Pods are deployed on different Node with an Antrea
	// ingress deny policy rule applied to destination Pod (one reject rule, one drop rule) and their flow information
	// is exported as IPFIX flow records. The test also verify if the service information is well filled in the record.
	// perftest-a -> svcC -> perftest-c (Ingress reject), perftest-a -> svcE -> perftest-e (Ingress drop)
	t.Run("InterNodeDenyConnIngressANPThroughSvc", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "InterNodeDenyConnIngressANPThroughSvc"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", "perftest-e", controlPlaneNodeName(), workerNodeName(1), true)
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
		// In theory, it's not possible to retrieve service information for these two flows because the packets are
		// either rejected or dropped in other nodes. Nevertheless, we can still observe the connection being recorded
		// in the conntrack table on the source node in cases of drop. This results in the aggregation process still
		// occurring within our flow-aggregator. Consequently, we can still see the service information when dealing
		// with inter-node traffic subject to an ingress drop network policy
		testFlow1 := testFlow{
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-c",
			svcIP:       svcC.Spec.ClusterIP,
			checkDstSvc: false,
		}
		testFlow2 := testFlow{
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-e",
			svcIP:       svcE.Spec.ClusterIP,
			checkDstSvc: true,
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podCIPs.IPv4.String(), podAIPs.IPv4.String(), podEIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, true, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podCIPs.IPv6.String(), podAIPs.IPv6.String(), podEIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, true, label)
		}
	})

	// InterNodeDenyConnEgressANPThroughSvc tests the case, where Pods are deployed on different Node with an Antrea
	// egress deny policy rule applied to source Pod (one reject rule, one drop rule) and their flow information
	// is exported as IPFIX flow records. The test also verify if the service information is well filled in the record.
	// perftest-a (Egress reject) -> svcC -> perftest-c, perftest-a (Egress drop) -> svcE -> perftest-e
	t.Run("InterNodeDenyConnEgressANPThroughSvc", func(t *testing.T) {
		skipIfAntreaPolicyDisabled(t)
		label := "InterNodeDenyConnEgressANPThroughSvc"
		addLabelToTestPods(t, data, label, podNames)
		anp1, anp2 := deployDenyAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", "perftest-e", controlPlaneNodeName(), workerNodeName(1), false)
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
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-c",
			svcIP:       svcC.Spec.ClusterIP,
			checkDstSvc: true,
		}
		testFlow2 := testFlow{
			srcPodName:  "perftest-a",
			dstPodName:  "perftest-e",
			svcIP:       svcE.Spec.ClusterIP,
			checkDstSvc: true,
		}
		if !isIPv6 {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv4.String(), podCIPs.IPv4.String(), podAIPs.IPv4.String(), podEIPs.IPv4.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, true, label)
		} else {
			testFlow1.srcIP, testFlow1.dstIP, testFlow2.srcIP, testFlow2.dstIP = podAIPs.IPv6.String(), podCIPs.IPv6.String(), podAIPs.IPv6.String(), podEIPs.IPv6.String()
			checkRecordsForDenyFlows(t, data, testFlow1, testFlow2, isIPv6, false, true, true, label)
		}
	})

	// Creating test server Pod for ToExternal tests
	serverIPs := createToExternalTestServer(t, data)

	// ToExternalEgressOnSourceNode tests the export of IPFIX flow records when
	// a source Pod sends traffic to an external IP and an Egress is applied on
	// the source Pod. In this case, the Egress Node is the same as the Source Node.
	t.Run("ToExternalEgressOnSourceNode", func(t *testing.T) {
		// Skip the test if Egress doesn't work on the cluster
		// Reference: TestEgress function in test/e2e/egress_test.go
		skipIfNumNodesLessThan(t, 2)
		skipIfEgressDisabled(t)
		skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

		// Deploy the client Pod on the control-plane node
		clientName, clientIPs, clientCleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", nodeName(0), data.testNamespace, false)
		defer clientCleanupFunc()
		label := "ToExternalEgressOnSourceNode"
		addLabelToTestPods(t, data, label, []string{clientName})

		// Create an Egress and the Egress IP is assigned to the Node running the client Pods
		var egressNodeIP string
		if !isIPv6 {
			egressNodeIP = nodeIPv4(0)
		} else {
			egressNodeIP = nodeIPv6(0)
		}
		egress := data.createEgress(t, "test-egress", nil, map[string]string{"app": "busybox"}, "", egressNodeIP, nil)
		egress, err := data.waitForEgressRealized(egress)
		if err != nil {
			t.Fatalf("Error when waiting for Egress to be realized: %v", err)
		}
		t.Logf("Egress %s is realized with Egress IP %s", egress.Name, egressNodeIP)
		defer data.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
		if !isIPv6 {
			if clientIPs.IPv4 != nil && serverIPs.IPv4 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.IPv4.String(), serverIPs.IPv4.String(), serverPodPort, isIPv6, egress.Name, egressNodeIP, label)
			}
		} else {
			if clientIPs.IPv6 != nil && serverIPs.IPv6 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.IPv6.String(), serverIPs.IPv6.String(), serverPodPort, isIPv6, egress.Name, egressNodeIP, label)
			}
		}
	})

	// ToExternalEgressOnOtherNode tests the export of IPFIX flow records when
	// a source Pod sends traffic to an external IP and an Egress applied on
	// the source Pod. In this case, the Egress Node is different from the Source Node.
	t.Run("ToExternalEgressOnOtherNode", func(t *testing.T) {
		// Skip the test if Egress doesn't work on the cluster
		// Reference: TestEgress function in test/e2e/egress_test.go
		skipIfNumNodesLessThan(t, 2)
		skipIfEgressDisabled(t)
		skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

		// Deploy the client Pod on the control-plane node
		clientName, clientIPs, clientCleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", nodeName(0), data.testNamespace, false)
		defer clientCleanupFunc()
		label := "ToExternalEgressOnOtherNode"
		addLabelToTestPods(t, data, label, []string{clientName})

		// Create an Egress and the Egress IP is assigned to the Node not running the client Pods
		var egressNodeIP string
		if !isIPv6 {
			egressNodeIP = nodeIPv4(1)
		} else {
			egressNodeIP = nodeIPv6(1)
		}
		egress := data.createEgress(t, "test-egress", nil, map[string]string{"app": "busybox"}, "", egressNodeIP, nil)
		egress, err := data.waitForEgressRealized(egress)
		if err != nil {
			t.Fatalf("Error when waiting for Egress to be realized: %v", err)
		}
		t.Logf("Egress %s is realized with Egress IP %s", egress.Name, egressNodeIP)
		defer data.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
		if !isIPv6 {
			if clientIPs.IPv4 != nil && serverIPs.IPv4 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.IPv4.String(), serverIPs.IPv4.String(), serverPodPort, isIPv6, egress.Name, egressNodeIP, label)
			}
		} else {
			if clientIPs.IPv6 != nil && serverIPs.IPv6 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.IPv6.String(), serverIPs.IPv6.String(), serverPodPort, isIPv6, egress.Name, egressNodeIP, label)
			}
		}
	})

	// ToExternalFlows tests the export of IPFIX flow records when a source Pod
	// sends traffic to an external IP
	t.Run("ToExternalFlows", func(t *testing.T) {
		// Deploy the client Pod on the control-plane node
		clientName, clientIPs, clientCleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", nodeName(0), data.testNamespace, false)
		defer clientCleanupFunc()
		label := "ToExternalFlows"
		addLabelToTestPods(t, data, label, []string{clientName})
		if !isIPv6 {
			if clientIPs.IPv4 != nil && serverIPs.IPv4 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.IPv4.String(), serverIPs.IPv4.String(), serverPodPort, isIPv6, "", "", label)
			}
		} else {
			if clientIPs.IPv6 != nil && serverIPs.IPv6 != nil {
				checkRecordsForToExternalFlows(t, data, nodeName(0), clientName, clientIPs.IPv6.String(), serverIPs.IPv6.String(), serverPodPort, isIPv6, "", "", label)
			}
		}
	})

	// LocalServiceAccess tests the case, where Pod and Service are deployed on the same Node and their flow information is exported as IPFIX flow records.
	t.Run("LocalServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t, data)
		label := "LocalServiceAccess"
		addLabelToTestPods(t, data, label, podNames)
		// In dual stack cluster, Service IP can be assigned as different IP family from specified.
		// In that case, source IP and destination IP will align with IP family of Service IP.
		// For IPv4-only and IPv6-only cluster, IP family of Service IP will be same as Pod IPs.
		isServiceIPv6 := net.ParseIP(svcB.Spec.ClusterIP).To4() == nil
		if isServiceIPv6 {
			checkRecordsForFlows(t, data, podAIPs.IPv6.String(), svcB.Spec.ClusterIP, isServiceIPv6, true, true, false, false, label)
		} else {
			checkRecordsForFlows(t, data, podAIPs.IPv4.String(), svcB.Spec.ClusterIP, isServiceIPv6, true, true, false, false, label)
		}
	})

	// RemoteServiceAccess tests the case, where Pod and Service are deployed on different Nodes and their flow information is exported as IPFIX flow records.
	t.Run("RemoteServiceAccess", func(t *testing.T) {
		skipIfProxyDisabled(t, data)
		label := "RemoteServiceAccess"
		addLabelToTestPods(t, data, label, podNames)
		// In dual stack cluster, Service IP can be assigned as different IP family from specified.
		// In that case, source IP and destination IP will align with IP family of Service IP.
		// For IPv4-only and IPv6-only cluster, IP family of Service IP will be same as Pod IPs.
		isServiceIPv6 := net.ParseIP(svcC.Spec.ClusterIP).To4() == nil
		if isServiceIPv6 {
			checkRecordsForFlows(t, data, podAIPs.IPv6.String(), svcC.Spec.ClusterIP, isServiceIPv6, false, true, false, false, label)
		} else {
			checkRecordsForFlows(t, data, podAIPs.IPv4.String(), svcC.Spec.ClusterIP, isServiceIPv6, false, true, false, false, label)
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
				antctlCovArgs := antctlCoverageArgs("antctl-coverage", "")
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
		srcIP = podAIPs.IPv4.String()
		dstIP = podBIPs.IPv4.String()
		cmdStr = fmt.Sprintf("iperf3 -c %s -t %d", dstIP, iperfTimeSecShort)
	} else {
		srcIP = podAIPs.IPv6.String()
		dstIP = podBIPs.IPv6.String()
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s -t %d", dstIP, iperfTimeSecShort)
	}
	stdout, _, err := data.RunCommandFromPod(data.testNamespace, "perftest-a", "iperf", []string{"bash", "-c", cmdStr})
	require.NoErrorf(t, err, "Error when running iperf3 client: %v", err)
	_, srcPort, dstPort := getBandwidthAndPorts(stdout)

	// run antctl command on flow aggregator to get flow records
	var command []string
	args := []string{"get", "flowrecords", "-o", "json", "--srcip", srcIP, "--srcport", srcPort}
	if testOptions.enableCoverage {
		antctlCovArgs := antctlCoverageArgs("antctl-coverage", "")
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

	checkAntctlRecord(t, records[0], srcIP, dstIP, srcPort, dstPort, isIPv6, data.testNamespace)
}

func checkAntctlRecord(t *testing.T, record map[string]interface{}, srcIP, dstIP, srcPort, dstPort string, isIPv6 bool, namespace string) {
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
	assert.Equal(namespace, record["sourcePodNamespace"], "The record from antctl does not have correct sourcePodNamespace")
	assert.Equal(controlPlaneNodeName(), record["sourceNodeName"], "The record from antctl does not have correct sourceNodeName")

	dstPortNum, err := strconv.Atoi(dstPort)
	require.NoErrorf(t, err, "error when converting the iperf dstPort to int type: %s", dstPort)
	assert.EqualValues(dstPortNum, record["destinationTransportPort"], "The record from antctl does not have correct destinationTransportPort")
	assert.Equal("perftest-b", record["destinationPodName"], "The record from antctl does not have correct destinationPodName")
	assert.Equal(namespace, record["destinationPodNamespace"], "The record from antctl does not have correct destinationPodNamespace")
	assert.Equal(controlPlaneNodeName(), record["destinationNodeName"], "The record from antctl does not have correct destinationNodeName")

	assert.EqualValues(ipfixregistry.FlowTypeIntraNode, record["flowType"], "The record from antctl does not have correct flowType")
	assert.EqualValues(protocolIdentifierTCP, record["protocolIdentifier"], "The record from antctl does not have correct protocolIdentifier")
}

func checkRecordsForFlows(t *testing.T, data *TestData, srcIP string, dstIP string, isIPv6 bool, isIntraNode bool, checkService bool, checkK8sNetworkPolicy bool, checkAntreaNetworkPolicy bool, labelFilter string) {
	var cmdStr string
	if !isIPv6 {
		cmdStr = fmt.Sprintf("iperf3 -c %s -t %d -b %s", dstIP, iperfTimeSec, iperfBandwidth)
	} else {
		cmdStr = fmt.Sprintf("iperf3 -6 -c %s -t %d -b %s", dstIP, iperfTimeSec, iperfBandwidth)
	}
	if checkService {
		cmdStr += fmt.Sprintf(" -p %d", iperfSvcPort)
	}
	stdout, _, err := data.RunCommandFromPod(data.testNamespace, "perftest-a", "iperf", []string{"bash", "-c", cmdStr})
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

	checkRecordsForFlowsCollector(t, data, srcIP, dstIP, srcPort, isIPv6, isIntraNode, checkService, checkK8sNetworkPolicy, checkAntreaNetworkPolicy, bandwidthInMbps, labelFilter)
	checkRecordsForFlowsClickHouse(t, data, srcIP, dstIP, srcPort, isIntraNode, checkService, checkK8sNetworkPolicy, checkAntreaNetworkPolicy, bandwidthInMbps, labelFilter)
}

func checkRecordsForFlowsCollector(t *testing.T, data *TestData, srcIP, dstIP, srcPort string, isIPv6, isIntraNode, checkService, checkK8sNetworkPolicy, checkAntreaNetworkPolicy bool, bandwidthInMbps float64, labelFilter string) {
	collectorOutput, recordSlices := getCollectorOutput(t, srcIP, dstIP, srcPort, checkService, true, isIPv6, data, labelFilter)
	// Checking only data records as data records cannot be decoded without template
	// record.
	assert.GreaterOrEqualf(t, len(recordSlices), expectedNumDataRecords, "IPFIX collector should receive expected number of flow records. Considered records: %s \n Collector output: %s", recordSlices, collectorOutput)
	// Iterate over recordSlices and build some results to test with expected results
	for _, record := range recordSlices {
		// Check if record has both Pod name of source and destination Pod.
		if isIntraNode {
			checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-b", controlPlaneNodeName(), data.testNamespace)
			checkFlowType(t, record, ipfixregistry.FlowTypeIntraNode)
		} else {
			checkPodAndNodeData(t, record, "perftest-a", controlPlaneNodeName(), "perftest-c", workerNodeName(1), data.testNamespace)
			checkFlowType(t, record, ipfixregistry.FlowTypeInterNode)
		}
		assert := assert.New(t)
		if checkService {
			if isIntraNode {
				assert.Contains(record, data.testNamespace+"/perftest-b", "Record with ServiceIP does not have Service name")
			} else {
				assert.Contains(record, data.testNamespace+"/perftest-c", "Record with ServiceIP does not have Service name")
			}
		}
		if checkK8sNetworkPolicy {
			// Check if records have both ingress and egress network policies.
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyName: %s", ingressAllowNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the ingress rule")
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have the correct NetworkPolicy Namespace with the ingress rule")
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeK8sNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress rule")
			assert.Contains(record, fmt.Sprintf("egressNetworkPolicyName: %s", egressAllowNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the egress rule")
			assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have the correct NetworkPolicy Namespace with the egress rule")
			assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeK8sNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress rule")
		}
		if checkAntreaNetworkPolicy {
			// Check if records have both ingress and egress network policies.
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyName: %s", ingressAntreaNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the ingress rule")
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have the correct NetworkPolicy Namespace with the ingress rule")
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress rule")
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleName: %s", testIngressRuleName), "Record does not have the correct NetworkPolicy RuleName with the ingress rule")
			assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionAllow), "Record does not have the correct NetworkPolicy RuleAction with the ingress rule")
			assert.Contains(record, fmt.Sprintf("egressNetworkPolicyName: %s", egressAntreaNetworkPolicyName), "Record does not have the correct NetworkPolicy name with the egress rule")
			assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have the correct NetworkPolicy Namespace with the egress rule")
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
			if flowEndReason == 3 {
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

func checkRecordsForFlowsClickHouse(t *testing.T, data *TestData, srcIP, dstIP, srcPort string, isIntraNode, checkService, checkK8sNetworkPolicy, checkAntreaNetworkPolicy bool, bandwidthInMbps float64, labelFilter string) {
	// Check the source port along with source and destination IPs as there
	// are flow records for control flows during the iperf with same IPs
	// and destination port.
	clickHouseRecords := getClickHouseOutput(t, data, srcIP, dstIP, srcPort, checkService, true, labelFilter)

	for _, record := range clickHouseRecords {
		// Check if record has both Pod name of source and destination Pod.
		if isIntraNode {
			checkPodAndNodeDataClickHouse(data, t, record, "perftest-a", controlPlaneNodeName(), "perftest-b", controlPlaneNodeName())
			checkFlowTypeClickHouse(t, record, ipfixregistry.FlowTypeIntraNode)
		} else {
			checkPodAndNodeDataClickHouse(data, t, record, "perftest-a", controlPlaneNodeName(), "perftest-c", workerNodeName(1))
			checkFlowTypeClickHouse(t, record, ipfixregistry.FlowTypeInterNode)
		}
		assert := assert.New(t)
		if checkService {
			if isIntraNode {
				assert.Contains(record.DestinationServicePortName, data.testNamespace+"/perftest-b", "Record with ServiceIP does not have Service name")
			} else {
				assert.Contains(record.DestinationServicePortName, data.testNamespace+"/perftest-c", "Record with ServiceIP does not have Service name")
			}
		}
		if checkK8sNetworkPolicy {
			// Check if records have both ingress and egress network policies.
			assert.Equal(record.IngressNetworkPolicyName, ingressAllowNetworkPolicyName, "Record does not have the correct NetworkPolicy name with the ingress rule")
			assert.Equal(record.IngressNetworkPolicyNamespace, data.testNamespace, "Record does not have the correct NetworkPolicy Namespace with the ingress rule")
			assert.Equal(record.IngressNetworkPolicyType, ipfixregistry.PolicyTypeK8sNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the ingress rule")
			assert.Equal(record.EgressNetworkPolicyName, egressAllowNetworkPolicyName, "Record does not have the correct NetworkPolicy name with the egress rule")
			assert.Equal(record.EgressNetworkPolicyNamespace, data.testNamespace, "Record does not have the correct NetworkPolicy Namespace with the egress rule")
			assert.Equal(record.EgressNetworkPolicyType, ipfixregistry.PolicyTypeK8sNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the egress rule")
		}
		if checkAntreaNetworkPolicy {
			// Check if records have both ingress and egress network policies.
			assert.Equal(record.IngressNetworkPolicyName, ingressAntreaNetworkPolicyName, "Record does not have the correct NetworkPolicy name with the ingress rule")
			assert.Equal(record.IngressNetworkPolicyNamespace, data.testNamespace, "Record does not have the correct NetworkPolicy Namespace with the ingress rule")
			assert.Equal(record.IngressNetworkPolicyType, ipfixregistry.PolicyTypeAntreaNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the ingress rule")
			assert.Equal(record.IngressNetworkPolicyRuleName, testIngressRuleName, "Record does not have the correct NetworkPolicy RuleName with the ingress rule")
			assert.Equal(record.IngressNetworkPolicyRuleAction, ipfixregistry.NetworkPolicyRuleActionAllow, "Record does not have the correct NetworkPolicy RuleAction with the ingress rule")
			assert.Equal(record.EgressNetworkPolicyName, egressAntreaNetworkPolicyName, "Record does not have the correct NetworkPolicy name with the egress rule")
			assert.Equal(record.EgressNetworkPolicyNamespace, data.testNamespace, "Record does not have the correct NetworkPolicy Namespace with the egress rule")
			assert.Equal(record.EgressNetworkPolicyType, ipfixregistry.PolicyTypeAntreaNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the egress rule")
			assert.Equal(record.EgressNetworkPolicyRuleName, testEgressRuleName, "Record does not have the correct NetworkPolicy RuleName with the egress rule")
			assert.Equal(record.EgressNetworkPolicyRuleAction, ipfixregistry.NetworkPolicyRuleActionAllow, "Record does not have the correct NetworkPolicy RuleAction with the egress rule")
		}

		// Skip the bandwidth check for the iperf control flow records which have 0 throughput.
		if record.Throughput > 0 {
			flowStartTime := record.FlowStartSeconds.Unix()
			exportTime := record.FlowEndSeconds.Unix()
			var recBandwidth float64
			// flowEndReason == 3 means the end of flow detected
			if record.FlowEndReason == 3 {
				octetTotalCount := record.OctetTotalCount
				recBandwidth = float64(octetTotalCount) * 8 / float64(exportTime-flowStartTime) / 1000000
			} else {
				// Check bandwidth with the field "throughput" except for the last record,
				// as their throughput may be significantly lower than the average Iperf throughput.
				throughput := record.Throughput
				recBandwidth = float64(throughput) / 1000000
			}
			t.Logf("Throughput check on record with flowEndSeconds-flowStartSeconds: %v, Iperf throughput: %.2f Mbits/s, ClickHouse record throughput: %.2f Mbits/s", exportTime-flowStartTime, bandwidthInMbps, recBandwidth)
			assert.InDeltaf(recBandwidth, bandwidthInMbps, bandwidthInMbps*0.15, "Difference between Iperf bandwidth and ClickHouse record bandwidth should be lower than 15%%, record: %v", record)
		}

	}
	// Checking only data records as data records cannot be decoded without template record.
	assert.GreaterOrEqualf(t, len(clickHouseRecords), expectedNumDataRecords, "ClickHouse should receive expected number of flow records. Considered records: %s", clickHouseRecords)
}

func checkRecordsForToExternalFlows(t *testing.T, data *TestData, srcNodeName string, srcPodName string, srcIP string, dstIP string, dstPort int32, isIPv6 bool, egressName, egressIP, labelFilter string) {
	var cmd string
	if !isIPv6 {
		cmd = fmt.Sprintf("wget -O- %s:%d", dstIP, dstPort)
	} else {
		cmd = fmt.Sprintf("wget -O- [%s]:%d", dstIP, dstPort)
	}
	stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, srcPodName, busyboxContainerName, strings.Fields(cmd))
	require.NoErrorf(t, err, "Error when running wget command, stdout: %s, stderr: %s", stdout, stderr)
	_, recordSlices := getCollectorOutput(t, srcIP, dstIP, "", false, false, isIPv6, data, labelFilter)
	for _, record := range recordSlices {
		checkPodAndNodeData(t, record, srcPodName, srcNodeName, "", "", data.testNamespace)
		checkFlowType(t, record, ipfixregistry.FlowTypeToExternal)
		if egressName != "" {
			checkEgressInfo(t, record, egressName, egressIP)
		}
	}

	clickHouseRecords := getClickHouseOutput(t, data, srcIP, dstIP, "", false, false, labelFilter)
	for _, record := range clickHouseRecords {
		checkPodAndNodeDataClickHouse(data, t, record, srcPodName, srcNodeName, "", "")
		checkFlowTypeClickHouse(t, record, ipfixregistry.FlowTypeToExternal)
		if egressName != "" {
			checkEgressInfoClickHouse(t, record, egressName, egressIP)
		}
	}
}

func checkRecordsForDenyFlows(t *testing.T, data *TestData, testFlow1, testFlow2 testFlow, isIPv6, isIntraNode, isANP, useSvcIP bool, labelFilter string) {
	var cmdStr1, cmdStr2 string
	if !isIPv6 {
		if useSvcIP {
			cmdStr1 = fmt.Sprintf("iperf3 -c %s -p %d -n 1", testFlow1.svcIP, iperfSvcPort)
			cmdStr2 = fmt.Sprintf("iperf3 -c %s -p %d -n 1", testFlow2.svcIP, iperfSvcPort)
		} else {
			cmdStr1 = fmt.Sprintf("iperf3 -c %s -n 1", testFlow1.dstIP)
			cmdStr2 = fmt.Sprintf("iperf3 -c %s -n 1", testFlow2.dstIP)
		}

	} else {
		if useSvcIP {
			cmdStr1 = fmt.Sprintf("iperf3 -6 -c %s -p %d -n 1", testFlow1.svcIP, iperfSvcPort)
			cmdStr2 = fmt.Sprintf("iperf3 -6 -c %s -p %d -n 1", testFlow2.svcIP, iperfSvcPort)
		} else {
			cmdStr1 = fmt.Sprintf("iperf3 -6 -c %s -n 1", testFlow1.dstIP)
			cmdStr2 = fmt.Sprintf("iperf3 -6 -c %s -n 1", testFlow2.dstIP)
		}
	}
	_, _, err := data.RunCommandFromPod(data.testNamespace, testFlow1.srcPodName, "", []string{"timeout", "2", "bash", "-c", cmdStr1})
	assert.Error(t, err)
	_, _, err = data.RunCommandFromPod(data.testNamespace, testFlow2.srcPodName, "", []string{"timeout", "2", "bash", "-c", cmdStr2})
	assert.Error(t, err)

	checkRecordsForDenyFlowsCollector(t, data, testFlow1, testFlow2, isIPv6, isIntraNode, isANP, labelFilter)
	checkRecordsForDenyFlowsClickHouse(t, data, testFlow1, testFlow2, isIPv6, isIntraNode, isANP, labelFilter)
}

func checkRecordsForDenyFlowsCollector(t *testing.T, data *TestData, testFlow1, testFlow2 testFlow, isIPv6, isIntraNode, isANP bool, labelFilter string) {
	_, recordSlices1 := getCollectorOutput(t, testFlow1.srcIP, testFlow1.dstIP, "", false, false, isIPv6, data, labelFilter)
	_, recordSlices2 := getCollectorOutput(t, testFlow2.srcIP, testFlow2.dstIP, "", false, false, isIPv6, data, labelFilter)
	recordSlices := append(recordSlices1, recordSlices2...)
	src_flow1, dst_flow1 := matchSrcAndDstAddress(testFlow1.srcIP, testFlow1.dstIP, false, isIPv6)
	src_flow2, dst_flow2 := matchSrcAndDstAddress(testFlow2.srcIP, testFlow2.dstIP, false, isIPv6)
	// Iterate over recordSlices and build some results to test with expected results
	for _, record := range recordSlices {
		var srcPodName, dstPodName string
		var checkDstSvc bool
		if strings.Contains(record, src_flow1) && strings.Contains(record, dst_flow1) {
			srcPodName = testFlow1.srcPodName
			dstPodName = testFlow1.dstPodName
			checkDstSvc = testFlow1.checkDstSvc
		} else if strings.Contains(record, src_flow2) && strings.Contains(record, dst_flow2) {
			srcPodName = testFlow2.srcPodName
			dstPodName = testFlow2.dstPodName
			checkDstSvc = testFlow2.checkDstSvc
		}
		if strings.Contains(record, src_flow1) && strings.Contains(record, dst_flow1) || strings.Contains(record, src_flow2) && strings.Contains(record, dst_flow2) {
			ingressRejectStr := fmt.Sprintf("ingressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionReject)
			ingressDropStr := fmt.Sprintf("ingressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionDrop)
			egressRejectStr := fmt.Sprintf("egressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionReject)
			egressDropStr := fmt.Sprintf("egressNetworkPolicyRuleAction: %d", ipfixregistry.NetworkPolicyRuleActionDrop)

			if isIntraNode {
				checkPodAndNodeData(t, record, srcPodName, controlPlaneNodeName(), dstPodName, controlPlaneNodeName(), data.testNamespace)
				checkFlowType(t, record, ipfixregistry.FlowTypeIntraNode)
			} else {
				checkPodAndNodeData(t, record, srcPodName, controlPlaneNodeName(), dstPodName, workerNodeName(1), data.testNamespace)
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
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have correct ingressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress reject rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleName: %s", testIngressRuleName), "Record does not have the correct NetworkPolicy RuleName with the ingress reject rule")
				} else if strings.Contains(record, ingressDropStr) {
					assert.Contains(record, ingressDropANPName, "Record does not have Antrea NetworkPolicy name with ingress drop rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have correct ingressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the ingress drop rule")
					assert.Contains(record, fmt.Sprintf("ingressNetworkPolicyRuleName: %s", testIngressRuleName), "Record does not have the correct NetworkPolicy RuleName with the ingress drop rule")
				} else if strings.Contains(record, egressRejectStr) {
					assert.Contains(record, egressRejectANPName, "Record does not have Antrea NetworkPolicy name with egress reject rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have correct egressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress reject rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyRuleName: %s", testEgressRuleName), "Record does not have the correct NetworkPolicy RuleName with the egress reject rule")
				} else if strings.Contains(record, egressDropStr) {
					assert.Contains(record, egressDropANPName, "Record does not have Antrea NetworkPolicy name with egress drop rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyNamespace: %s", data.testNamespace), "Record does not have correct egressNetworkPolicyNamespace")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyType: %d", ipfixregistry.PolicyTypeAntreaNetworkPolicy), "Record does not have the correct NetworkPolicy Type with the egress drop rule")
					assert.Contains(record, fmt.Sprintf("egressNetworkPolicyRuleName: %s", testEgressRuleName), "Record does not have the correct NetworkPolicy RuleName with the egress drop rule")
				}
			}
			if checkDstSvc {
				destinationServicePortName := data.testNamespace + "/" + dstPodName
				assert.Contains(record, fmt.Sprintf("destinationServicePortName: %s", destinationServicePortName), "Record does not have correct destinationServicePortName")
				assert.Contains(record, fmt.Sprintf("destinationServicePort: %d", iperfSvcPort), "Record does not have correct destinationServicePort")
			} else {
				assert.Contains(record, "destinationServicePortName:  \n", "Record does not have correct destinationServicePortName")
				assert.Contains(record, "destinationServicePort: 0 \n", "Record does not have correct destinationServicePort")
			}
		}
	}
}

func checkRecordsForDenyFlowsClickHouse(t *testing.T, data *TestData, testFlow1, testFlow2 testFlow, isIPv6, isIntraNode, isANP bool, labelFilter string) {
	clickHouseRecords1 := getClickHouseOutput(t, data, testFlow1.srcIP, testFlow1.dstIP, "", false, false, labelFilter)
	clickHouseRecords2 := getClickHouseOutput(t, data, testFlow2.srcIP, testFlow2.dstIP, "", false, false, labelFilter)
	recordSlices := append(clickHouseRecords1, clickHouseRecords2...)
	// Iterate over recordSlices and build some results to test with expected results
	for _, record := range recordSlices {
		var srcPodName, dstPodName string
		var checkDstSvc bool
		if record.SourceIP == testFlow1.srcIP && (record.DestinationIP == testFlow1.dstIP || record.DestinationClusterIP == testFlow1.dstIP) {
			srcPodName = testFlow1.srcPodName
			dstPodName = testFlow1.dstPodName
			checkDstSvc = testFlow1.checkDstSvc
		} else if record.SourceIP == testFlow2.srcIP && (record.DestinationIP == testFlow2.dstIP || record.DestinationClusterIP == testFlow2.dstIP) {
			srcPodName = testFlow2.srcPodName
			dstPodName = testFlow2.dstPodName
			checkDstSvc = testFlow2.checkDstSvc
		}

		if isIntraNode {
			checkPodAndNodeDataClickHouse(data, t, record, srcPodName, controlPlaneNodeName(), dstPodName, controlPlaneNodeName())
			checkFlowTypeClickHouse(t, record, ipfixregistry.FlowTypeIntraNode)
		} else {
			checkPodAndNodeDataClickHouse(data, t, record, srcPodName, controlPlaneNodeName(), dstPodName, workerNodeName(1))
			checkFlowTypeClickHouse(t, record, ipfixregistry.FlowTypeInterNode)
		}
		if checkDstSvc {
			destinationServicePortName := data.testNamespace + "/" + dstPodName
			assert.Contains(t, record.DestinationServicePortName, destinationServicePortName)
			assert.Equal(t, iperfSvcPort, int(record.DestinationServicePort))
		} else {
			assert.Equal(t, "", record.DestinationServicePortName)
			assert.Equal(t, 0, int(record.DestinationServicePort))
		}
		assert := assert.New(t)
		if !isANP { // K8s Network Policies
			if (record.IngressNetworkPolicyRuleAction == ipfixregistry.NetworkPolicyRuleActionDrop) && (record.IngressNetworkPolicyName != ingressDropANPName) {
				assert.Equal(record.DestinationIP, testFlow1.dstIP)
			} else if (record.EgressNetworkPolicyRuleAction == ipfixregistry.NetworkPolicyRuleActionDrop) && (record.EgressNetworkPolicyName != egressDropANPName) {
				assert.Equal(record.DestinationIP, testFlow2.dstIP)
			}
		} else { // Antrea Network Policies
			if record.IngressNetworkPolicyRuleAction == ipfixregistry.NetworkPolicyRuleActionReject {
				assert.Equal(record.IngressNetworkPolicyName, ingressRejectANPName, "Record does not have Antrea NetworkPolicy name with ingress reject rule")
				assert.Equal(record.IngressNetworkPolicyNamespace, data.testNamespace, "Record does not have correct ingressNetworkPolicyNamespace")
				assert.Equal(record.IngressNetworkPolicyType, ipfixregistry.PolicyTypeAntreaNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the ingress reject rule")
				assert.Equal(record.IngressNetworkPolicyRuleName, testIngressRuleName, "Record does not have the correct NetworkPolicy RuleName with the ingress reject rule")
			} else if record.IngressNetworkPolicyRuleAction == ipfixregistry.NetworkPolicyRuleActionDrop {
				assert.Equal(record.IngressNetworkPolicyName, ingressDropANPName, "Record does not have Antrea NetworkPolicy name with ingress drop rule")
				assert.Equal(record.IngressNetworkPolicyNamespace, data.testNamespace, "Record does not have correct ingressNetworkPolicyNamespace")
				assert.Equal(record.IngressNetworkPolicyType, ipfixregistry.PolicyTypeAntreaNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the ingress drop rule")
				assert.Equal(record.IngressNetworkPolicyRuleName, testIngressRuleName, "Record does not have the correct NetworkPolicy RuleName with the ingress drop rule")
			} else if record.EgressNetworkPolicyRuleAction == ipfixregistry.NetworkPolicyRuleActionReject {
				assert.Equal(record.EgressNetworkPolicyName, egressRejectANPName, "Record does not have Antrea NetworkPolicy name with egress reject rule")
				assert.Equal(record.EgressNetworkPolicyNamespace, data.testNamespace, "Record does not have correct egressNetworkPolicyNamespace")
				assert.Equal(record.EgressNetworkPolicyType, ipfixregistry.PolicyTypeAntreaNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the egress reject rule")
				assert.Equal(record.EgressNetworkPolicyRuleName, testEgressRuleName, "Record does not have the correct NetworkPolicy RuleName with the egress reject rule")
			} else if record.EgressNetworkPolicyRuleAction == ipfixregistry.NetworkPolicyRuleActionDrop {
				assert.Equal(record.EgressNetworkPolicyName, egressDropANPName, "Record does not have Antrea NetworkPolicy name with egress drop rule")
				assert.Equal(record.EgressNetworkPolicyNamespace, data.testNamespace, "Record does not have correct egressNetworkPolicyNamespace")
				assert.Equal(record.EgressNetworkPolicyType, ipfixregistry.PolicyTypeAntreaNetworkPolicy, "Record does not have the correct NetworkPolicy Type with the egress drop rule")
				assert.Equal(record.EgressNetworkPolicyRuleName, testEgressRuleName, "Record does not have the correct NetworkPolicy RuleName with the egress drop rule")
			}
		}
	}
}

func checkPodAndNodeData(t *testing.T, record, srcPod, srcNode, dstPod, dstNode string, namespace string) {
	assert := assert.New(t)
	assert.Contains(record, srcPod, "Record with srcIP does not have Pod name: %s", srcPod)
	assert.Contains(record, fmt.Sprintf("sourcePodNamespace: %s", namespace), "Record does not have correct sourcePodNamespace: %s", namespace)
	assert.Contains(record, fmt.Sprintf("sourceNodeName: %s", srcNode), "Record does not have correct sourceNodeName: %s", srcNode)
	// For Pod-To-External flow type, we send traffic to an external address,
	// so we skip the verification of destination Pod info.
	// Also, source Pod labels are different for Pod-To-External flow test.
	if dstPod != "" {
		assert.Contains(record, dstPod, "Record with dstIP does not have Pod name: %s", dstPod)
		assert.Contains(record, fmt.Sprintf("destinationPodNamespace: %s", namespace), "Record does not have correct destinationPodNamespace: %s", namespace)
		assert.Contains(record, fmt.Sprintf("destinationNodeName: %s", dstNode), "Record does not have correct destinationNodeName: %s", dstNode)
		assert.Contains(record, fmt.Sprintf("\"antrea-e2e\":\"%s\",\"app\":\"iperf\"", srcPod), "Record does not have correct label for source Pod")
		assert.Contains(record, fmt.Sprintf("\"antrea-e2e\":\"%s\",\"app\":\"iperf\"", dstPod), "Record does not have correct label for destination Pod")
	} else {
		assert.Contains(record, fmt.Sprintf("\"antrea-e2e\":\"%s\",\"app\":\"busybox\"", srcPod), "Record does not have correct label for source Pod")
	}
}

func checkPodAndNodeDataClickHouse(data *TestData, t *testing.T, record *ClickHouseFullRow, srcPod, srcNode, dstPod, dstNode string) {
	assert := assert.New(t)
	assert.Equal(record.SourcePodName, srcPod, "Record with srcIP does not have Pod name: %s", srcPod)
	assert.Equal(record.SourcePodNamespace, data.testNamespace, "Record does not have correct sourcePodNamespace: %s", data.testNamespace)
	assert.Equal(record.SourceNodeName, srcNode, "Record does not have correct sourceNodeName: %s", srcNode)
	// For Pod-To-External flow type, we send traffic to an external address,
	// so we skip the verification of destination Pod info.
	// Also, source Pod labels are different for Pod-To-External flow test.
	if dstPod != "" {
		assert.Equal(record.DestinationPodName, dstPod, "Record with dstIP does not have Pod name: %s", dstPod)
		assert.Equal(record.DestinationPodNamespace, data.testNamespace, "Record does not have correct destinationPodNamespace: %s", data.testNamespace)
		assert.Equal(record.DestinationNodeName, dstNode, "Record does not have correct destinationNodeName: %s", dstNode)
		assert.Contains(record.SourcePodLabels, fmt.Sprintf("\"antrea-e2e\":\"%s\",\"app\":\"iperf\"", srcPod), "Record does not have correct label for source Pod")
		assert.Contains(record.DestinationPodLabels, fmt.Sprintf("\"antrea-e2e\":\"%s\",\"app\":\"iperf\"", dstPod), "Record does not have correct label for destination Pod")
	} else {
		assert.Contains(record.SourcePodLabels, fmt.Sprintf("\"antrea-e2e\":\"%s\",\"app\":\"busybox\"", srcPod), "Record does not have correct label for source Pod")
	}
}

func checkFlowType(t *testing.T, record string, flowType uint8) {
	assert.Containsf(t, record, fmt.Sprintf("flowType: %d", flowType), "Record does not have correct flowType")
}

func checkFlowTypeClickHouse(t *testing.T, record *ClickHouseFullRow, flowType uint8) {
	assert.Equal(t, record.FlowType, flowType, "Record does not have correct flowType")
}

func checkEgressInfo(t *testing.T, record, egressName, egressIP string) {
	assert.Containsf(t, record, fmt.Sprintf("egressName: %s", egressName), "Record does not have correct egressName")
	assert.Containsf(t, record, fmt.Sprintf("egressIP: %s", egressIP), "Record does not have correct egressIP")
}

func checkEgressInfoClickHouse(t *testing.T, record *ClickHouseFullRow, egressName, egressIP string) {
	assert.Equal(t, egressName, record.EgressName, "Record does not have correct egressName")
	assert.Equal(t, egressIP, record.EgressIP, "Record does not have correct egressIP")
}

func checkL7FlowExporterData(t *testing.T, record, appProtocolName string) {
	assert.Containsf(t, record, fmt.Sprintf("appProtocolName: %s", appProtocolName), "Record does not have correct Layer 7 protocol Name")
}

func checkL7FlowExporterDataClickHouse(t *testing.T, record *ClickHouseFullRow, appProtocolName string) {
	assert.Equal(t, record.AppProtocolName, appProtocolName, "Record does not have correct Layer 7 protocol Name")
	assert.NotEmpty(t, record.HttpVals, "Record does not have httpVals")
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
func getCollectorOutput(t *testing.T, srcIP, dstIP, srcPort string, isDstService bool, checkAllRecords bool, isIPv6 bool, data *TestData, labelFilter string) (string, []string) {
	var collectorOutput string
	var recordSlices []string
	// In the ToExternalFlows test, flow record will arrive 5.5s (exporterActiveFlowExportTimeout+aggregatorActiveFlowRecordTimeout) after executing wget command
	// We set the timeout to 9s (5.5s plus one more aggregatorActiveFlowRecordTimeout) to make the ToExternalFlows test more stable
	err := wait.PollImmediate(500*time.Millisecond, exporterActiveFlowExportTimeout+aggregatorActiveFlowRecordTimeout*2, func() (bool, error) {
		var rc int
		var err error
		var cmd string
		ipfixCollectorIP, err := testData.podWaitForIPs(defaultTimeout, "ipfix-collector", testData.testNamespace)
		if err != nil || len(ipfixCollectorIP.IPStrings) == 0 {
			require.NoErrorf(t, err, "Should be able to get IP from IPFIX collector Pod")
		}
		if !isIPv6 {
			cmd = fmt.Sprintf("curl http://%s:8080/records", ipfixCollectorIP.IPv4.String())
		} else {
			cmd = fmt.Sprintf("curl http://[%s]:8080/records", ipfixCollectorIP.IPv6.String())
		}
		rc, collectorOutput, _, err = data.RunCommandOnNode(controlPlaneNodeName(), cmd)
		if err != nil || rc != 0 {
			return false, err
		}
		// Checking that all the data records which correspond to the iperf flow are received
		src, dst := matchSrcAndDstAddress(srcIP, dstIP, isDstService, isIPv6)
		recordSlices = getRecordsFromOutput(t, collectorOutput, labelFilter, src, dst, srcPort)
		if checkAllRecords {
			for _, record := range recordSlices {
				flowEndReason := int64(getUint64FieldFromRecord(t, record, "flowEndReason"))
				// flowEndReason == 3 means the end of flow detected
				if flowEndReason == 3 {
					return true, nil
				}
			}
			return false, nil
		}
		return len(recordSlices) != 0, nil
	})
	require.NoErrorf(t, err, "IPFIX collector did not receive the expected records in collector, recordSlices ares: %v, output: %v iperf source port: %s", recordSlices, collectorOutput, srcPort)
	return collectorOutput, recordSlices
}

// getClickHouseOutput queries clickhouse with built-in client and checks if we have
// received all the expected records for a given flow with source IP, destination IP
// and source port. We send source port to ignore the control flows during the iperf test.
// Polling timeout is coded assuming IPFIX output has been checked first.
func getClickHouseOutput(t *testing.T, data *TestData, srcIP, dstIP, srcPort string, isDstService, checkAllRecords bool, labelFilter string) []*ClickHouseFullRow {
	var flowRecords []*ClickHouseFullRow
	var queryOutput string

	query := fmt.Sprintf("SELECT * FROM flows WHERE (sourceIP = '%s') AND (destinationIP = '%s') AND (octetDeltaCount != 0)", srcIP, dstIP)
	if isDstService {
		query = fmt.Sprintf("SELECT * FROM flows WHERE (sourceIP = '%s') AND (destinationClusterIP = '%s') AND (octetDeltaCount != 0)", srcIP, dstIP)
	}
	if len(srcPort) > 0 {
		query = fmt.Sprintf("%s AND (sourceTransportPort = %s)", query, srcPort)
	}
	if labelFilter != "" {
		query = fmt.Sprintf("%s AND (sourcePodLabels LIKE '%%%s%%')", query, labelFilter)
	}
	cmd := []string{
		"clickhouse-client",
		"--date_time_output_format=iso",
		"--format=JSONEachRow",
		fmt.Sprintf("--query=%s", query),
	}
	// ClickHouse output expected to be checked after IPFIX collector.
	// Waiting additional 4x commit interval to be adequate for 3 commit attempts.
	err := wait.PollImmediate(500*time.Millisecond, aggregatorClickHouseCommitInterval*4, func() (bool, error) {
		queryOutput, _, err := data.RunCommandFromPod(flowVisibilityNamespace, clickHousePodName, "clickhouse", cmd)
		if err != nil {
			return false, err
		}
		rows := strings.Split(queryOutput, "\n")
		flowRecords = make([]*ClickHouseFullRow, 0, len(rows))
		for _, row := range rows {
			row = strings.TrimSpace(row)
			if len(row) == 0 {
				continue
			}
			flowRecord := ClickHouseFullRow{}
			err = json.Unmarshal([]byte(row), &flowRecord)
			if err != nil {
				return false, err
			}
			flowRecords = append(flowRecords, &flowRecord)
		}

		if checkAllRecords {
			for _, record := range flowRecords {
				// flowEndReason == 3 means the end of flow detected
				if record.FlowEndReason == 3 {
					return true, nil
				}
			}
			return false, nil
		}
		return len(flowRecords) > 0, nil
	})
	require.NoErrorf(t, err, "ClickHouse did not receive the expected records in query output: %v; query: %s", queryOutput, query)
	return flowRecords
}

func getRecordsFromOutput(t *testing.T, output, labelFilter, src, dst, srcPort string) []string {
	var response IPFIXCollectorResponse
	err := json.Unmarshal([]byte(output), &response)
	if err != nil {
		require.NoErrorf(t, err, "error when unmarshall output from IPFIX collector Pod")
	}
	recordSlices := response.FlowRecords
	records := []string{}
	for _, recordSlice := range recordSlices {
		// We don't check the last record.
		if strings.Contains(recordSlice, "octetDeltaCount: 0") {
			continue
		}
		// We don't check the record that can't match the srcIP, dstIP and srcPort.
		if !strings.Contains(recordSlice, src) || !strings.Contains(recordSlice, dst) || !strings.Contains(recordSlice, srcPort) {
			continue
		}
		if labelFilter == "" || strings.Contains(recordSlice, labelFilter) {
			records = append(records, recordSlice)
		}
	}
	return records
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
	if err := WaitNetworkPolicyRealize(controlPlaneNodeName(), openflow.IngressRuleTable, ingressTableInitFlowCount+1, data); err != nil {
		t.Errorf("Error when waiting for ingress Network Policy to be realized: %v", err)
	}
	if err := WaitNetworkPolicyRealize(controlPlaneNodeName(), openflow.IngressRuleTable, egressTableInitFlowCount+1, data); err != nil {
		t.Errorf("Error when waiting for egress Network Policy to be realized: %v", err)
	}
	t.Log("Network Policies are realized.")
	return np1, np2
}

func deployAntreaNetworkPolicies(t *testing.T, data *TestData, srcPod, dstPod string, srcNode, dstNode string) (anp1 *secv1beta1.NetworkPolicy, anp2 *secv1beta1.NetworkPolicy) {
	builder1 := &utils.AntreaNetworkPolicySpecBuilder{}
	// apply anp to dstPod, allow ingress from srcPod
	builder1 = builder1.SetName(data.testNamespace, ingressAntreaNetworkPolicyName).
		SetPriority(2.0).
		SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": dstPod}}})
	builder1 = builder1.AddIngress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{}, nil,
		nil, nil, nil, nil, secv1beta1.RuleActionAllow, "", testIngressRuleName)
	anp1 = builder1.Get()
	anp1, err1 := k8sUtils.CreateOrUpdateANNP(anp1)
	if err1 != nil {
		failOnError(fmt.Errorf("Error when creating Antrea Network Policy: %v", err1), t)
	}

	builder2 := &utils.AntreaNetworkPolicySpecBuilder{}
	// apply anp to srcPod, allow egress to dstPod
	builder2 = builder2.SetName(data.testNamespace, egressAntreaNetworkPolicyName).
		SetPriority(2.0).
		SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
	builder2 = builder2.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": dstPod}, map[string]string{}, nil,
		nil, nil, nil, nil, secv1beta1.RuleActionAllow, "", testEgressRuleName)
	anp2 = builder2.Get()
	anp2, err2 := k8sUtils.CreateOrUpdateANNP(anp2)
	if err2 != nil {
		failOnError(fmt.Errorf("Error when creating Network Policy: %v", err2), t)
	}

	// Wait for network policies to be realized.
	if err := WaitNetworkPolicyRealize(dstNode, openflow.AntreaPolicyIngressRuleTable, antreaIngressTableInitFlowCount+1, data); err != nil {
		t.Errorf("Error when waiting for Antrea ingress Network Policy to be realized: %v", err)
	}
	if err := WaitNetworkPolicyRealize(srcNode, openflow.AntreaPolicyEgressRuleTable, antreaEgressTableInitFlowCount+1, data); err != nil {
		t.Errorf("Error when waiting for Antrea egress Network Policy to be realized: %v", err)
	}
	t.Log("Antrea Network Policies are realized.")
	return anp1, anp2
}

func deployDenyAntreaNetworkPolicies(t *testing.T, data *TestData, srcPod, podReject, podDrop string, srcNode, dstNode string, isIngress bool) (anp1 *secv1beta1.NetworkPolicy, anp2 *secv1beta1.NetworkPolicy) {
	var err error
	builder1 := &utils.AntreaNetworkPolicySpecBuilder{}
	builder2 := &utils.AntreaNetworkPolicySpecBuilder{}
	var table *openflow.Table
	var flowCount int
	var nodeName string
	if isIngress {
		// apply reject and drop ingress rule to destination pods
		builder1 = builder1.SetName(data.testNamespace, ingressRejectANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": podReject}}})
		builder1 = builder1.AddIngress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{}, nil,
			nil, nil, nil, nil, secv1beta1.RuleActionReject, "", testIngressRuleName)
		builder2 = builder2.SetName(data.testNamespace, ingressDropANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": podDrop}}})
		builder2 = builder2.AddIngress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": srcPod}, map[string]string{}, nil,
			nil, nil, nil, nil, secv1beta1.RuleActionDrop, "", testIngressRuleName)
		table = openflow.AntreaPolicyIngressRuleTable
		flowCount = antreaIngressTableInitFlowCount + 2
		nodeName = dstNode
	} else {
		// apply reject and drop egress rule to source pod
		builder1 = builder1.SetName(data.testNamespace, egressRejectANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
		builder1 = builder1.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": podReject}, map[string]string{}, nil,
			nil, nil, nil, nil, secv1beta1.RuleActionReject, "", testEgressRuleName)
		builder2 = builder2.SetName(data.testNamespace, egressDropANPName).
			SetPriority(2.0).
			SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: map[string]string{"antrea-e2e": srcPod}}})
		builder2 = builder2.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil, map[string]string{"antrea-e2e": podDrop}, map[string]string{}, nil,
			nil, nil, nil, nil, secv1beta1.RuleActionDrop, "", testEgressRuleName)
		table = openflow.AntreaPolicyEgressRuleTable
		flowCount = antreaEgressTableInitFlowCount + 2
		nodeName = srcNode
	}
	anp1 = builder1.Get()
	anp1, err = k8sUtils.CreateOrUpdateANNP(anp1)
	if err != nil {
		failOnError(fmt.Errorf("Error when creating Antrea Network Policy: %v", err), t)
	}
	anp2 = builder2.Get()
	anp2, err = k8sUtils.CreateOrUpdateANNP(anp2)
	if err != nil {
		failOnError(fmt.Errorf("Error when creating Antrea Network Policy: %v", err), t)
	}
	// Wait for Antrea NetworkPolicy to be realized.
	if err := WaitNetworkPolicyRealize(nodeName, table, flowCount, data); err != nil {
		t.Errorf("Error when waiting for Antrea Network Policy to be realized: %v", err)
	}
	t.Log("Antrea Network Policies are realized.")
	return anp1, anp2
}

func deployDenyNetworkPolicies(t *testing.T, data *TestData, pod1, pod2 string, node1, node2 string) (np1 *networkingv1.NetworkPolicy, np2 *networkingv1.NetworkPolicy) {
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
	if err := WaitNetworkPolicyRealize(node1, openflow.IngressRuleTable, ingressTableInitFlowCount+1, data); err != nil {
		t.Errorf("Error when waiting for ingress Network Policies to be realized: %v", err)
	}
	if err := WaitNetworkPolicyRealize(node2, openflow.EgressRuleTable, egressTableInitFlowCount+1, data); err != nil {
		t.Errorf("Error when waiting for egress Network Policies to be realized: %v", err)
	}
	t.Log("Network Policies are realized.")
	return np1, np2
}

func createPerftestPods(data *TestData) (*PodIPs, *PodIPs, *PodIPs, *PodIPs, *PodIPs, error) {
	cmd := []string{"iperf3", "-s"}
	create := func(name string, nodeName string, ports []corev1.ContainerPort) error {
		return NewPodBuilder(name, data.testNamespace, ToolboxImage).WithContainerName("iperf").WithCommand(cmd).OnNode(nodeName).WithPorts(ports).Create(data)
	}
	var err error
	var podIPsArray [5]*PodIPs
	for i, podName := range podNames {
		var nodeName string
		if slices.Contains([]string{"perftest-a", "perftest-b", "perftest-d"}, podName) {
			nodeName = controlPlaneNodeName()
		} else {
			nodeName = workerNodeName(1)
		}
		if err := create(podName, nodeName, []corev1.ContainerPort{{Protocol: corev1.ProtocolTCP, ContainerPort: iperfPort}}); err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("error when creating the perftest client Pod: %v", err)
		}
		podIPsArray[i], err = data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("error when waiting for the perftest client Pod: %v", err)
		}
	}
	return podIPsArray[0], podIPsArray[1], podIPsArray[2], podIPsArray[3], podIPsArray[4], nil
}

func createPerftestServices(data *TestData, isIPv6 bool) (*corev1.Service, *corev1.Service, *corev1.Service, *corev1.Service, *corev1.Service, error) {
	svcIPFamily := corev1.IPv4Protocol
	if isIPv6 {
		svcIPFamily = corev1.IPv6Protocol
	}
	var err error
	var services [5]*corev1.Service
	for i, serviceName := range serviceNames {
		services[i], err = data.CreateService(serviceName, data.testNamespace, iperfSvcPort, iperfPort, map[string]string{"antrea-e2e": serviceName}, false, false, corev1.ServiceTypeClusterIP, &svcIPFamily)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("error when creating perftest-b Service: %v", err)
		}
	}
	return services[0], services[1], services[2], services[3], services[4], nil
}

func deletePerftestServices(t *testing.T, data *TestData) {
	for _, serviceName := range serviceNames {
		err := data.deleteService(data.testNamespace, serviceName)
		if err != nil {
			t.Logf("Error when deleting %s Service: %v", serviceName, err)
		}
	}
}

func addLabelToTestPods(t *testing.T, data *TestData, label string, podNames []string) {
	for _, podName := range podNames {
		testPod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
		require.NoErrorf(t, err, "Error when getting Pod %s in %s", testPod, data.testNamespace)
		testPod.Labels["targetLabel"] = label
		_, err = data.clientset.CoreV1().Pods(data.testNamespace).Update(context.TODO(), testPod, metav1.UpdateOptions{})
		require.NoErrorf(t, err, "Error when adding label to %s", testPod.Name)
		err = wait.Poll(defaultInterval, timeout, func() (bool, error) {
			pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), testPod.Name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					return false, nil
				}
				return false, fmt.Errorf("error when getting Pod '%s': %w", pod.Name, err)
			}
			return pod.Labels["targetLabel"] == label, nil
		})
		require.NoErrorf(t, err, "Error when verifying the label on %s", testPod.Name)
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

func createToExternalTestServer(t *testing.T, data *TestData) *PodIPs {
	// Creating an agnhost server as a hostNetwork Pod
	// Egress will be applied to the traffic when the destination is a hostNetwork Pod.
	_, serverIPs, serverCleanupFunc := createAndWaitForPod(t, data, func(name string, ns string, nodeName string, hostNetwork bool) error {
		return data.createServerPod(name, data.testNamespace, "", serverPodPort, false, true)
	}, "test-server-", "", data.testNamespace, false)

	t.Cleanup(func() {
		serverCleanupFunc()
	})

	return serverIPs
}

func getAndCheckFlowAggregatorMetrics(t *testing.T, data *TestData) error {
	flowAggPod, err := data.getFlowAggregator()
	if err != nil {
		return fmt.Errorf("error when getting flow-aggregator Pod: %w", err)
	}
	podName := flowAggPod.Name
	command := []string{"antctl", "get", "recordmetrics", "-o", "json"}
	if err := wait.Poll(defaultInterval, 2*defaultTimeout, func() (bool, error) {
		stdout, _, err := runAntctl(podName, command, data)
		if err != nil {
			t.Logf("Error when requesting recordmetrics, %v", err)
			return false, nil
		}
		metrics := &recordmetrics.Response{}
		if err := json.Unmarshal([]byte(stdout), metrics); err != nil {
			return false, fmt.Errorf("error when decoding recordmetrics: %w", err)
		}
		if metrics.NumConnToCollector != int64(clusterInfo.numNodes) || !metrics.WithClickHouseExporter || !metrics.WithIPFIXExporter || metrics.NumRecordsExported == 0 {
			t.Logf("Metrics are not correct. Current metrics: NumConnToCollector=%d, ClickHouseExporter=%v, IPFIXExporter=%v, NumRecordsExported=%d", metrics.NumConnToCollector, metrics.WithClickHouseExporter, metrics.WithIPFIXExporter, metrics.NumRecordsExported)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("error when checking recordmetrics for Flow Aggregator: %w", err)
	}
	return nil
}

func testL7FlowExporterController(t *testing.T, data *TestData, isIPv6 bool) {
	skipIfFeatureDisabled(t, features.L7FlowExporter, true, false)
	nodeName := nodeName(1)
	_, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "l7flowexportertestpodserver", nodeName, data.testNamespace, false)
	defer cleanupFunc()

	clientPodName := "l7flowexportertestpodclient"
	clientPodLabels := map[string]string{"flowexportertest": "l7"}
	clientPodAnnotations := map[string]string{antreaagenttypes.L7FlowExporterAnnotationKey: "both"}
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, ToolboxImage).OnNode(nodeName).WithContainerName("l7flowexporter").WithLabels(clientPodLabels).WithAnnotations(clientPodAnnotations).Create(data))
	clientPodIPs, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoErrorf(t, err, "Error when waiting for IP for Pod '%s': %v", clientPodName, err)
	defer deletePodWrapper(t, data, data.testNamespace, clientPodName)

	// Wait for the Suricata to start.
	time.Sleep(3 * time.Second)

	testFlow1 := testFlow{
		srcPodName: clientPodName,
	}
	var cmd []string
	if !isIPv6 {
		testFlow1.srcIP = clientPodIPs.IPv4.String()
		testFlow1.dstIP = serverIPs.IPv4.String()
		cmd = []string{
			"curl",
			fmt.Sprintf("http://%s:%d", serverIPs.IPv4.String(), serverPodPort),
		}
	} else {
		testFlow1.srcIP = clientPodIPs.IPv6.String()
		testFlow1.dstIP = serverIPs.IPv6.String()
		cmd = []string{
			"curl",
			"-6",
			fmt.Sprintf("http://[%s]:%d", serverIPs.IPv6.String(), serverPodPort),
		}
	}
	stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, testFlow1.srcPodName, "l7flowexporter", cmd)
	require.NoErrorf(t, err, "Error when running curl command, stdout: %s, stderr: %s", stdout, stderr)
	_, recordSlices := getCollectorOutput(t, testFlow1.srcIP, testFlow1.dstIP, "", false, true, isIPv6, data, "")
	for _, record := range recordSlices {
		assert := assert.New(t)
		assert.Contains(record, testFlow1.srcPodName, "Record with srcIP does not have Pod name: %s", testFlow1.srcPodName)
		assert.Contains(record, fmt.Sprintf("sourcePodNamespace: %s", data.testNamespace), "Record does not have correct sourcePodNamespace: %s", data.testNamespace)
		assert.Contains(record, fmt.Sprintf("sourceNodeName: %s", nodeName), "Record does not have correct sourceNodeName: %s", nodeName)
		assert.Contains(record, fmt.Sprintf("\"flowexportertest\":\"l7\""), "Record does not have correct label for source Pod")

		checkL7FlowExporterData(t, record, "http")
	}

	clickHouseRecords := getClickHouseOutput(t, data, testFlow1.srcIP, testFlow1.dstIP, "", false, true, "")
	for _, record := range clickHouseRecords {
		assert := assert.New(t)
		assert.Equal(record.SourcePodName, testFlow1.srcPodName, "Record with srcIP does not have Pod name: %s", testFlow1.srcPodName)
		assert.Equal(record.SourcePodNamespace, data.testNamespace, "Record does not have correct sourcePodNamespace: %s", data.testNamespace)
		assert.Equal(record.SourceNodeName, nodeName, "Record does not have correct sourceNodeName: %s", nodeName)
		assert.Contains(record.SourcePodLabels, fmt.Sprintf("\"flowexportertest\":\"l7\""), "Record does not have correct label for source Pod")

		checkL7FlowExporterDataClickHouse(t, record, "http")
	}

}

type ClickHouseFullRow struct {
	TimeInserted                         time.Time `json:"timeInserted"`
	FlowStartSeconds                     time.Time `json:"flowStartSeconds"`
	FlowEndSeconds                       time.Time `json:"flowEndSeconds"`
	FlowEndSecondsFromSourceNode         time.Time `json:"flowEndSecondsFromSourceNode"`
	FlowEndSecondsFromDestinationNode    time.Time `json:"flowEndSecondsFromDestinationNode"`
	FlowEndReason                        uint8     `json:"flowEndReason"`
	SourceIP                             string    `json:"sourceIP"`
	DestinationIP                        string    `json:"destinationIP"`
	SourceTransportPort                  uint16    `json:"sourceTransportPort"`
	DestinationTransportPort             uint16    `json:"destinationTransportPort"`
	ProtocolIdentifier                   uint8     `json:"protocolIdentifier"`
	PacketTotalCount                     uint64    `json:"packetTotalCount,string"`
	OctetTotalCount                      uint64    `json:"octetTotalCount,string"`
	PacketDeltaCount                     uint64    `json:"packetDeltaCount,string"`
	OctetDeltaCount                      uint64    `json:"octetDeltaCount,string"`
	ReversePacketTotalCount              uint64    `json:"reversePacketTotalCount,string"`
	ReverseOctetTotalCount               uint64    `json:"reverseOctetTotalCount,string"`
	ReversePacketDeltaCount              uint64    `json:"reversePacketDeltaCount,string"`
	ReverseOctetDeltaCount               uint64    `json:"reverseOctetDeltaCount,string"`
	SourcePodName                        string    `json:"sourcePodName"`
	SourcePodNamespace                   string    `json:"sourcePodNamespace"`
	SourceNodeName                       string    `json:"sourceNodeName"`
	DestinationPodName                   string    `json:"destinationPodName"`
	DestinationPodNamespace              string    `json:"destinationPodNamespace"`
	DestinationNodeName                  string    `json:"destinationNodeName"`
	DestinationClusterIP                 string    `json:"destinationClusterIP"`
	DestinationServicePort               uint16    `json:"destinationServicePort"`
	DestinationServicePortName           string    `json:"destinationServicePortName"`
	IngressNetworkPolicyName             string    `json:"ingressNetworkPolicyName"`
	IngressNetworkPolicyNamespace        string    `json:"ingressNetworkPolicyNamespace"`
	IngressNetworkPolicyRuleName         string    `json:"ingressNetworkPolicyRuleName"`
	IngressNetworkPolicyRuleAction       uint8     `json:"ingressNetworkPolicyRuleAction"`
	IngressNetworkPolicyType             uint8     `json:"ingressNetworkPolicyType"`
	EgressNetworkPolicyName              string    `json:"egressNetworkPolicyName"`
	EgressNetworkPolicyNamespace         string    `json:"egressNetworkPolicyNamespace"`
	EgressNetworkPolicyRuleName          string    `json:"egressNetworkPolicyRuleName"`
	EgressNetworkPolicyRuleAction        uint8     `json:"egressNetworkPolicyRuleAction"`
	EgressNetworkPolicyType              uint8     `json:"egressNetworkPolicyType"`
	TcpState                             string    `json:"tcpState"`
	FlowType                             uint8     `json:"flowType"`
	SourcePodLabels                      string    `json:"sourcePodLabels"`
	DestinationPodLabels                 string    `json:"destinationPodLabels"`
	Throughput                           uint64    `json:"throughput,string"`
	ReverseThroughput                    uint64    `json:"reverseThroughput,string"`
	ThroughputFromSourceNode             uint64    `json:"throughputFromSourceNode,string"`
	ThroughputFromDestinationNode        uint64    `json:"throughputFromDestinationNode,string"`
	ReverseThroughputFromSourceNode      uint64    `json:"reverseThroughputFromSourceNode,string"`
	ReverseThroughputFromDestinationNode uint64    `json:"reverseThroughputFromDestinationNode,string"`
	ClusterUUID                          string    `json:"clusterUUID"`
	Trusted                              uint8     `json:"trusted"`
	EgressName                           string    `json:"egressName"`
	EgressIP                             string    `json:"egressIP"`
	AppProtocolName                      string    `json:"appProtocolName"`
	HttpVals                             string    `json:"httpVals"`
}
