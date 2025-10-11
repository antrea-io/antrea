// Copyright 2025 Antrea Authors.
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
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
)

var (
	collectorName1, collectorName2 string
)

func isTestProtocolGRPC() bool {
	cmd := fmt.Sprintf("cat %s", flowVisibilityProtocolFile)
	_, stdout, _, _ := testData.RunCommandOnNode(controlPlaneNodeName(), cmd)
	return stdout == "" || strings.EqualFold(stdout, "grpc")
}

type FlowExporterDestinationOptions struct {
	targetIndex int
	tls         bool
}

// applyFlowExporterDestination creates a new FlowExporterDestination and hooks it up for deletion at the end of the test.
func applyFlowExporterDestination(tb testing.TB, namePrefix string, opts FlowExporterDestinationOptions) *v1alpha1.FlowExporterDestination {
	serviceAddr := "flow-aggregator/flow-aggregator"
	if opts.targetIndex > 0 {
		serviceAddr = fmt.Sprintf("%s-%d", serviceAddr, opts.targetIndex)
	}

	protocol := v1alpha1.FlowExporterProtocol{}
	if isTestProtocolGRPC() {
		protocol.GRPC = &v1alpha1.FlowExporterGRPCConfig{}
	} else {
		var transport v1alpha1.FlowExporterTransportProtocol
		if opts.tls {
			transport = v1alpha1.FlowExporterTransportTLS
		} else {
			transport = v1alpha1.FlowExporterTransportTCP
		}
		protocol.IPFIX = &v1alpha1.FlowExporterIPFIXConfig{
			Transport: transport,
		}
	}

	dest := testData.BuildFlowExporterDestination(randName(namePrefix+"-"), testData.testNamespace, serviceAddr, protocol, 2, 1)
	updatedTarget, err := testData.CreateOrUpdateFlowExporterDestination(dest)
	if err != nil {
		tb.Fatalf("failed to create FlowExporterTarget: %v", err)
	}
	tb.Cleanup(func() {
		testData.DeleteFlowExporterDestination(dest.Name)
	})

	return updatedTarget
}

func deployIPFIXCollectorOnNode(tb testing.TB, name string, nodeIdx int) string {
	tb.Logf("Deploying IPFIX Collector")
	collectorName := "ipfix-collector"
	if name != "" {
		collectorName = name
	}

	ipfixCollectorAddr, err := testData.deployIPFIXCollectorWithName(collectorName, nil, nil, nil, nodeName(nodeIdx))
	if err != nil {
		tb.Fatalf("Error when deploying IPFIX collector %q: %v", collectorName, err)
	}

	return ipfixCollectorAddr
}

func setupFlowExporterDestinationTest(tb testing.TB, opts ...flowVisibilityTestOptions) {
	for _, opt := range opts {
		tb.Logf("Deploying FlowAggregator with ipfix collector: %s and options: %+v", opt.flowAggregator.collectorAddr, opt)
		if err := testData.deployFlowAggregator(opt.flowAggregator.collectorAddr, nil, nil, nil, opt); err != nil {
			tb.Fatalf("Error when deploying flow aggregator: %v", err)
		}
	}

	if len(opts) > 0 {
		tb.Cleanup(func() {
			teardownFlowAggregator(tb, testData)
		})
	}
}

func verifyNoRecords(name string) verifierFunc {
	// We want to make sure no records for our label come in, we need to wait at least pollInterval + min(activeExportTimeout, idleExportTimeout) + min(FA's Active Timeout,FA's Idle Timeout)
	// If any records are seen we should fail.

	return func(t require.TestingT, srcIP, dstIP, srcPort string, isIPv6 bool, data *TestData, labelFilter string) {
		const interval = 500 * time.Millisecond
		iterations := 10 // This means we will check for at least 10s.

		isDstService := false
		var allRecords, records []string
		err := wait.PollUntilContextTimeout(context.Background(), interval, 2*defaultTimeout, true, func(ctx context.Context) (bool, error) {
			var rc int
			var err error
			var cmd string

			ipfixCollectorIP, err := testData.podWaitForIPs(defaultTimeout, name, testData.testNamespace)
			if err != nil || len(ipfixCollectorIP.IPStrings) == 0 {
				require.NoErrorf(t, err, "Should be able to get IP from IPFIX collector Pod")
			}

			if !isIPv6 {
				cmd = fmt.Sprintf("curl http://%s:8080/records", ipfixCollectorIP.IPv4.String())
			} else {
				cmd = fmt.Sprintf("curl http://[%s]:8080/records", ipfixCollectorIP.IPv6.String())
			}
			rc, collectorOutput, _, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
			if err != nil || rc != 0 {
				return false, fmt.Errorf("failed to run curl command to retrieve flow records, rc: %d - err: %v", rc, err)
			}

			src, dst := matchSrcAndDstAddress(srcIP, dstIP, isDstService, isIPv6)
			var response IPFIXCollectorResponse
			if err := json.Unmarshal([]byte(collectorOutput), &response); err != nil {
				return false, fmt.Errorf("error when unmarshalling output from IPFIX collector Pod: %w", err)
			}
			allRecords = make([]string, len(response.FlowRecords))
			for idx := range response.FlowRecords {
				allRecords[idx] = response.FlowRecords[idx].Data
			}
			records = filterCollectorRecords(allRecords, labelFilter, src, dst, srcPort)
			if len(records) > 0 {
				return false, fmt.Errorf("unexpected records found")
			}
			iterations--
			return iterations <= 0, nil
		})

		require.NoErrorf(t, err, "Unable to verify that no records were received, source IP: %s, dest IP: %s, source port: %s, total records count: %d, filtered records count: %d, iterations remaining: %d", srcIP, dstIP, srcPort, len(allRecords), len(records), iterations)
	}
}

type verifierFunc func(t require.TestingT, srcIP, dstIP, srcPort string, isIPv6 bool, data *TestData, labelFilter string)

func verifyRecords(name string) verifierFunc {
	return func(t require.TestingT, srcIP, dstIP, srcPort string, isIPv6 bool, data *TestData, labelFilter string) {
		const timeout = 2 * time.Minute
		records := getCollectorOutputWithName(t, name, srcIP, dstIP, srcPort, false /* isDstService */, true /* lookForFlowEnd */, isIPv6, data, labelFilter, timeout)
		require.NotEmpty(t, records)
		record := records[len(records)-1]

		assert.Contains(t, record, fmt.Sprintf("sourcePodNamespace: %s", data.testNamespace), "Record does not have correct sourcePodNamespace")
		assert.Contains(t, record, fmt.Sprintf("destinationPodNamespace: %s", data.testNamespace), "Record does not have correct destinationPodNamespace")
		assert.Contains(t, record, fmt.Sprintf("sourcePodName: %s", "perftest-a"), "Record does not have correct sourcePodName")
		assert.Contains(t, record, fmt.Sprintf("destinationPodName: %s", "perftest-c"), "Record does not have correct destinationPodName")
		assert.NotContains(t, record, "sourcePodUUID: ")
		assert.NotContains(t, record, "destinationPodUUID: ")
		assert.NotContains(t, record, "sourceNodeUUID: ")
		assert.NotContains(t, record, "destinationNodeUUID: ")

		// Check the clusterId field, which should match the customClusterID set in the flowVisibilityTestOptions
		assert.Contains(t, record, fmt.Sprintf("clusterId: %s", customClusterID), "Record does not have the correct clusterId")
		assert.Contains(t, record, "originalObservationDomainId", "Record does not have originalObservationDomainId")
		assert.Contains(t, record, "originalExporterIPv4Address", "Record does not have originalExporterIPv4Address")
		assert.Contains(t, record, "originalExporterIPv6Address", "Record does not have originalExporterIPv6Address")
	}
}

func TestFlowExporterFlowExporterDestinations(t *testing.T) {
	skipIfNotFlowVisibilityTest(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 3)
	skipIfRunCoverage(t, "Multiple Flow Aggregators is used. Need to verify the modified resource is correct.")
	skipIfFlowExportProtocolIsGRPC(t, testData)

	// Common Setup
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	t.Cleanup(func() {
		teardownTest(t, data)
	})
	if antreaClusterUUID == "" {
		if uuid, err := data.getAntreaClusterUUID(10 * time.Second); err != nil {
			t.Fatalf("Error when retrieving Antrea Cluster UUID: %v", err)
		} else {
			antreaClusterUUID = uuid.String()
		}
	}

	collectorName1 = randName("ipfix-collector-")
	collectorName2 = randName("ipfix-collector-")
	collectorAddr1 := deployIPFIXCollectorOnNode(t, collectorName1, 1)
	collectorAddr2 := deployIPFIXCollectorOnNode(t, collectorName2, 2)

	optDefault := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			collectorAddr: "invalid.local:8090",
		},
	}

	opt1 := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			disableTLS:         true,
			selectedAggregator: 1,
			collectorAddr:      collectorAddr1,
		},
	}

	opt2 := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			disableTLS:         true,
			selectedAggregator: 2,
			collectorAddr:      collectorAddr2,
		},
	}

	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "Error when creating Kubernetes utils client")

	t.Logf("Creating Perf Pods")
	podAIPs, _, podCIPs, _, _, err = createPerftestPods(data)
	require.NoError(t, err, "Error when creating perftest Pods")

	runTests := func(t *testing.T, isIPv6 bool) {
		data.CleanFlowExporterDestinations()
		t.Run("no flow exporter destination - only send to static destination", func(t *testing.T) {
			setupFlowExporterDestinationTest(t, optDefault, opt1, opt2)
			generateTrafficAndVerify(t, data, false, verifyNoRecords(collectorName1), verifyNoRecords(collectorName2))
		})

		t.Run("one flow exporter destination", func(t *testing.T) {
			setupFlowExporterDestinationTest(t, optDefault, opt1, opt2)
			applyFlowExporterDestination(t, "single-exporter", FlowExporterDestinationOptions{targetIndex: 1})
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, 1), "Error when checking metrics of Flow Aggregator 1")
			generateTrafficAndVerify(t, data, isIPv6, verifyRecords(collectorName1), verifyNoRecords(collectorName2))
		})

		t.Run("multi flow exporter destinations", func(t *testing.T) {
			setupFlowExporterDestinationTest(t, optDefault, opt1, opt2)
			applyFlowExporterDestination(t, "multi-exporter-1", FlowExporterDestinationOptions{targetIndex: 1})
			applyFlowExporterDestination(t, "multi-exporter-2", FlowExporterDestinationOptions{targetIndex: 2})
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, 1), "Error when checking metrics of Flow Aggregator")
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, 2), "Error when checking metrics of Flow Aggregator 2")
			generateTrafficAndVerify(t, data, isIPv6, verifyRecords(collectorName1), verifyRecords(collectorName2))
		})
	}

	if isIPv4Enabled() {
		t.Run("IPv4", func(t *testing.T) {
			t.Logf("Running IPv4 test now")
			runTests(t, false)
		})
	}

	if isIPv6Enabled() {
		t.Run("IPv6", func(t *testing.T) {
			t.Logf("Running IPv6 test now")
			runTests(t, true)
		})
	}
}

func generateTrafficAndVerify(t *testing.T, data *TestData, isIPv6 bool, expectations ...verifierFunc) {
	label := "flow-exporter-target-" + randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})

	var srcIP, dstIP string
	var cmd []string
	if !isIPv6 {
		srcIP = podAIPs.IPv4.String()
		dstIP = podCIPs.IPv4.String()
		cmd = []string{"iperf3", "-c", dstIP, "-t", "5"}
	} else {
		srcIP = podAIPs.IPv6.String()
		dstIP = podCIPs.IPv6.String()
		cmd = []string{"iperf3", "-6", "-c", dstIP, "-t", "5"}
	}
	stdout, _, err := data.RunCommandFromPod(data.testNamespace, "perftest-a", "iperf", cmd)
	require.NoError(t, err, "Error when running iperf3 client")
	_, srcPort, _ := getBandwidthAndPorts(stdout)

	for _, c := range expectations {
		c(t, srcIP, dstIP, srcPort, isIPv6, data, label)
	}
}
