package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	collector1Name, collector2Name string
	collector1Addr, collector2Addr string
)

func isTestProtocolGRPC() bool {
	cmd := fmt.Sprintf("cat %s", flowVisibilityProtocolFile)
	_, stdout, _, _ := testData.RunCommandOnNode(controlPlaneNodeName(), cmd)
	return stdout == "" || strings.EqualFold(stdout, "grpc")
}

// createFlowExporterTarget creates a new FlowExporterTarget and hooks it up for deletion at the end of the test.
func createFlowExporterTarget(tb testing.TB, name string, isTLS, targetSecondFA bool) *v1alpha1.FlowExporterTarget {
	serviceAddr := "flow-aggregator/flow-aggregator"
	if targetSecondFA {
		serviceAddr = "flow-aggregator2/flow-aggregator"
	}

	protocol := v1alpha1.ProtoGRPC
	var transport v1alpha1.TransportProtocol
	if !isTestProtocolGRPC() {
		protocol = v1alpha1.ProtoIPFix
	}
	if isTLS {
		transport = v1alpha1.ProtoTLS
	} else {
		transport = v1alpha1.ProtoTCP
	}

	target := testData.BuildFlowExporterTarget(randName(name+"-"), testData.testNamespace, serviceAddr, protocol, transport, "2s", "1s")
	updatedTarget, err := testData.CreateOrUpdateFET(target)
	if err != nil {
		tb.Fatalf("failed to create FlowExporterTarget: %v", err)
	}
	tb.Cleanup(func() {
		testData.DeleteFET(target.Name)
	})

	return updatedTarget
}

func deployIPFIXCollectorOnNode(tb testing.TB, o flowVisibilityTestOptions, nodeIdx int) string {
	tb.Logf("Deploying IPFIX Collector")
	collectorName := "ipfix-collector"
	if o.ipfixCollector.name != "" {
		collectorName = o.ipfixCollector.name
	}

	ipfixCollectorAddr, err := testData.deployIPFIXCollectorWithName(collectorName, nil, nil, nil, nodeName(nodeIdx))
	if err != nil {
		tb.Fatalf("Error when deploying IPFIX collector %q: %v", collectorName, err)
	}

	return ipfixCollectorAddr
}

func setupFlowExporterTargetTest(tb testing.TB, opt1, opt2 flowVisibilityTestOptions) {
	tb.Logf("Deploying FlowAggregator with ipfix collector: %s and options: %+v", collector1Addr, opt1)
	if err := testData.deployFlowAggregator(collector1Addr, nil, nil, nil, opt1); err != nil {
		tb.Fatalf("Error when deploying flow aggregator: %v", err)
	}

	tb.Cleanup(func() {
		teardownFlowAggregator(tb, testData)
	})

	tb.Logf("Deploying FlowAggregator with ipfix collector: %s and options: %+v", collector2Addr, opt2)
	if err := testData.deployFlowAggregator(collector2Addr, nil, nil, nil, opt2); err != nil {
		tb.Fatalf("Error when deploying flow aggregator: %v", err)
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
		const timeout = 10 * time.Minute
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

func TestFlowExporterFlowExporterTargets(t *testing.T) {
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

	collector1Name = randName("ipfix-collector-")
	opt1 := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			disableTLS: true,
		},
		ipfixCollector: flowVisibilityIPFIXTestOptions{
			name: collector1Name,
		}}
	// TODO: Create one for each node instead, daemonset?
	collector1Addr = deployIPFIXCollectorOnNode(t, opt1, 1)

	collector2Name = randName("ipfix-collector-")
	opt2 := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			disableTLS: true,
		},
		useSecondFlowAggregator: true,
		ipfixCollector: flowVisibilityIPFIXTestOptions{
			name: collector2Name,
		}}
	collector2Addr = deployIPFIXCollectorOnNode(t, opt2, 2)

	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "Error when creating Kubernetes utils client")

	t.Logf("Creating Perf Pods")
	podAIPs, _, podCIPs, _, _, err = createPerftestPods(data)
	require.NoError(t, err, "Error when creating perftest Pods")

	runTests := func(t *testing.T, isIPv6 bool) {
		data.CleanFETs()
		t.Run("no flow exporter targets", func(t *testing.T) {
			setupFlowExporterTargetTest(t, opt1, opt2)
			// We don't wait and verify metrics because at this point there are no consumer thus no connections.
			generateTrafficAndVerify(t, data, false, verifyNoRecords(collector1Name), verifyNoRecords(collector2Name))
		})

		t.Run("one exporter", func(t *testing.T) {
			setupFlowExporterTargetTest(t, opt1, opt2)

			createFlowExporterTarget(t, "single-exporter", false, false)
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, isIPv6, flowAggregatorNamespace), "Error when checking metrics of Flow Aggregator")

			generateTrafficAndVerify(t, data, isIPv6, verifyRecords(collector1Name) /*, verifyNoRecords(collector2Name)*/)
		})

		t.Run("multi exporters", func(t *testing.T) {
			setupFlowExporterTargetTest(t, opt1, opt2)

			createFlowExporterTarget(t, "multi-exporter-ag1", false, false)
			createFlowExporterTarget(t, "multi-exporter-ag2", false, true)

			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, isIPv6, flowAggregatorNamespace), "Error when checking metrics of Flow Aggregator")
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, isIPv6, flowAggregatorNamespace2), "Error when checking metrics of Flow Aggregator 2")
			generateTrafficAndVerify(t, data, isIPv6, verifyRecords(collector1Name), verifyRecords(collector2Name))
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
