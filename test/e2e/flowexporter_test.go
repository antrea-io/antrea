// Copyright 2026 Antrea Authors.
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
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
)

var (
	collector1Name, collector2Name string
	collector1Addr, collector2Addr string
)

func isTestProtocolGRPC() bool {
	return strings.EqualFold(testOptions.flowVisibilityProtocol, "grpc")
}

// createFlowExporterDestination creates a new FlowExporterDestination and hooks it up for deletion at the end of the test.
func createFlowExporterDestination(tb testing.TB, name string, isTLS bool, namespace string) *v1alpha1.FlowExporterDestination {
	serviceAddr := fmt.Sprintf("%s/%s", namespace, "flow-aggregator")
	serverName := fmt.Sprintf("%s.%s.svc", "flow-aggregator", namespace)

	protocol := v1alpha1.FlowExporterProtocol{}
	if isTestProtocolGRPC() {
		protocol.GRPC = &v1alpha1.FlowExporterGRPCConfig{}
	} else {
		var transport v1alpha1.FlowExporterTransportProtocol
		if isTLS {
			transport = v1alpha1.FlowExporterTransportTLS
		} else {
			transport = v1alpha1.FlowExporterTransportTCP
		}
		protocol.IPFIX = &v1alpha1.FlowExporterIPFIXConfig{
			Transport: transport,
		}
	}

	var tlsConfig *v1alpha1.FlowExporterTLSConfig
	if isTLS || isTestProtocolGRPC() {
		tlsConfig = &v1alpha1.FlowExporterTLSConfig{
			ServerName: serverName,
			CAConfigMap: v1alpha1.NamespacedName{
				Name:      "flow-aggregator-ca",
				Namespace: namespace,
			},
			ClientSecret: &v1alpha1.NamespacedName{
				Name:      "flow-aggregator-client-tls",
				Namespace: namespace,
			},
		}
	}

	destination := BuildFlowExporterDestination(randName(name+"-"), serviceAddr, protocol, 2, 1, tlsConfig)
	updatedDest, err := testData.CreateOrUpdateFlowExporterDestination(destination)
	require.NoError(tb, err, "Failed to create FlowExporterDestination")

	tb.Cleanup(func() {
		testData.DeleteFlowExporterDestination(destination.Name)
	})

	return updatedDest
}

func deployIPFIXCollectorForTest(tb testing.TB, o flowVisibilityTestOptions) string {
	tb.Logf("Deploying IPFIX Collector")
	collectorName := "ipfix-collector"
	if o.ipfixCollector.name != "" {
		collectorName = o.ipfixCollector.name
	}

	ipfixCollectorAddr, err := testData.deployIPFIXCollectorWithName(collectorName, nil, nil, nil)
	require.NoError(tb, err, "Failed to deploy IPFIX collector", "name", collectorName)

	return ipfixCollectorAddr
}

func setupFlowExporterDestinationTest(tb testing.TB, opt1, opt2 flowVisibilityTestOptions) {
	tb.Logf("Deploying FlowAggregator with ipfix collector: %s and options: %+v", collector1Addr, opt1)
	require.NoError(tb, testData.deployFlowAggregator(collector1Addr, nil, nil, nil, opt1), "Failed to deploy flow aggregator", "opts", opt1)

	tb.Cleanup(func() {
		teardownFlowAggregator(tb, testData)
	})

	tb.Logf("Deploying FlowAggregator with ipfix collector: %s and options: %+v", collector2Addr, opt2)
	require.NoError(tb, testData.deployFlowAggregator(collector2Addr, nil, nil, nil, opt2), "Failed to deploy flow aggregator", "opts", opt2)
}

type verifierFunc func(t require.TestingT, srcIP, dstIP, srcPort string, isIPv6 bool, data *TestData, labelFilter string)

func verifyRecords(collectorName string) verifierFunc {
	return func(t require.TestingT, srcIP, dstIP, srcPort string, isIPv6 bool, data *TestData, labelFilter string) {
		records := getCollectorOutputWithName(t, collectorName, srcIP, dstIP, srcPort, false /* isDstService */, true /* lookForFlowEnd */, isIPv6, data, labelFilter, getCollectorOutputDefaultTimeout)
		require.NotEmpty(t, records)
		record := records[len(records)-1]

		assert.Contains(t, record, fmt.Sprintf("sourcePodNamespace: %s", data.testNamespace), "Record does not have correct sourcePodNamespace")
		assert.Contains(t, record, fmt.Sprintf("destinationPodNamespace: %s", data.testNamespace), "Record does not have correct destinationPodNamespace")
		assert.Contains(t, record, fmt.Sprintf("sourcePodName: %s", "perftest-a"), "Record does not have correct sourcePodName")
		assert.Contains(t, record, fmt.Sprintf("destinationPodName: %s", "perftest-c"), "Record does not have correct destinationPodName")
	}
}

func TestFlowExporterFlowExporterDestinations(t *testing.T) {
	skipIfNotFlowVisibilityTest(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 3)

	// Common Setup
	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")
	t.Cleanup(func() {
		teardownTest(t, data)
	})

	if antreaClusterUUID == "" {
		uuid, err := data.getAntreaClusterUUID(10 * time.Second)
		require.NoError(t, err, "Error when retrieving Antrea Cluster UUID")
		antreaClusterUUID = uuid.String()
	}

	collector1Name = randName("ipfix-collector-")
	opt1 := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			disableTLS:         false,
			selectedAggregator: 1,
		},
		ipfixCollector: flowVisibilityIPFIXTestOptions{
			name: collector1Name,
		},
	}
	collector1Addr = deployIPFIXCollectorForTest(t, opt1)

	collector2Name = randName("ipfix-collector-")
	opt2 := flowVisibilityTestOptions{
		mode:      flowaggregatorconfig.AggregatorModeProxy,
		clusterID: customClusterID,
		flowAggregator: flowAggregatorTestOptions{
			disableTLS:         false,
			selectedAggregator: 2,
		},
		ipfixCollector: flowVisibilityIPFIXTestOptions{
			name: collector2Name,
		},
	}
	collector2Addr = deployIPFIXCollectorForTest(t, opt2)

	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "Error when creating Kubernetes utils client")

	t.Logf("Creating Perf Pods")
	podAIPs, _, podCIPs, _, _, err = createPerftestPods(data)
	require.NoError(t, err, "Error when creating perftest Pods")

	runTests := func(t *testing.T, isIPv6 bool) {
		data.CleanFlowExporterDestinations()

		t.Run("one exporter", func(t *testing.T) {
			setupFlowExporterDestinationTest(t, opt1, opt2)

			createFlowExporterDestination(t, "single-exporter", true, flowAggregatorNamespace1)
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, flowAggregatorNamespace1), "Error when checking metrics of Flow Aggregator")

			generateTrafficAndVerify(t, data, isIPv6, verifyRecords(collector1Name))
		})

		t.Run("multi exporters", func(t *testing.T) {
			setupFlowExporterDestinationTest(t, opt1, opt2)

			createFlowExporterDestination(t, "multi-exporter-ag1", true, flowAggregatorNamespace1)
			createFlowExporterDestination(t, "multi-exporter-ag2", true, flowAggregatorNamespace2)

			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, flowAggregatorNamespace1), "Error when checking metrics of Flow Aggregator")
			require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, flowAggregatorNamespace2), "Error when checking metrics of Flow Aggregator 2")
			generateTrafficAndVerify(t, data, isIPv6, verifyRecords(collector1Name), verifyRecords(collector2Name))
		})
	}

	if isIPv4Enabled() {
		t.Run("IPv4", func(t *testing.T) {
			runTests(t, false)
		})
	}

	if isIPv6Enabled() {
		t.Run("IPv6", func(t *testing.T) {
			runTests(t, true)
		})
	}
}

func generateTrafficAndVerify(t *testing.T, data *TestData, isIPv6 bool, expectations ...verifierFunc) {
	label := "flow-exporter-destination-" + randSeq(8)
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

func BuildFlowExporterDestination(name, faServiceAddr string, protocol v1alpha1.FlowExporterProtocol,
	activeFlowTimeout, idleFlowTimeout int32, tlsConfig *v1alpha1.FlowExporterTLSConfig) *v1alpha1.FlowExporterDestination {

	flowAggregatorAddr := faServiceAddr + ":14739"
	if protocol.IPFIX != nil {
		flowAggregatorAddr = faServiceAddr + ":4739"
	}

	destination := &v1alpha1.FlowExporterDestination{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.FlowExporterDestinationSpec{
			Address:   flowAggregatorAddr,
			Protocol:  protocol,
			TLSConfig: tlsConfig,

			ActiveFlowExportTimeoutSeconds: activeFlowTimeout,
			IdleFlowExportTimeoutSeconds:   idleFlowTimeout,
		},
	}

	return destination
}

// CreateOrUpdateFlowExporterDestination is a convenience function for updating/creating FlowExporterDestinations.
func (data *TestData) CreateOrUpdateFlowExporterDestination(res *v1alpha1.FlowExporterDestination) (*v1alpha1.FlowExporterDestination, error) {
	log.Infof("Creating/updating FlowExporterDestination %s", res.Name)
	fedReturned, err := data.CRDClient.CrdV1alpha1().FlowExporterDestinations().Get(context.TODO(), res.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating FlowExporterDestination %s", res.Name)
		if !errors.IsNotFound(err) {
			return nil, err
		}
		res, err = data.CRDClient.CrdV1alpha1().FlowExporterDestinations().Create(context.TODO(), res, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create FlowExporterDestination: %s", err)
		}
		return res, err
	} else if fedReturned.Name != "" {
		log.Debugf("FlowExporterDestination with name %s already exists, updating", res.Name)
		fedReturned.Spec = res.Spec
		res, err = data.CRDClient.CrdV1alpha1().FlowExporterDestinations().Update(context.TODO(), fedReturned, metav1.UpdateOptions{})
		return res, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating FlowExporterDestination %s", res.Name)
}

// GetFlowExporterDestination is a convenience function for getting FlowExporterDestination.
func (data *TestData) GetFlowExporterDestination(name string) (*v1alpha1.FlowExporterDestination, error) {
	return data.CRDClient.CrdV1alpha1().FlowExporterDestinations().Get(context.TODO(), name, metav1.GetOptions{})
}

// DeleteFlowExporterDestination is a convenience function for deleting FET by name.
func (data *TestData) DeleteFlowExporterDestination(name string) error {
	log.Infof("Deleting FlowExporterDestination %s", name)
	return data.CRDClient.CrdV1alpha1().FlowExporterDestinations().Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// CleanFlowExporterDestinations is a convenience function for deleting all FlowExporterDestinations in the cluster.
func (data *TestData) CleanFlowExporterDestinations() error {
	return data.CRDClient.CrdV1alpha1().FlowExporterDestinations().DeleteCollection(context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{})
}
