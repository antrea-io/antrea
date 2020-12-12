// Copyright 2020 Antrea Authors
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

package usagereport

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/featuregate"

	nptesting "github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/testing"
	"github.com/vmware-tanzu/antrea/pkg/controller/usagereport/api"
	"github.com/vmware-tanzu/antrea/pkg/features"
)

const (
	informerDefaultResync time.Duration = 30 * time.Second

	testReportInterval = 100 * time.Millisecond

	testReportInitialDelay = 0 * time.Millisecond

	antreaConfigMapName = "antrea-config"

	defaultNumNamespaces                   = 3
	defaultNumPods                         = 100
	defaultNumTiers                        = 0
	defaultNumNetworkPolicies              = 100
	defaultNumAntreaNetworkPolicies        = 0
	defaultNumAntreaClusterNetworkPolicies = 0
)

var (
	clusterUUID = uuid.New()

	// First release of Antrea (v0.1.0) at KubeCon NA 2019 (San Diego) :)
	sanDiegoLocation, _        = time.LoadLocation("America/Los_Angeles")
	configMapCreationTimestamp = metav1.Date(2019, time.November, 18, 11, 26, 2, 0, sanDiegoLocation)

	antreaConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultAntreaNamespace, Name: antreaConfigMapName},
		Data: map[string]string{
			"antrea-agent.conf":      "", // use all defaults
			"antrea-controller.conf": "",
		},
	}

	uuidConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         defaultAntreaNamespace,
			Name:              uuidConfigMapName,
			CreationTimestamp: configMapCreationTimestamp,
		},
		Data: map[string]string{
			uuidConfigMapKey: clusterUUID.String(),
		},
	}

	uuidConfigMapEmpty = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         defaultAntreaNamespace,
			Name:              uuidConfigMapName,
			CreationTimestamp: configMapCreationTimestamp,
		},
		Data: map[string]string{},
	}

	nodeSystemInfo = corev1.NodeSystemInfo{
		KernelVersion:           "4.15.0-72-generic",
		OSImage:                 "Ubuntu 18.04.3 LTS",
		ContainerRuntimeVersion: "docker://20.10.0",
		KubeletVersion:          "v1.20.0",
		KubeProxyVersion:        "v1.20.0",
		OperatingSystem:         "linux",
		Architecture:            "amd64",
	}

	node1 = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		Spec:       corev1.NodeSpec{},
		Status: corev1.NodeStatus{
			NodeInfo: nodeSystemInfo,
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.1.1",
				},
			},
		},
	}
)

type testData struct {
	*testing.T
	ts                             *httptest.Server
	usageReports                   []*api.UsageReport
	stopCh                         chan struct{}
	ctrl                           *gomock.Controller
	mockNetworkPolicyUsageReporter *nptesting.MockNetworkPolicyUsageReporter
	reporter                       *Reporter
	wg                             sync.WaitGroup
}

func setUp(t *testing.T, objects ...runtime.Object) *testData {
	client := fake.NewSimpleClientset(objects...)
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	nodeInformer := informerFactory.Core().V1().Nodes()

	data := testData{
		T:      t,
		stopCh: make(chan struct{}),
	}

	data.ctrl = gomock.NewController(t)
	data.mockNetworkPolicyUsageReporter = nptesting.NewMockNetworkPolicyUsageReporter(data.ctrl)

	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumNamespaces().Return(defaultNumNamespaces, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumPods().Return(defaultNumPods, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumTiers().Return(defaultNumTiers, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumNetworkPolicies().Return(defaultNumNetworkPolicies, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumAntreaNetworkPolicies().Return(defaultNumAntreaNetworkPolicies, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumAntreaClusterNetworkPolicies().Return(defaultNumAntreaClusterNetworkPolicies, nil).AnyTimes()

	data.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err, "Error when reading HTTP request body")
		var report api.UsageReport
		assert.NoError(t, json.Unmarshal(b, &report), "Error when unmarshalling usage report")
		t.Logf("Received test usage report for cluster %s (%d bytes)", report.ClusterUUID, len(b))
		data.usageReports = append(data.usageReports, &report)
	}))

	setTestURL := func(config *ReporterConfig) { config.ServerURL = data.ts.URL }
	setTestReportInterval := func(config *ReporterConfig) { config.ReportInterval = testReportInterval }
	setTestReportInitialDelay := func(config *ReporterConfig) { config.ReportInitialDelay = testReportInitialDelay }
	setAntreaNamespace := func(config *ReporterConfig) { config.AntreaNamespace = defaultAntreaNamespace }
	setAntreaConfigMapName := func(config *ReporterConfig) { config.AntreaConfigMapName = antreaConfigMapName }

	data.reporter = NewReporter(
		client, nodeInformer, data.mockNetworkPolicyUsageReporter,
		setTestURL, setTestReportInterval, setTestReportInitialDelay, setAntreaNamespace, setAntreaConfigMapName,
	)

	informerFactory.Start(data.stopCh)

	return &data
}

func (data *testData) runFor(d time.Duration) {
	data.wg.Add(1)
	go func() {
		defer data.wg.Done()
		data.reporter.Run(data.stopCh)
	}()
	time.Sleep(d)
	close(data.stopCh)
	data.wg.Wait()
}

func (data *testData) tearDown() {
	data.ts.Close()
	data.ctrl.Finish()
}

func (data *testData) checkUsageReports(minCount int, maxCount int, expectedClusterUUID string, numNodes int) {
	require.GreaterOrEqual(data, len(data.usageReports), minCount, "Not enough usage reports received")
	require.LessOrEqual(data, len(data.usageReports), maxCount, "Too many usage reports received")

	for _, report := range data.usageReports[:minCount] {
		if expectedClusterUUID != "" {
			assert.Equal(data, expectedClusterUUID, report.ClusterUUID)
		} else {
			var err error
			_, err = uuid.Parse(report.ClusterUUID)
			assert.NoError(data, err, "Report does not include valid UUID")
			// we will check that subsequent reports include the same UUID
			expectedClusterUUID = report.ClusterUUID
		}

		// comparing timestamps directly does not work because of different location pointers
		assert.True(data, report.AntreaDeploymentTime.Equal(configMapCreationTimestamp.Time))

		assert.Equal(data, api.K8sDistributionUnknown, report.ClusterInfo.K8sDistribution)
		assert.Equal(data, []api.IPFamily{api.IPFamilyIPv4}, report.ClusterInfo.IPFamilies)

		assert.Len(data, report.ClusterInfo.Nodes, numNodes)
		assert.EqualValues(data, numNodes, *report.ClusterInfo.NumNodes)
		assert.EqualValues(data, defaultNumPods, *report.ClusterInfo.NumPods)
		assert.EqualValues(data, defaultNumNetworkPolicies, *report.ClusterInfo.NetworkPolicies.NumNetworkPolicies)
		assert.EqualValues(data, defaultNumAntreaNetworkPolicies, *report.ClusterInfo.NetworkPolicies.NumAntreaNetworkPolicies)
		for _, node := range report.ClusterInfo.Nodes {
			// TODO: check the entire struct?
			assert.Equal(data, nodeSystemInfo.KernelVersion, node.KernelVersion)
			assert.True(data, node.HasIPv4Address)
			assert.False(data, node.HasIPv6Address)
		}

		assert.Equal(data, agentConfigDefaults.EnablePrometheusMetrics, report.AgentConfig.EnablePrometheusMetrics)
		assert.Equal(data, controllerConfigDefaults.EnablePrometheusMetrics, report.ControllerConfig.EnablePrometheusMetrics)

		assert.Len(data, report.AgentConfig.FeatureGates, len(features.DefaultAntreaFeatureGates))
		for _, featureGate := range report.AgentConfig.FeatureGates {
			assert.Equal(data, features.DefaultFeatureGate.Enabled(featuregate.Feature(featureGate.Name)), featureGate.Enabled)
		}
		assert.Len(data, report.ControllerConfig.FeatureGates, len(features.DefaultAntreaFeatureGates))
		for _, featureGate := range report.ControllerConfig.FeatureGates {
			assert.Equal(data, features.DefaultFeatureGate.Enabled(featuregate.Feature(featureGate.Name)), featureGate.Enabled)
		}
	}
}

func TestUsageReportingNoUUID(t *testing.T) {
	data := setUp(t, node1, antreaConfigMap, uuidConfigMapEmpty)
	defer data.tearDown()

	data.runFor(time.Second)
	// we should receive about 10 usage reports (one every 100ms for 1s)
	data.checkUsageReports(2, 20, "", 1)
}

func TestUsageReportingExistingUUID(t *testing.T) {
	data := setUp(t, node1, antreaConfigMap, uuidConfigMap)
	defer data.tearDown()

	data.runFor(time.Second)
	// we should receive about 10 usage reports (one every 100ms for 1s)
	data.checkUsageReports(2, 20, clusterUUID.String(), 1)
}

func TestDetectDistribution(t *testing.T) {
	testCases := []struct {
		envVar               string
		expectedDistribution api.K8sDistributionName
	}{
		{"", api.K8sDistributionUnknown},
		{"ANTREA_CLOUD_AKS", api.K8sDistributionAKS},
		{"ANTREA_CLOUD_EKS", api.K8sDistributionEKS},
		{"ANTREA_CLOUD_GKE", api.K8sDistributionGKE},
	}

	data := setUp(t, node1, antreaConfigMap, uuidConfigMapEmpty)
	defer data.tearDown()

	for _, tc := range testCases {
		t.Run(string(tc.expectedDistribution), func(t *testing.T) {
			if tc.envVar != "" {
				err := os.Setenv(tc.envVar, "true")
				require.NoError(t, err, "Error when setting env var")
				defer func() {
					err := os.Unsetenv(tc.envVar)
					assert.NoError(t, err, "Error when unsetting env var")
				}()
			}
			assert.Equal(t, tc.expectedDistribution, data.reporter.getK8sDistribution())
		})
	}
}
