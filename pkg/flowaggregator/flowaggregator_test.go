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

package flowaggregator

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/exporter"
	exportertesting "antrea.io/antrea/pkg/flowaggregator/exporter/testing"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
	ipfixtesting "antrea.io/antrea/pkg/ipfix/testing"
)

const (
	testActiveTimeout     = 60 * time.Second
	testInactiveTimeout   = 180 * time.Second
	informerDefaultResync = 12 * time.Hour
)

func init() {
	ipfixregistry.LoadRegistry()
}

func TestFlowAggregator_sendFlowKeyRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
	mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
	mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	mockAggregationProcess := ipfixtesting.NewMockIPFIXAggregationProcess(ctrl)

	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)

	newFlowAggregator := func(includePodLabels bool) *flowAggregator {
		return &flowAggregator{
			aggregatorTransportProtocol: "tcp",
			aggregationProcess:          mockAggregationProcess,
			activeFlowRecordTimeout:     testActiveTimeout,
			inactiveFlowRecordTimeout:   testInactiveTimeout,
			ipfixExporter:               mockIPFIXExporter,
			clickHouseExporter:          mockClickHouseExporter,
			registry:                    mockIPFIXRegistry,
			flowAggregatorAddress:       "",
			includePodLabels:            includePodLabels,
			podInformer:                 informerFactory.Core().V1().Pods(),
		}
	}

	mockExporters := []*exportertesting.MockInterface{mockIPFIXExporter, mockClickHouseExporter}

	ipv4Key := ipfixintermediate.FlowKey{
		SourceAddress:      "10.0.0.1",
		DestinationAddress: "10.0.0.2",
		Protocol:           6,
		SourcePort:         1234,
		DestinationPort:    5678,
	}

	ipv6Key := ipfixintermediate.FlowKey{
		SourceAddress:      "2001:0:3238:dfe1:63::fefb",
		DestinationAddress: "2001:0:3238:dfe1:63::fefc",
		Protocol:           6,
		SourcePort:         1234,
		DestinationPort:    5678,
	}

	readyRecord := &ipfixintermediate.AggregationFlowRecord{
		Record:      mockRecord,
		ReadyToSend: true,
	}

	testcases := []struct {
		name             string
		isIPv6           bool
		flowKey          ipfixintermediate.FlowKey
		flowRecord       *ipfixintermediate.AggregationFlowRecord
		includePodLabels bool
	}{
		{
			"IPv4_ready_to_send_with_pod_labels",
			false,
			ipv4Key,
			readyRecord,
			true,
		},
		{
			"IPv6_ready_to_send_with_pod_labels",
			true,
			ipv6Key,
			readyRecord,
			true,
		},
		{
			"IPv4_ready_to_send_without_pod_labels",
			false,
			ipv4Key,
			readyRecord,
			false,
		},
		{
			"IPv6_ready_to_send_without_pod_labels",
			true,
			ipv6Key,
			readyRecord,
			false,
		},
	}

	for _, tc := range testcases {
		fa := newFlowAggregator(tc.includePodLabels)
		for _, exporter := range mockExporters {
			exporter.EXPECT().AddRecord(mockRecord, tc.isIPv6)
		}
		mockAggregationProcess.EXPECT().ResetStatAndThroughputElementsInRecord(mockRecord).Return(nil)
		mockAggregationProcess.EXPECT().AreCorrelatedFieldsFilled(*tc.flowRecord).Return(false)
		emptyStr := make([]byte, 0)
		sourcePodNameElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("sourcePodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
		mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(sourcePodNameElem, 0, false)
		destPodNameElem, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("destinationPodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), emptyStr)
		mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(destPodNameElem, 0, false)
		mockAggregationProcess.EXPECT().SetCorrelatedFieldsFilled(tc.flowRecord, true)
		if tc.includePodLabels {
			mockAggregationProcess.EXPECT().AreExternalFieldsFilled(*tc.flowRecord).Return(false)
			sourcePodLabelsElement := ipfixentities.NewInfoElement("sourcePodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0)
			mockIPFIXRegistry.EXPECT().GetInfoElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID).Return(sourcePodLabelsElement, nil)
			sourcePodLabelsIE, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(sourcePodLabelsElement, bytes.NewBufferString("").Bytes())
			mockRecord.EXPECT().AddInfoElement(sourcePodLabelsIE).Return(nil)
			destinationPodLabelsElement := ipfixentities.NewInfoElement("destinationPodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0)
			mockIPFIXRegistry.EXPECT().GetInfoElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID).Return(ipfixentities.NewInfoElement("destinationPodLabels", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), nil)
			destinationPodLabelsIE, _ := ipfixentities.DecodeAndCreateInfoElementWithValue(destinationPodLabelsElement, bytes.NewBufferString("").Bytes())
			mockRecord.EXPECT().AddInfoElement(destinationPodLabelsIE).Return(nil)
			mockAggregationProcess.EXPECT().SetExternalFieldsFilled(tc.flowRecord, true)
		}
		mockAggregationProcess.EXPECT().IsAggregatedRecordIPv4(*tc.flowRecord).Return(!tc.isIPv6)

		err := fa.sendFlowKeyRecord(tc.flowKey, tc.flowRecord)
		assert.NoError(t, err, "Error in sending flow key record: %v, key: %v, record: %v", err, tc.flowKey, tc.flowRecord)
	}
}

func TestFlowAggregator_watchConfiguration(t *testing.T) {
	opt := options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
				Enable:  true,
				Address: "10.10.10.10:155",
			},
			ClickHouse: flowaggregatorconfig.ClickHouseConfig{
				Enable: true,
			},
			S3Uploader: flowaggregatorconfig.S3UploaderConfig{
				Enable:     true,
				BucketName: "test-bucket-name",
			},
		},
	}
	wd, err := os.Getwd()
	require.NoError(t, err)
	// fsnotify does not seem to work when using the default tempdir on MacOS, which is why we
	// use the current working directory.
	f, err := os.CreateTemp(wd, "test_*.config")
	require.NoError(t, err, "Failed to create test config file")
	fileName := f.Name()
	defer os.Remove(fileName)
	// create watcher
	configWatcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)
	defer configWatcher.Close()
	flowAggregator := &flowAggregator{
		// use a larger buffer to prevent the buffered channel from blocking
		updateCh:      make(chan *options.Options, 100),
		configFile:    fileName,
		configWatcher: configWatcher,
	}
	dir := filepath.Dir(fileName)
	t.Logf("DIR: %s", dir)
	require.NoError(t, err)
	err = flowAggregator.configWatcher.Add(dir)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	err = os.Remove(flowAggregator.configFile)
	require.NoError(t, err)
	f, err = os.Create(flowAggregator.configFile)
	require.NoError(t, err)
	b, err := yaml.Marshal(opt.Config)
	require.NoError(t, err)
	_, err = f.Write(b)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flowAggregator.watchConfiguration(stopCh)
	}()

	select {
	case msg := <-flowAggregator.updateCh:
		assert.Equal(t, opt.Config.FlowCollector.Enable, msg.Config.FlowCollector.Enable)
		assert.Equal(t, opt.Config.FlowCollector.Address, msg.Config.FlowCollector.Address)
		assert.Equal(t, opt.Config.ClickHouse.Enable, msg.Config.ClickHouse.Enable)
		assert.Equal(t, opt.Config.S3Uploader.Enable, msg.Config.S3Uploader.Enable)
		assert.Equal(t, opt.Config.S3Uploader.BucketName, msg.Config.S3Uploader.BucketName)
	case <-time.After(5 * time.Second):
		t.Errorf("Timeout while waiting for update")
	}
	close(stopCh)
	wg.Wait()
}

func TestFlowAggregator_updateFlowAggregator(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
	mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
	mockS3Exporter := exportertesting.NewMockInterface(ctrl)

	newIPFIXExporterSaved := newIPFIXExporter
	newClickHouseExporterSaved := newClickHouseExporter
	newS3ExporterSaved := newS3Exporter
	defer func() {
		newIPFIXExporter = newIPFIXExporterSaved
		newClickHouseExporter = newClickHouseExporterSaved
		newS3Exporter = newS3ExporterSaved
	}()
	newIPFIXExporter = func(kubernetes.Interface, *options.Options, ipfix.IPFIXRegistry) exporter.Interface {
		return mockIPFIXExporter
	}
	newClickHouseExporter = func(kubernetes.Interface, *options.Options) (exporter.Interface, error) {
		return mockClickHouseExporter, nil
	}
	newS3Exporter = func(kubernetes.Interface, *options.Options) (exporter.Interface, error) {
		return mockS3Exporter, nil
	}

	t.Run("updateIPFIX", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			ipfixExporter: mockIPFIXExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
					Enable:  true,
					Address: "10.10.10.10:155",
				},
			},
		}
		mockIPFIXExporter.EXPECT().UpdateOptions(opt)
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("disableIPFIX", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			ipfixExporter: mockIPFIXExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
					Enable: false,
				},
			},
		}
		mockIPFIXExporter.EXPECT().Stop()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("enableClickHouse", func(t *testing.T) {
		flowAggregator := &flowAggregator{}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				ClickHouse: flowaggregatorconfig.ClickHouseConfig{
					Enable: true,
				},
			},
		}
		mockClickHouseExporter.EXPECT().Start()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("disableClickHouse", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			clickHouseExporter: mockClickHouseExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				ClickHouse: flowaggregatorconfig.ClickHouseConfig{
					Enable: false,
				},
			},
		}
		mockClickHouseExporter.EXPECT().Stop()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("updateClickHouse", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			clickHouseExporter: mockClickHouseExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				ClickHouse: flowaggregatorconfig.ClickHouseConfig{
					Enable: true,
				},
			},
		}
		mockClickHouseExporter.EXPECT().UpdateOptions(opt)
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("enableS3Uploader", func(t *testing.T) {
		flowAggregator := &flowAggregator{}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				S3Uploader: flowaggregatorconfig.S3UploaderConfig{
					Enable:     true,
					BucketName: "test-bucket-name",
				},
			},
		}
		mockS3Exporter.EXPECT().Start()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("disableS3Uploader", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			s3Exporter: mockS3Exporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				S3Uploader: flowaggregatorconfig.S3UploaderConfig{
					Enable: false,
				},
			},
		}
		mockS3Exporter.EXPECT().Stop()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("updateS3Uploader", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			s3Exporter: mockS3Exporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				S3Uploader: flowaggregatorconfig.S3UploaderConfig{
					Enable:     true,
					BucketName: "test-bucket-name",
				},
			},
		}
		mockS3Exporter.EXPECT().UpdateOptions(opt)
		flowAggregator.updateFlowAggregator(opt)
	})
}

func TestFlowAggregator_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
	mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
	mockS3Exporter := exportertesting.NewMockInterface(ctrl)
	mockCollectingProcess := ipfixtesting.NewMockIPFIXCollectingProcess(ctrl)
	mockAggregationProcess := ipfixtesting.NewMockIPFIXAggregationProcess(ctrl)

	newIPFIXExporterSaved := newIPFIXExporter
	newClickHouseExporterSaved := newClickHouseExporter
	newS3ExporterSaved := newS3Exporter
	defer func() {
		newIPFIXExporter = newIPFIXExporterSaved
		newClickHouseExporter = newClickHouseExporterSaved
		newS3Exporter = newS3ExporterSaved
	}()
	newIPFIXExporter = func(kubernetes.Interface, *options.Options, ipfix.IPFIXRegistry) exporter.Interface {
		return mockIPFIXExporter
	}
	newClickHouseExporter = func(kubernetes.Interface, *options.Options) (exporter.Interface, error) {
		return mockClickHouseExporter, nil
	}
	newS3Exporter = func(kubernetes.Interface, *options.Options) (exporter.Interface, error) {
		return mockS3Exporter, nil
	}

	// create dummy watcher: we will not add any files or directory to it.
	configWatcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)
	defer configWatcher.Close()

	updateCh := make(chan *options.Options)

	updateOptions := func(opt *options.Options) {
		// this is somewhat hacky: we use a non-buffered channel and
		// every update is sent twice. This way, we can guarantee that by
		// the time the second statement returns, the options have been
		// processed at least once.
		updateCh <- opt
		updateCh <- opt
	}

	flowAggregator := &flowAggregator{
		activeFlowRecordTimeout: 1 * time.Hour,
		logTickerDuration:       1 * time.Hour,
		collectingProcess:       mockCollectingProcess,
		aggregationProcess:      mockAggregationProcess,
		ipfixExporter:           mockIPFIXExporter,
		configWatcher:           configWatcher,
		updateCh:                updateCh,
	}

	mockCollectingProcess.EXPECT().Start()
	mockCollectingProcess.EXPECT().Stop()
	mockAggregationProcess.EXPECT().Start()
	mockAggregationProcess.EXPECT().Stop()

	// this is not really relevant; but in practice there will be one call
	// to mockClickHouseExporter.UpdateOptions because of the hack used to
	// implement updateOptions above.
	mockIPFIXExporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()
	mockClickHouseExporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()
	mockS3Exporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flowAggregator.Run(stopCh)
	}()

	disableIPFIXOptions := &options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
				Enable: false,
			},
		},
	}
	enableIPFIXOptions := &options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
				Enable: true,
			},
		},
	}
	enableClickHouseOptions := &options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			ClickHouse: flowaggregatorconfig.ClickHouseConfig{
				Enable: true,
			},
		},
	}
	disableClickHouseOptions := &options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			ClickHouse: flowaggregatorconfig.ClickHouseConfig{
				Enable: false,
			},
		},
	}
	enableS3UploaderOptions := &options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			S3Uploader: flowaggregatorconfig.S3UploaderConfig{
				Enable: true,
			},
		},
	}
	disableS3UploaderOptions := &options.Options{
		Config: &flowaggregatorconfig.FlowAggregatorConfig{
			S3Uploader: flowaggregatorconfig.S3UploaderConfig{
				Enable: false,
			},
		},
	}

	mockIPFIXExporter.EXPECT().Start().Times(2)
	mockIPFIXExporter.EXPECT().Stop().Times(2)
	mockClickHouseExporter.EXPECT().Start()
	mockClickHouseExporter.EXPECT().Stop()
	mockS3Exporter.EXPECT().Start()
	mockS3Exporter.EXPECT().Stop()

	// we do a few operations: the main purpose is to ensure that cleanup
	// (i.e., stopping the exporters) is done properly. This sequence of
	// updates determines the mock expectations above.
	// 1. The IPFIXExporter is enabled on start, so we expect a call to mockIPFIXExporter.Start()
	// 2. The IPFIXExporter is then disabled, so we expect a call to mockIPFIXExporter.Stop()
	// 3. The ClickHouseExporter is then enabled, so we expect a call to mockClickHouseExporter.Start()
	// 4. The ClickHouseExporter is then disabled, so we expect a call to mockClickHouseExporter.Stop()
	// 5. The S3Uploader is then enabled, so we expect a call to mockS3Exporter.Start()
	// 6. The S3Uploader is then disabled, so we expect a call to mockS3Exporter.Stop()
	// 7. The IPFIXExporter is then re-enabled, so we expect a second call to mockIPFIXExporter.Start()
	// 8. Finally, when Run() is stopped, we expect a second call to mockIPFIXExporter.Stop()
	updateOptions(disableIPFIXOptions)
	updateOptions(enableClickHouseOptions)
	updateOptions(disableClickHouseOptions)
	updateOptions(enableS3UploaderOptions)
	updateOptions(disableS3UploaderOptions)
	updateOptions(enableIPFIXOptions)

	close(stopCh)
	wg.Wait()
}

// When the FlowAggregator is stopped (stopCh is closed), watchConfiguration and
// flowExportLoop are stopped asynchronosuly. If watchConfiguration is stopped
// "first" and the updateCh is closed, we need to make sure that flowExportLoop
// (which reads from updateCh) can handle correctly the channel closing.
func TestFlowAggregator_closeUpdateChBeforeFlowExportLoopReturns(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	// fsnotify does not seem to work when using the default tempdir on MacOS, which is why we
	// use the current working directory.
	f, err := os.CreateTemp(wd, "test_*.config")
	require.NoError(t, err, "Failed to create test config file")
	fileName := f.Name()
	defer os.Remove(fileName)
	// create watcher
	configWatcher, err := fsnotify.NewWatcher()
	require.NoError(t, err)
	defer configWatcher.Close()
	flowAggregator := &flowAggregator{
		updateCh:                make(chan *options.Options),
		configFile:              fileName,
		configWatcher:           configWatcher,
		activeFlowRecordTimeout: 1 * time.Hour,
		logTickerDuration:       1 * time.Hour,
	}

	stopCh1 := make(chan struct{})
	var wg1 sync.WaitGroup
	wg1.Add(1)
	go func() {
		defer wg1.Done()
		flowAggregator.watchConfiguration(stopCh1)
	}()

	stopCh2 := make(chan struct{})
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		flowAggregator.flowExportLoop(stopCh2)
	}()

	// stop watchConfiguration, wait, then stop flowExportLoop.
	// the test is essentially successful if it doesn't panic.
	close(stopCh1)
	wg1.Wait()
	close(stopCh2)
	wg2.Wait()
}

func TestFlowAggregator_podInfoIndexFunc(t *testing.T) {
	node := &v1.Node{}
	pendingPod := &v1.Pod{
		Status: v1.PodStatus{
			Phase: v1.PodPending,
			PodIPs: []v1.PodIP{
				{
					IP: "192.168.1.2",
				},
			},
		},
	}
	succeededPod := &v1.Pod{
		Status: v1.PodStatus{
			Phase: v1.PodSucceeded,
			PodIPs: []v1.PodIP{
				{
					IP: "192.168.1.3",
				},
			},
		},
	}

	tests := []struct {
		name        string
		obj         interface{}
		want        []string
		expectedErr string
	}{
		{
			name:        "object is not pod",
			obj:         node,
			expectedErr: "obj is not pod: ",
		},
		{
			name: "pod status in pending phase",
			obj:  pendingPod,
			want: []string{"192.168.1.2"},
		},
		{
			name: "pod status in succeeded phase",
			obj:  succeededPod,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := podInfoIndexFunc(tt.obj)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFlowAggregator_fetchPodLabels(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "testPod",
			Labels: map[string]string{
				"test": "ut",
			},
		},
		Status: v1.PodStatus{
			Phase: v1.PodPending,
			PodIPs: []v1.PodIP{
				{
					IP: "192.168.1.2",
				},
			},
		},
	}

	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	informerFactory.Core().V1().Pods().Informer().AddIndexers(cache.Indexers{podInfoIndex: podInfoIndexFunc})

	stopCh := make(chan struct{})
	defer close(stopCh)

	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	informerFactory.Core().V1().Pods().Informer().GetIndexer().Add(pod)

	tests := []struct {
		name       string
		podAddress string
		want       string
	}{
		{
			name:       "no pod object",
			podAddress: "192.168.1.3",
		},
		{
			name:       "pod with label",
			podAddress: "192.168.1.2",
			want:       "{\"test\":\"ut\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fa := &flowAggregator{
				k8sClient:        client,
				includePodLabels: true,
				podInformer:      informerFactory.Core().V1().Pods(),
			}
			got := fa.fetchPodLabels(tt.podAddress)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFlowAggregator_GetRecordMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCollectingProcess := ipfixtesting.NewMockIPFIXCollectingProcess(ctrl)
	mockAggregationProcess := ipfixtesting.NewMockIPFIXAggregationProcess(ctrl)
	want := querier.Metrics{
		NumRecordsExported: 1,
		NumRecordsReceived: 1,
		NumFlows:           1,
		NumConnToCollector: 1,
	}

	fa := &flowAggregator{
		collectingProcess:  mockCollectingProcess,
		aggregationProcess: mockAggregationProcess,
		numRecordsExported: 1,
	}

	mockCollectingProcess.EXPECT().GetNumRecordsReceived().Return(int64(1))
	mockAggregationProcess.EXPECT().GetNumFlows().Return(int64(1))
	mockCollectingProcess.EXPECT().GetNumConnToCollector().Return(int64(1))

	got := fa.GetRecordMetrics()
	assert.Equal(t, want, got)
}

func TestFlowAggregator_InitCollectingProcess(t *testing.T) {
	tests := []struct {
		name                        string
		aggregatorTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol
		flowAggregatorAddress       string
		k8sClient                   kubernetes.Interface
	}{
		{
			name:                        "TLS protocol",
			aggregatorTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolTLS,
			k8sClient:                   fake.NewSimpleClientset(),
			flowAggregatorAddress:       "192.168.1.2",
		},
		{
			name:                        "TCP protocol",
			aggregatorTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolTCP,
			k8sClient:                   fake.NewSimpleClientset(),
		},
		{
			name:      "neither TLS nor TCP protocol",
			k8sClient: fake.NewSimpleClientset(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fa := &flowAggregator{
				aggregatorTransportProtocol: tt.aggregatorTransportProtocol,
				flowAggregatorAddress:       tt.flowAggregatorAddress,
				k8sClient:                   tt.k8sClient,
			}
			err := fa.InitCollectingProcess()
			require.NoError(t, err)
		})
	}
}

func TestFlowAggregator_InitAggregationProcess(t *testing.T) {
	fa := &flowAggregator{
		activeFlowRecordTimeout:     testActiveTimeout,
		inactiveFlowRecordTimeout:   testInactiveTimeout,
		aggregatorTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolTCP,
	}
	err := fa.InitCollectingProcess()
	require.NoError(t, err)

	err = fa.InitAggregationProcess()
	require.NoError(t, err)
}

func TestFlowAggregator_fillK8sMetadata(t *testing.T) {
	srcPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "sourcePod",
		},
		Spec: v1.PodSpec{
			NodeName: "sourceNode",
		},
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "192.168.1.2",
				},
			},
		},
	}
	dstPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "destinationPod",
		},
		Spec: v1.PodSpec{
			NodeName: "destinationNode",
		},
		Status: v1.PodStatus{
			PodIPs: []v1.PodIP{
				{
					IP: "192.168.1.3",
				},
			},
		},
	}
	emptyStr := make([]byte, 0)
	sourcePodNameElem, err := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("sourcePodName", uint16(0), ipfixentities.String, ipfixregistry.AntreaEnterpriseID, uint16(0)), emptyStr)
	require.NoError(t, err)
	sourcePodNamespaceElem, err := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("sourcePodNamespace", uint16(0), ipfixentities.String, ipfixregistry.AntreaEnterpriseID, uint16(0)), emptyStr)
	require.NoError(t, err)
	sourceNodeNameElem, err := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("sourceNodeName", uint16(0), ipfixentities.String, ipfixregistry.AntreaEnterpriseID, uint16(0)), emptyStr)
	require.NoError(t, err)
	destinationPodNameElem, err := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("destinationPodName", uint16(0), ipfixentities.String, ipfixregistry.AntreaEnterpriseID, uint16(0)), emptyStr)
	require.NoError(t, err)
	destinationPodNamespaceElem, err := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("destinationPodNamespace", uint16(0), ipfixentities.String, ipfixregistry.AntreaEnterpriseID, uint16(0)), emptyStr)
	require.NoError(t, err)
	destinationNodeNameElem, err := ipfixentities.DecodeAndCreateInfoElementWithValue(ipfixentities.NewInfoElement("destinationNodeName", uint16(0), ipfixentities.String, ipfixregistry.AntreaEnterpriseID, uint16(0)), emptyStr)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	informerFactory.Core().V1().Pods().Informer().AddIndexers(cache.Indexers{podInfoIndex: podInfoIndexFunc})

	stopCh := make(chan struct{})
	defer close(stopCh)

	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	informerFactory.Core().V1().Pods().Informer().GetIndexer().Add(srcPod)
	informerFactory.Core().V1().Pods().Informer().GetIndexer().Add(dstPod)

	ipv4Key := ipfixintermediate.FlowKey{
		SourceAddress:      "192.168.1.2",
		DestinationAddress: "192.168.1.3",
	}

	fa := &flowAggregator{
		podInformer: informerFactory.Core().V1().Pods(),
	}

	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(sourcePodNameElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodNamespace").Return(sourcePodNamespaceElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("sourceNodeName").Return(sourceNodeNameElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(destinationPodNameElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodNamespace").Return(destinationPodNamespaceElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("destinationNodeName").Return(destinationNodeNameElem, 0, true)

	fa.fillK8sMetadata(ipv4Key, mockRecord)
}
