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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/exporter"
	exportertesting "antrea.io/antrea/pkg/flowaggregator/exporter/testing"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
	ipfixtesting "antrea.io/antrea/pkg/ipfix/testing"
	podstoretest "antrea.io/antrea/pkg/util/podstore/testing"
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

	podA := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "podA",
		},
	}
	podB := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "podB",
		},
	}

	testcases := []struct {
		name             string
		isIPv6           bool
		flowKey          ipfixintermediate.FlowKey
		includePodLabels bool
	}{
		{
			"IPv4_ready_to_send_with_pod_labels",
			false,
			ipv4Key,
			true,
		},
		{
			"IPv6_ready_to_send_with_pod_labels",
			true,
			ipv6Key,
			true,
		},
		{
			"IPv4_ready_to_send_without_pod_labels",
			false,
			ipv4Key,
			false,
		},
		{
			"IPv6_ready_to_send_without_pod_labels",
			true,
			ipv6Key,
			false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := podstoretest.NewMockInterface(ctrl)
			mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
			mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
			mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
			mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
			mockAggregationProcess := ipfixtesting.NewMockIPFIXAggregationProcess(ctrl)

			clusterUUID := uuid.New()
			newFlowAggregator := func(includePodLabels bool) *flowAggregator {
				return &flowAggregator{
					clusterUUID:                 clusterUUID,
					aggregatorTransportProtocol: "tcp",
					aggregationProcess:          mockAggregationProcess,
					activeFlowRecordTimeout:     testActiveTimeout,
					inactiveFlowRecordTimeout:   testInactiveTimeout,
					ipfixExporter:               mockIPFIXExporter,
					clickHouseExporter:          mockClickHouseExporter,
					registry:                    mockIPFIXRegistry,
					flowAggregatorAddress:       "",
					includePodLabels:            includePodLabels,
					podStore:                    mockPodStore,
				}
			}

			mockExporters := []*exportertesting.MockInterface{mockIPFIXExporter, mockClickHouseExporter}

			flowRecord := &ipfixintermediate.AggregationFlowRecord{
				Record:      mockRecord,
				ReadyToSend: true,
			}

			fa := newFlowAggregator(tc.includePodLabels)
			for _, exporter := range mockExporters {
				exporter.EXPECT().AddRecord(mockRecord, tc.isIPv6)
			}

			startTime := time.Now().Truncate(time.Second)

			mockAggregationProcess.EXPECT().ResetStatAndThroughputElementsInRecord(mockRecord).Return(nil)
			flowStartSecondsIE := ipfixentities.NewDateTimeSecondsInfoElement(ipfixentities.NewInfoElement("flowStartSeconds", 150, 14, ipfixregistry.IANAEnterpriseID, 4), uint32(startTime.Unix()))
			mockRecord.EXPECT().GetInfoElementWithValue("flowStartSeconds").Return(flowStartSecondsIE, 0, true)
			mockAggregationProcess.EXPECT().AreCorrelatedFieldsFilled(*flowRecord).Return(false)
			sourcePodNameIE := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("sourcePodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), "podA")
			mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(sourcePodNameIE, 0, true).MinTimes(1)
			destinationPodNameIE := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("destinationPodName", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), "podB")
			mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(destinationPodNameIE, 0, true).MinTimes(1)
			mockAggregationProcess.EXPECT().SetCorrelatedFieldsFilled(flowRecord, true)
			mockAggregationProcess.EXPECT().AreExternalFieldsFilled(*flowRecord).Return(false)
			podLabels := ""
			if tc.includePodLabels {
				podLabels = "{}"
				sourcePodNamespaceIE := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("sourcePodNamespace", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), "default")
				mockRecord.EXPECT().GetInfoElementWithValue("sourcePodNamespace").Return(sourcePodNamespaceIE, 0, true)
				destinationPodNamespaceIE := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("destinationPodNamespace", 0, 0, ipfixregistry.AntreaEnterpriseID, 0), "default")
				mockRecord.EXPECT().GetInfoElementWithValue("destinationPodNamespace").Return(destinationPodNamespaceIE, 0, true)
				mockPodStore.EXPECT().GetPodByIPAndTime(tc.flowKey.SourceAddress, startTime).Return(podA, true)
				mockPodStore.EXPECT().GetPodByIPAndTime(tc.flowKey.DestinationAddress, startTime).Return(podB, true)
			}
			sourcePodLabelsElement := ipfixentities.NewInfoElement("sourcePodLabels", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0)
			mockIPFIXRegistry.EXPECT().GetInfoElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID).Return(sourcePodLabelsElement, nil)
			sourcePodLabelsIE := ipfixentities.NewStringInfoElement(sourcePodLabelsElement, podLabels)
			mockRecord.EXPECT().AddInfoElement(sourcePodLabelsIE).Return(nil)
			destinationPodLabelsElement := ipfixentities.NewInfoElement("destinationPodLabels", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0)
			mockIPFIXRegistry.EXPECT().GetInfoElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID).Return(destinationPodLabelsElement, nil)
			destinationPodLabelsIE := ipfixentities.NewStringInfoElement(destinationPodLabelsElement, podLabels)
			mockRecord.EXPECT().AddInfoElement(destinationPodLabelsIE).Return(nil)
			clusterIDElement := ipfixentities.NewInfoElement("clusterId", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0)
			mockIPFIXRegistry.EXPECT().GetInfoElement("clusterId", ipfixregistry.AntreaEnterpriseID).Return(clusterIDElement, nil)
			clusterIDIE := ipfixentities.NewStringInfoElement(clusterIDElement, clusterUUID.String())
			mockRecord.EXPECT().AddInfoElement(clusterIDIE).Return(nil)
			mockAggregationProcess.EXPECT().SetExternalFieldsFilled(flowRecord, true)
			mockAggregationProcess.EXPECT().IsAggregatedRecordIPv4(*flowRecord).Return(!tc.isIPv6)

			err := fa.sendFlowKeyRecord(tc.flowKey, flowRecord)
			assert.NoError(t, err, "Error when sending flow key record, key: %v, record: %v", tc.flowKey, flowRecord)
		})
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
			FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
				Enable: true,
				Path:   "/tmp/antrea-flows.log",
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
		assert.Equal(t, opt.Config.FlowLogger.Enable, msg.Config.FlowLogger.Enable)
		assert.Equal(t, opt.Config.FlowLogger.Path, msg.Config.FlowLogger.Path)
	case <-time.After(5 * time.Second):
		t.Errorf("Timeout while waiting for update")
	}
	close(stopCh)
	wg.Wait()
}

// mockExporters creates mocks for all supported exporters and returns them. It also modifies the
// global functions used by the FlowAggregator to instantiate the exporters, so that the mocks are
// returned. The functions will be automatically restored at the end of the test. If
// expectedClusterUUID is not nil, the functions will assert that the correct UUID is provided by
// the FlowAggregator when instantiating an exporter, if applicable.
func mockExporters(t *testing.T, ctrl *gomock.Controller, expectedClusterUUID *uuid.UUID) (
	*exportertesting.MockInterface,
	*exportertesting.MockInterface,
	*exportertesting.MockInterface,
	*exportertesting.MockInterface,
) {
	mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
	mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
	mockS3Exporter := exportertesting.NewMockInterface(ctrl)
	mockLogExporter := exportertesting.NewMockInterface(ctrl)

	newIPFIXExporterSaved := newIPFIXExporter
	newClickHouseExporterSaved := newClickHouseExporter
	newS3ExporterSaved := newS3Exporter
	newLogExporterSaved := newLogExporter
	t.Cleanup(func() {
		newIPFIXExporter = newIPFIXExporterSaved
		newClickHouseExporter = newClickHouseExporterSaved
		newS3Exporter = newS3ExporterSaved
		newLogExporter = newLogExporterSaved
	})
	newIPFIXExporter = func(clusterUUID uuid.UUID, opts *options.Options, registry ipfix.IPFIXRegistry) exporter.Interface {
		if expectedClusterUUID != nil {
			assert.Equal(t, *expectedClusterUUID, clusterUUID)
		}
		return mockIPFIXExporter
	}
	newClickHouseExporter = func(clusterUUID uuid.UUID, opts *options.Options) (exporter.Interface, error) {
		if expectedClusterUUID != nil {
			assert.Equal(t, *expectedClusterUUID, clusterUUID)
		}
		return mockClickHouseExporter, nil
	}
	newS3Exporter = func(clusterUUID uuid.UUID, opts *options.Options) (exporter.Interface, error) {
		if expectedClusterUUID != nil {
			assert.Equal(t, *expectedClusterUUID, clusterUUID)
		}
		return mockS3Exporter, nil
	}
	newLogExporter = func(opt *options.Options) (exporter.Interface, error) {
		return mockLogExporter, nil
	}

	return mockIPFIXExporter, mockClickHouseExporter, mockS3Exporter, mockLogExporter
}

func TestFlowAggregator_updateFlowAggregator(t *testing.T) {
	ctrl := gomock.NewController(t)

	mockIPFIXExporter, mockClickHouseExporter, mockS3Exporter, mockLogExporter := mockExporters(t, ctrl, nil)

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
	t.Run("enableFlowLogger", func(t *testing.T) {
		flowAggregator := &flowAggregator{}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
					Enable: true,
					Path:   "/tmp/antrea-flows.log",
				},
			},
		}
		mockLogExporter.EXPECT().Start()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("disableFlowLogger", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			s3Exporter: mockLogExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
					Enable: false,
				},
			},
		}
		mockLogExporter.EXPECT().Stop()
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("updateFlowLogger", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			logExporter: mockLogExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
					Enable: true,
					Path:   "/tmp/antrea-flows.log",
				},
			},
		}
		mockLogExporter.EXPECT().UpdateOptions(opt)
		flowAggregator.updateFlowAggregator(opt)
	})
	t.Run("includePodLabels", func(t *testing.T) {
		flowAggregator := &flowAggregator{}
		require.False(t, flowAggregator.includePodLabels)
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				RecordContents: flowaggregatorconfig.RecordContentsConfig{
					PodLabels: true,
				},
			},
		}
		flowAggregator.updateFlowAggregator(opt)
		assert.True(t, flowAggregator.includePodLabels)
	})
	t.Run("unsupportedUpdate", func(t *testing.T) {
		flowAggregator := &flowAggregator{}
		var b bytes.Buffer
		klog.SetOutput(&b)
		klog.LogToStderr(false)
		defer func() {
			klog.SetOutput(os.Stderr)
			klog.LogToStderr(true)
		}()
		opt := &options.Options{
			ActiveFlowRecordTimeout: 30 * time.Second,
			Config:                  &flowaggregatorconfig.FlowAggregatorConfig{},
		}
		flowAggregator.updateFlowAggregator(opt)
		assert.Contains(t, b.String(), "Ignoring unsupported configuration updates, please restart FlowAggregator\" keys=[\"activeFlowRecordTimeout\"]")
	})
}

func TestFlowAggregator_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockPodStore := podstoretest.NewMockInterface(ctrl)
	mockIPFIXExporter, mockClickHouseExporter, mockS3Exporter, mockLogExporter := mockExporters(t, ctrl, nil)
	mockCollectingProcess := ipfixtesting.NewMockIPFIXCollectingProcess(ctrl)
	mockAggregationProcess := ipfixtesting.NewMockIPFIXAggregationProcess(ctrl)

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
		// must be large enough to avoid a call to ForAllExpiredFlowRecordsDo
		activeFlowRecordTimeout: 1 * time.Hour,
		logTickerDuration:       1 * time.Hour,
		collectingProcess:       mockCollectingProcess,
		preprocessor:            &preprocessor{},
		aggregationProcess:      mockAggregationProcess,
		ipfixExporter:           mockIPFIXExporter,
		configWatcher:           configWatcher,
		updateCh:                updateCh,
		podStore:                mockPodStore,
	}

	mockCollectingProcess.EXPECT().Start()
	mockCollectingProcess.EXPECT().Stop()
	mockAggregationProcess.EXPECT().Start()
	mockAggregationProcess.EXPECT().Stop()
	mockPodStore.EXPECT().Run(gomock.Any())

	// Mock expectations determined by sequence of updateOptions operations below.
	mockIPFIXExporter.EXPECT().Start().Times(2)
	mockIPFIXExporter.EXPECT().Stop().Times(2)
	mockClickHouseExporter.EXPECT().Start()
	mockClickHouseExporter.EXPECT().Stop()
	mockS3Exporter.EXPECT().Start()
	mockS3Exporter.EXPECT().Stop()
	mockLogExporter.EXPECT().Start()
	mockLogExporter.EXPECT().Stop()

	// this is not really relevant; but in practice there will be one call
	// to mockClickHouseExporter.UpdateOptions because of the hack used to
	// implement updateOptions above.
	mockIPFIXExporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()
	mockClickHouseExporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()
	mockS3Exporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()
	mockLogExporter.EXPECT().UpdateOptions(gomock.Any()).AnyTimes()

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flowAggregator.Run(stopCh)
	}()

	makeOptions := func(config *flowaggregatorconfig.FlowAggregatorConfig) *options.Options {
		return &options.Options{
			ActiveFlowRecordTimeout: flowAggregator.activeFlowRecordTimeout,
			Config:                  config,
		}
	}

	disableIPFIXOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
			Enable: false,
		},
	})
	enableIPFIXOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
			Enable: true,
		},
	})
	enableClickHouseOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		ClickHouse: flowaggregatorconfig.ClickHouseConfig{
			Enable: true,
		},
	})
	disableClickHouseOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		ClickHouse: flowaggregatorconfig.ClickHouseConfig{
			Enable: false,
		},
	})
	enableS3UploaderOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		S3Uploader: flowaggregatorconfig.S3UploaderConfig{
			Enable: true,
		},
	})
	disableS3UploaderOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		S3Uploader: flowaggregatorconfig.S3UploaderConfig{
			Enable: false,
		},
	})
	enableFlowLoggerOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
			Enable: true,
		},
	})
	disableFlowLoggerOptions := makeOptions(&flowaggregatorconfig.FlowAggregatorConfig{
		FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
			Enable: false,
		},
	})

	// we do a few operations: the main purpose is to ensure that cleanup
	// (i.e., stopping the exporters) is done properly.
	// 1. The IPFIXExporter is enabled on start, so we expect a call to mockIPFIXExporter.Start()
	// 2. The IPFIXExporter is then disabled, so we expect a call to mockIPFIXExporter.Stop()
	// 3. The ClickHouseExporter is then enabled, so we expect a call to mockClickHouseExporter.Start()
	// 4. The ClickHouseExporter is then disabled, so we expect a call to mockClickHouseExporter.Stop()
	// 5. The S3Uploader is then enabled, so we expect a call to mockS3Exporter.Start()
	// 6. The S3Uploader is then disabled, so we expect a call to mockS3Exporter.Stop()
	// 7. The FlowLogger is then enabled, so we expect a call to mockLogExporter.Start()
	// 8. The FlowLogger is then disabled, so we expect a call to mockLogExporter.Stop()
	// 9. The IPFIXExporter is then re-enabled, so we expect a second call to mockIPFIXExporter.Start()
	// 10. Finally, when Run() is stopped, we expect a second call to mockIPFIXExporter.Stop()
	updateOptions(disableIPFIXOptions)
	updateOptions(enableClickHouseOptions)
	updateOptions(disableClickHouseOptions)
	updateOptions(enableS3UploaderOptions)
	updateOptions(disableS3UploaderOptions)
	updateOptions(enableFlowLoggerOptions)
	updateOptions(disableFlowLoggerOptions)
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

func TestFlowAggregator_fetchPodLabels(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		pod  *v1.Pod
		want string
	}{
		{
			name: "no pod object",
			ip:   "192.168.1.2",
			pod:  nil,
			want: "",
		},
		{
			name: "pod with label",
			ip:   "192.168.1.2",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "testPod",
					Labels: map[string]string{
						"test": "ut",
					},
				},
			},
			want: "{\"test\":\"ut\"}",
		},
		{
			name: "pod with empty labels",
			ip:   "192.168.1.2",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "testPod",
					Labels:    map[string]string{},
				},
			},
			want: "{}",
		},
		{
			name: "pod with null labels",
			ip:   "192.168.1.2",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "testPod",
					Labels:    nil,
				},
			},
			want: "{}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := fake.NewSimpleClientset()
			mockPodStore := podstoretest.NewMockInterface(ctrl)
			mockPodStore.EXPECT().GetPodByIPAndTime(tt.ip, gomock.Any()).Return(tt.pod, tt.pod != nil)
			fa := &flowAggregator{
				k8sClient:        client,
				includePodLabels: true,
				podStore:         mockPodStore,
			}
			got := fa.fetchPodLabels(tt.ip, time.Now())
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFlowAggregator_GetRecordMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCollectingProcess := ipfixtesting.NewMockIPFIXCollectingProcess(ctrl)
	mockAggregationProcess := ipfixtesting.NewMockIPFIXAggregationProcess(ctrl)
	mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
	mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
	mockS3Exporter := exportertesting.NewMockInterface(ctrl)
	mockLogExporter := exportertesting.NewMockInterface(ctrl)
	want := querier.Metrics{
		NumRecordsExported:     1,
		NumRecordsReceived:     1,
		NumFlows:               1,
		NumConnToCollector:     1,
		WithClickHouseExporter: true,
		WithS3Exporter:         true,
		WithLogExporter:        true,
		WithIPFIXExporter:      true,
	}

	fa := &flowAggregator{
		collectingProcess:  mockCollectingProcess,
		aggregationProcess: mockAggregationProcess,
		numRecordsExported: 1,
		clickHouseExporter: mockClickHouseExporter,
		s3Exporter:         mockS3Exporter,
		logExporter:        mockLogExporter,
		ipfixExporter:      mockIPFIXExporter,
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
		registry:                    ipfix.NewIPFIXRegistry(),
	}
	require.NoError(t, fa.InitCollectingProcess())
	recordCh := make(chan ipfixentities.Record)
	require.NoError(t, fa.InitPreprocessor(recordCh))
	require.NoError(t, fa.InitAggregationProcess(recordCh))
}

func TestFlowAggregator_fillK8sMetadata(t *testing.T) {
	srcPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "sourcePod",
			UID:       "sourcePod",
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
			UID:       "destinationPod",
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
	sourcePodNameElem := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("sourcePodName", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0), "")
	sourcePodNamespaceElem := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("sourcePodNamespace", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0), "")
	sourceNodeNameElem := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("sourceNodeName", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0), "")
	destinationPodNameElem := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("destinationPodName", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0), "")
	destinationPodNamespaceElem := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("destinationPodNamespace", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0), "")
	destinationNodeNameElem := ipfixentities.NewStringInfoElement(ipfixentities.NewInfoElement("destinationNodeName", 0, ipfixentities.String, ipfixregistry.AntreaEnterpriseID, 0), "")

	ctrl := gomock.NewController(t)
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	mockPodStore := podstoretest.NewMockInterface(ctrl)

	stopCh := make(chan struct{})
	defer close(stopCh)

	ipv4Key := ipfixintermediate.FlowKey{
		SourceAddress:      "192.168.1.2",
		DestinationAddress: "192.168.1.3",
	}

	fa := &flowAggregator{
		podStore: mockPodStore,
	}

	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodName").Return(sourcePodNameElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("sourcePodNamespace").Return(sourcePodNamespaceElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("sourceNodeName").Return(sourceNodeNameElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodName").Return(destinationPodNameElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("destinationPodNamespace").Return(destinationPodNamespaceElem, 0, true)
	mockRecord.EXPECT().GetInfoElementWithValue("destinationNodeName").Return(destinationNodeNameElem, 0, true)
	mockPodStore.EXPECT().GetPodByIPAndTime("192.168.1.2", gomock.Any()).Return(srcPod, true)
	mockPodStore.EXPECT().GetPodByIPAndTime("192.168.1.3", gomock.Any()).Return(dstPod, true)

	fa.fillK8sMetadata(ipv4Key, mockRecord, time.Now())
}

func TestNewFlowAggregator(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := fake.NewSimpleClientset()
	mockPodStore := podstoretest.NewMockInterface(ctrl)
	wd, err := os.Getwd()
	require.NoError(t, err)
	// fsnotify does not seem to work when using the default tempdir on MacOS, which is why we
	// use the current working directory.
	f, err := os.CreateTemp(wd, "test_*.config")
	require.NoError(t, err, "Failed to create test config file")
	fileName := f.Name()
	defer os.Remove(fileName)

	clusterUUID := uuid.New()
	// This will validate that the correct UUID is provided by the FlowAggregator when
	// instantiating exporters.
	mockExporters(t, ctrl, &clusterUUID)

	config := &flowaggregatorconfig.FlowAggregatorConfig{
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
		FlowLogger: flowaggregatorconfig.FlowLoggerConfig{
			Enable: true,
			Path:   "/tmp/antrea-flows.log",
		},
	}
	b, err := yaml.Marshal(config)
	require.NoError(t, err)
	_, err = f.Write(b)
	require.NoError(t, err)
	fa, err := NewFlowAggregator(client, clusterUUID, mockPodStore, fileName)
	require.NoError(t, err)
	assert.Equal(t, clusterUUID, fa.clusterUUID)
}
