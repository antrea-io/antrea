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
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/testing/protocmp"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/certificate"
	certificatetesting "antrea.io/antrea/pkg/flowaggregator/certificate/testing"
	collectortesting "antrea.io/antrea/pkg/flowaggregator/collector/testing"
	"antrea.io/antrea/pkg/flowaggregator/exporter"
	exportertesting "antrea.io/antrea/pkg/flowaggregator/exporter/testing"
	"antrea.io/antrea/pkg/flowaggregator/intermediate"
	intermediatetesting "antrea.io/antrea/pkg/flowaggregator/intermediate/testing"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
	ipfixtesting "antrea.io/antrea/pkg/ipfix/testing"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"
)

const (
	testActiveTimeout     = 60 * time.Second
	testInactiveTimeout   = 180 * time.Second
	informerDefaultResync = 12 * time.Hour
)

func TestFlowAggregator_sendAggregatedRecord(t *testing.T) {
	ipv4Key := intermediate.FlowKey{
		SourceAddress:      "10.0.0.1",
		DestinationAddress: "10.0.0.2",
		Protocol:           6,
		SourcePort:         1234,
		DestinationPort:    5678,
	}
	ipv6Key := intermediate.FlowKey{
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
		flowKey          intermediate.FlowKey
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
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
			mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
			mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)
			mockAggregationProcess := intermediatetesting.NewMockAggregationProcess(ctrl)

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
					podStore:                    mockPodStore,
				}
			}

			mockExporters := []*exportertesting.MockInterface{mockIPFIXExporter, mockClickHouseExporter}

			startTime := time.Now().UTC().Truncate(time.Second)
			record := &flowpb.Flow{
				StartTs:   timestamppb.New(startTime),
				EndTs:     &timestamppb.Timestamp{},
				Ip:        &flowpb.IP{},
				Transport: &flowpb.Transport{},
				K8S: &flowpb.Kubernetes{
					SourcePodNamespace:      "default",
					SourcePodName:           "podA",
					DestinationPodNamespace: "default",
					DestinationPodName:      "podB",
				},
				Stats:        &flowpb.Stats{},
				ReverseStats: &flowpb.Stats{},
				App:          &flowpb.App{},
			}
			flowRecord := &intermediate.AggregationFlowRecord{
				Record:      record,
				ReadyToSend: true,
			}

			fa := newFlowAggregator(tc.includePodLabels)
			for _, exporter := range mockExporters {
				exporter.EXPECT().AddRecord(record, tc.isIPv6)
			}

			mockAggregationProcess.EXPECT().ResetStatAndThroughputElementsInRecord(record).Return(nil)
			mockAggregationProcess.EXPECT().AreCorrelatedFieldsFilled(*flowRecord).Return(false)
			mockAggregationProcess.EXPECT().SetCorrelatedFieldsFilled(flowRecord, true)
			mockAggregationProcess.EXPECT().AreExternalFieldsFilled(*flowRecord).Return(false)
			if tc.includePodLabels {
				mockPodStore.EXPECT().GetPodByIPAndTime(tc.flowKey.SourceAddress, startTime).Return(podA, true)
				mockPodStore.EXPECT().GetPodByIPAndTime(tc.flowKey.DestinationAddress, startTime).Return(podB, true)
			}
			mockAggregationProcess.EXPECT().SetExternalFieldsFilled(flowRecord, true)
			mockAggregationProcess.EXPECT().IsAggregatedRecordIPv4(*flowRecord).Return(!tc.isIPv6)

			err := fa.sendAggregatedRecord(tc.flowKey, flowRecord)
			assert.NoError(t, err, "Error when sending flow key record, key: %v, record: %v", tc.flowKey, flowRecord)
			if tc.includePodLabels {
				assert.NotNil(t, record.K8S.SourcePodLabels)
				assert.NotNil(t, record.K8S.DestinationPodLabels)
			}
		})
	}
}

func TestFlowAggregator_proxyRecord(t *testing.T) {
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

	const sourceAddressIPv4 = "10.0.0.1"
	const destinationAddressIPv4 = "10.0.0.2"
	const sourceAddressIPv6 = "2001:0:3238:dfe1:63::fefb"
	const destinationAddressIPv6 = "2001:0:3238:dfe1:63::fefc"

	testcases := []struct {
		name             string
		isIPv6           bool
		includePodLabels bool
	}{
		{
			"IPv4_with_pod_labels",
			false,
			true,
		},
		{
			"IPv6_with_pod_labels",
			true,
			true,
		},
		{
			"IPv4_without_pod_labels",
			false,
			false,
		},
		{
			"IPv6_without_pod_labels",
			true,
			false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
			mockIPFIXRegistry := ipfixtesting.NewMockIPFIXRegistry(ctrl)

			newFlowAggregator := func(includePodLabels bool) *flowAggregator {
				return &flowAggregator{
					aggregatorMode:              flowaggregatorconfig.AggregatorModeProxy,
					aggregatorTransportProtocol: "tcp",
					activeFlowRecordTimeout:     testActiveTimeout,
					inactiveFlowRecordTimeout:   testInactiveTimeout,
					ipfixExporter:               mockIPFIXExporter,
					registry:                    mockIPFIXRegistry,
					flowAggregatorAddress:       "",
					includePodLabels:            includePodLabels,
					podStore:                    mockPodStore,
				}
			}

			fa := newFlowAggregator(tc.includePodLabels)

			startTime := time.Now().UTC().Truncate(time.Second)
			record := &flowpb.Flow{
				StartTs:   timestamppb.New(startTime),
				EndTs:     &timestamppb.Timestamp{},
				Ip:        &flowpb.IP{},
				Transport: &flowpb.Transport{},
				K8S: &flowpb.Kubernetes{
					FlowType:                flowpb.FlowType_FLOW_TYPE_INTER_NODE,
					SourcePodNamespace:      "default",
					SourcePodName:           "podA",
					DestinationPodNamespace: "default",
					DestinationPodName:      "podB",
				},
				Stats:        &flowpb.Stats{},
				ReverseStats: &flowpb.Stats{},
				App:          &flowpb.App{},
			}

			mockIPFIXExporter.EXPECT().AddRecord(record, tc.isIPv6)

			var sourceAddress, destinationAddress string
			if tc.isIPv6 {
				record.Ip.Version = flowpb.IPVersion_IP_VERSION_6
				sourceAddress = sourceAddressIPv6
				destinationAddress = destinationAddressIPv6
			} else {
				record.Ip.Version = flowpb.IPVersion_IP_VERSION_4
				sourceAddress = sourceAddressIPv4
				destinationAddress = destinationAddressIPv4
			}
			record.Ip.Source = netip.MustParseAddr(sourceAddress).AsSlice()
			record.Ip.Destination = netip.MustParseAddr(destinationAddress).AsSlice()

			if tc.includePodLabels {
				mockPodStore.EXPECT().GetPodByIPAndTime(sourceAddress, startTime).Return(podA, true)
				mockPodStore.EXPECT().GetPodByIPAndTime(destinationAddress, startTime).Return(podB, true)
			}

			err := fa.proxyRecord(record)
			assert.NoError(t, err, "Error when proxying flow record")
			if tc.includePodLabels {
				assert.NotNil(t, record.K8S.SourcePodLabels)
				assert.NotNil(t, record.K8S.DestinationPodLabels)
			}
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
// the FlowAggregator when instantiating an exporter, if applicable. Same for clusterID for the
// IPFIX exporter.
func mockExporters(t *testing.T, ctrl *gomock.Controller, expectedClusterUUID *uuid.UUID, expectedClusterID *string) (
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
	newIPFIXExporter = func(clusterUUID uuid.UUID, clusterID string, opts *options.Options, registry ipfix.IPFIXRegistry) exporter.Interface {
		if expectedClusterUUID != nil {
			assert.Equal(t, *expectedClusterUUID, clusterUUID)
		}
		if expectedClusterID != nil {
			assert.Equal(t, *expectedClusterID, clusterID)
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

	mockIPFIXExporter, mockClickHouseExporter, mockS3Exporter, mockLogExporter := mockExporters(t, ctrl, nil, nil)

	t.Run("updateIPFIX", func(t *testing.T) {
		flowAggregator := &flowAggregator{
			ipfixExporter: mockIPFIXExporter,
		}
		opt := &options.Options{
			Config: &flowaggregatorconfig.FlowAggregatorConfig{
				FlowCollector: flowaggregatorconfig.FlowCollectorConfig{
					Enable:         true,
					Address:        "10.10.10.10:155",
					IncludeK8sUIDs: ptr.To(true),
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
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)
	mockPodStore.EXPECT().HasSynced().Return(true)
	mockNodeStore := objectstoretest.NewMockNodeStore(ctrl)
	mockNodeStore.EXPECT().HasSynced().Return(true)
	mockServiceStore := objectstoretest.NewMockServiceStore(ctrl)
	mockServiceStore.EXPECT().HasSynced().Return(true)
	mockIPFIXExporter, mockClickHouseExporter, mockS3Exporter, mockLogExporter := mockExporters(t, ctrl, nil, nil)
	mockCollector := collectortesting.NewMockInterface(ctrl)
	mockAggregationProcess := intermediatetesting.NewMockAggregationProcess(ctrl)
	mockCertificateProvider := certificatetesting.NewMockProvider(ctrl)

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
		aggregatorMode: flowaggregatorconfig.AggregatorModeAggregate,
		// must be large enough to avoid a call to ForAllExpiredFlowRecordsDo
		activeFlowRecordTimeout: 1 * time.Hour,
		logTickerDuration:       1 * time.Hour,
		grpcCollector:           mockCollector,
		aggregationProcess:      mockAggregationProcess,
		ipfixExporter:           mockIPFIXExporter,
		configWatcher:           configWatcher,
		updateCh:                updateCh,
		podStore:                mockPodStore,
		nodeStore:               mockNodeStore,
		serviceStore:            mockServiceStore,
		certificateProvider:     mockCertificateProvider,
	}

	mockCertificateProvider.EXPECT().Run(gomock.Any())
	mockCertificateProvider.EXPECT().HasSynced().Return(true)
	mockCollector.EXPECT().Run(gomock.Any())
	mockAggregationProcess.EXPECT().Start()
	mockAggregationProcess.EXPECT().Stop()

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
			AggregatorMode:          flowAggregator.aggregatorMode,
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
			Enable:         true,
			IncludeK8sUIDs: ptr.To(false),
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
		want *flowpb.Labels
	}{
		{
			name: "no pod object",
			ip:   "192.168.1.2",
			pod:  nil,
			want: nil,
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
			want: &flowpb.Labels{
				Labels: map[string]string{
					"test": "ut",
				},
			},
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
			want: &flowpb.Labels{},
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
			want: &flowpb.Labels{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := fake.NewSimpleClientset()
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockPodStore.EXPECT().GetPodByIPAndTime(tt.ip, gomock.Any()).Return(tt.pod, tt.pod != nil)
			fa := &flowAggregator{
				k8sClient:        client,
				includePodLabels: true,
				podStore:         mockPodStore,
			}
			got := fa.fetchPodLabels(tt.ip, time.Now())
			assert.Empty(t, cmp.Diff(tt.want, got, protocmp.Transform()))
		})
	}
}

func TestFlowAggregator_GetRecordMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCollector := collectortesting.NewMockInterface(ctrl)
	mockAggregationProcess := intermediatetesting.NewMockAggregationProcess(ctrl)
	mockIPFIXExporter := exportertesting.NewMockInterface(ctrl)
	mockClickHouseExporter := exportertesting.NewMockInterface(ctrl)
	mockS3Exporter := exportertesting.NewMockInterface(ctrl)
	mockLogExporter := exportertesting.NewMockInterface(ctrl)
	want := querier.Metrics{
		NumRecordsExported:     10,
		NumRecordsReceived:     1,
		NumRecordsDropped:      1,
		NumFlows:               1,
		NumConnToCollector:     1,
		WithClickHouseExporter: true,
		WithS3Exporter:         true,
		WithLogExporter:        true,
		WithIPFIXExporter:      true,
	}

	fa := &flowAggregator{
		grpcCollector:      mockCollector,
		aggregationProcess: mockAggregationProcess,
		clickHouseExporter: mockClickHouseExporter,
		s3Exporter:         mockS3Exporter,
		logExporter:        mockLogExporter,
		ipfixExporter:      mockIPFIXExporter,
	}
	fa.numRecordsExported.Store(10)
	fa.numRecordsDropped.Store(1)

	mockCollector.EXPECT().GetNumRecordsReceived().Return(int64(1))
	mockAggregationProcess.EXPECT().GetNumFlows().Return(int64(1))
	mockCollector.EXPECT().GetNumConnsToCollector().Return(int64(1))

	got := fa.GetRecordMetrics()
	assert.Equal(t, want, got)
}

func TestFlowAggregator_InitCollectors(t *testing.T) {
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
			name:                        "UDP protocol",
			aggregatorTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolUDP,
			k8sClient:                   fake.NewSimpleClientset(),
		},
		{
			name:                        "no IPFIX collector",
			aggregatorTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolNone,
			k8sClient:                   fake.NewSimpleClientset(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockCertificateProvider := certificatetesting.NewMockProvider(ctrl)
			caCert, serverCert, serverKey := generateServerCerts(t)
			mockCertificateProvider.EXPECT().GetServerCertKey().Return(caCert, serverCert, serverKey)

			fa := &flowAggregator{
				aggregatorTransportProtocol: tt.aggregatorTransportProtocol,
				flowAggregatorAddress:       tt.flowAggregatorAddress,
				k8sClient:                   tt.k8sClient,
				certificateProvider:         mockCertificateProvider,
			}
			err := fa.InitCollectors()
			require.NoError(t, err)
			assert.NotNil(t, fa.grpcCollector)
			if tt.aggregatorTransportProtocol == flowaggregatorconfig.AggregatorTransportProtocolNone {
				assert.Nil(t, fa.ipfixCollector)
			} else {
				assert.NotNil(t, fa.ipfixCollector)
			}
			assert.EqualValues(t, 0, fa.getNumRecordsReceived())
			assert.EqualValues(t, 0, fa.getNumConnsToCollector())
		})
	}
}

func TestFlowAggregator_InitAggregationProcess(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCertificateProvider := certificatetesting.NewMockProvider(ctrl)
	caCert, serverCert, serverKey := generateServerCerts(t)
	mockCertificateProvider.EXPECT().GetServerCertKey().Return(caCert, serverCert, serverKey)
	fa := &flowAggregator{
		activeFlowRecordTimeout:     testActiveTimeout,
		inactiveFlowRecordTimeout:   testInactiveTimeout,
		aggregatorTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolNone,
		registry:                    ipfix.NewIPFIXRegistry(),
		recordCh:                    make(chan *flowpb.Flow),
		k8sClient:                   fake.NewSimpleClientset(),
		certificateProvider:         mockCertificateProvider,
	}
	require.NoError(t, fa.InitCollectors())
	require.NoError(t, fa.InitAggregationProcess())
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

	ctrl := gomock.NewController(t)
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)

	sourceAdress := "192.168.1.2"
	destinationAddress := "192.168.1.3"

	fa := &flowAggregator{
		podStore: mockPodStore,
	}

	record := &flowpb.Flow{
		K8S: &flowpb.Kubernetes{},
	}

	mockPodStore.EXPECT().GetPodByIPAndTime("192.168.1.2", gomock.Any()).Return(srcPod, true)
	mockPodStore.EXPECT().GetPodByIPAndTime("192.168.1.3", gomock.Any()).Return(dstPod, true)

	fa.fillK8sMetadata(sourceAdress, destinationAddress, record, time.Now())
	assert.Equal(t, "sourcePod", record.K8S.SourcePodName)
	assert.Equal(t, "default", record.K8S.SourcePodNamespace)
	assert.Equal(t, "sourceNode", record.K8S.SourceNodeName)
	assert.Equal(t, "destinationPod", record.K8S.DestinationPodName)
	assert.Equal(t, "default", record.K8S.DestinationPodNamespace)
	assert.Equal(t, "destinationNode", record.K8S.DestinationNodeName)
}

func TestNewFlowAggregator(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	// fsnotify does not seem to work when using the default tempdir on MacOS, which is why we
	// use the current working directory.
	f, err := os.CreateTemp(wd, "test_*.config")
	require.NoError(t, err, "Failed to create test config file")
	fileName := f.Name()
	defer os.Remove(fileName)

	newFlowAggregatorConfig := func(clusterID string) *flowaggregatorconfig.FlowAggregatorConfig {
		return &flowaggregatorconfig.FlowAggregatorConfig{
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
			ClusterID: clusterID,
		}
	}

	testcases := []struct {
		name   string
		config *flowaggregatorconfig.FlowAggregatorConfig
	}{
		{
			"ClusterID is the UUID by default",
			newFlowAggregatorConfig(""),
		},
		{
			"ClusterID is set by the user",
			newFlowAggregatorConfig("custom-cluster-id"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := fake.NewSimpleClientset()
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockNodeStore := objectstoretest.NewMockNodeStore(ctrl)
			mockServiceStore := objectstoretest.NewMockServiceStore(ctrl)
			mockCertificateProvider := certificatetesting.NewMockProvider(ctrl)

			caCert, serverCert, serverKey := generateServerCerts(t)
			mockCertificateProvider.EXPECT().GetServerCertKey().Return(caCert, serverCert, serverKey)

			oldCertProviderFn := newCertificateProvider
			newCertificateProvider = func(_ kubernetes.Interface, _ string) certificate.Provider {
				return mockCertificateProvider
			}
			t.Cleanup(func() {
				newCertificateProvider = oldCertProviderFn
			})

			clusterUUID := uuid.New()
			clusterID := tc.config.ClusterID
			if clusterID == "" {
				clusterID = clusterUUID.String()
			}
			// This will validate that the correct UUID / ID is provided by the
			// FlowAggregator when instantiating exporters.
			mockExporters(t, ctrl, &clusterUUID, &clusterID)
			b, err := yaml.Marshal(tc.config)
			require.NoError(t, err)
			_, err = f.Write(b)
			require.NoError(t, err)
			fa, err := NewFlowAggregator(client, clusterUUID, mockPodStore, mockNodeStore, mockServiceStore, fileName)
			require.NoError(t, err)
			assert.Equal(t, clusterUUID, fa.clusterUUID)
			assert.Equal(t, clusterID, fa.clusterID)
		})
	}
}

func generateServerCerts(t *testing.T) ([]byte, []byte, []byte) {
	validFrom := time.Now().Add(-time.Hour)
	caCertPEM, caKeyPEM, err := certificate.GenerateCACertKey(validFrom)
	require.NoError(t, err)

	caCertBlock, _ := pem.Decode(caCertPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	require.NoError(t, err)

	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	require.NoError(t, err)

	serverCertPEM, serverKeyPEM, err := certificate.GenerateCertKey(caCert, caKey, validFrom, true, "myaddr")
	require.NoError(t, err)

	return caCertPEM, serverCertPEM, serverKeyPEM
}
