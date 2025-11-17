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

package flowexporter

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/openflow"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/channel"
	utilwait "antrea.io/antrea/pkg/util/wait"
)

func TestFlowExporter_createExporter(t *testing.T) {
	tests := []struct {
		name     string
		protocol exporterProtocol
		want     exporter.Interface
	}{
		{
			name:     "gRPC protocol",
			protocol: &api.FlowExporterGRPCConfig{},
			want:     exporter.NewGRPCExporter("", "", 0),
		}, {
			name:     "ipfix protocol",
			protocol: &api.FlowExporterIPFIXConfig{},
			want:     exporter.NewIPFIXExporter("", "", 0, false, false),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &FlowExporter{}
			exp := fe.createExporter(tt.protocol)
			assert.IsType(t, tt.want, exp)
		})
	}
}

func Test_createDestinationResFromOptions(t *testing.T) {
	tests := []struct {
		name string
		o    *options.FlowExporterOptions
		want *api.FlowExporterDestination
	}{
		{
			name: "static destination not enabled",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: false,
			},
			want: nil,
		}, {
			name: "address is namespace/name - tcp",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: true,
				FlowCollectorAddr:       "ns1/svc1:5678",
				FlowCollectorProto:      "tcp",
				ActiveFlowTimeout:       5 * time.Second,
				IdleFlowTimeout:         2 * time.Second,
				ProtocolFilter:          []string{"udp"},
			},
			want: &api.FlowExporterDestination{
				Spec: api.FlowExporterDestinationSpec{
					Address: "ns1/svc1:5678",
					Protocol: api.FlowExporterProtocol{
						IPFIX: &api.FlowExporterIPFIXConfig{
							Transport: api.FlowExporterTransportTCP,
						},
					},
					Filter: &api.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 5,
					IdleFlowExportTimeoutSeconds:   2,
					TLSConfig:                      nil,
				},
			},
		}, {
			name: "address is namespace/name - tls",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: true,
				FlowCollectorAddr:       "ns1/svc1:5678",
				FlowCollectorProto:      "tls",
				ActiveFlowTimeout:       5 * time.Second,
				IdleFlowTimeout:         2 * time.Second,
				ProtocolFilter:          []string{"udp"},
			},
			want: &api.FlowExporterDestination{
				Spec: api.FlowExporterDestinationSpec{
					Address: "ns1/svc1:5678",
					Protocol: api.FlowExporterProtocol{
						IPFIX: &api.FlowExporterIPFIXConfig{
							Transport: api.FlowExporterTransportTLS,
						},
					},
					Filter: &api.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 5,
					IdleFlowExportTimeoutSeconds:   2,
					TLSConfig: &api.FlowExporterTLSConfig{
						ServerName:    "svc1.ns1.svc",
						MinTLSVersion: "",
						CAConfigMap: api.NamespacedName{
							Name:      "flow-aggregator-ca",
							Namespace: "flow-aggregator",
						},
						ClientSecret: &api.NamespacedName{
							Name:      "flow-aggregator-client-tls",
							Namespace: "flow-aggregator",
						},
					},
				},
			},
		}, {
			name: "address is ip - udp",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: true,
				FlowCollectorAddr:       "1.2.3.4:5432",
				FlowCollectorProto:      "udp",
				ActiveFlowTimeout:       5 * time.Second,
				IdleFlowTimeout:         2 * time.Second,
				ProtocolFilter:          []string{"udp"},
			},
			want: &api.FlowExporterDestination{
				Spec: api.FlowExporterDestinationSpec{
					Address: "1.2.3.4:5432",
					Protocol: api.FlowExporterProtocol{
						IPFIX: &api.FlowExporterIPFIXConfig{
							Transport: api.FlowExporterTransportUDP,
						},
					},
					Filter: &api.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 5,
					IdleFlowExportTimeoutSeconds:   2,
					TLSConfig:                      nil,
				},
			},
		}, {
			name: "address is dns - grpc",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: true,
				FlowCollectorAddr:       "foo.example.com:5678",
				FlowCollectorProto:      "grpc",
				ActiveFlowTimeout:       5 * time.Second,
				IdleFlowTimeout:         2 * time.Second,
				ProtocolFilter:          []string{"udp"},
			},
			want: &api.FlowExporterDestination{
				Spec: api.FlowExporterDestinationSpec{
					Address: "foo.example.com:5678",
					Protocol: api.FlowExporterProtocol{
						GRPC: &api.FlowExporterGRPCConfig{},
					},
					Filter: &api.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 5,
					IdleFlowExportTimeoutSeconds:   2,
					TLSConfig: &api.FlowExporterTLSConfig{
						ServerName:    "",
						MinTLSVersion: "",
						CAConfigMap: api.NamespacedName{
							Name:      "flow-aggregator-ca",
							Namespace: "flow-aggregator",
						},
						ClientSecret: &api.NamespacedName{
							Name:      "flow-aggregator-client-tls",
							Namespace: "flow-aggregator",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, err := createStaticDestinationResFromOptions(tt.o)
			require.NoError(t, err)
			assert.Equal(t, tt.want, dest)
		})
	}
}

func TestFlowExporter_createDestinationFromResource(t *testing.T) {
	tests := []struct {
		name string
		res  *api.FlowExporterDestination
		want *Destination
	}{
		{
			name: "populates config",
			res: &api.FlowExporterDestination{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "dest1",
				},
				Spec: api.FlowExporterDestinationSpec{
					Address: "12.23.34.45:9876",
					Protocol: api.FlowExporterProtocol{
						GRPC: &api.FlowExporterGRPCConfig{},
					},
					Filter:                         &api.FlowExporterFilter{Protocols: []string{"udp"}},
					ActiveFlowExportTimeoutSeconds: 4,
					IdleFlowExportTimeoutSeconds:   6,
					TLSConfig: &api.FlowExporterTLSConfig{
						ServerName:    "foo.example.com",
						MinTLSVersion: "",
						CAConfigMap:   api.NamespacedName{Name: "ca1", Namespace: "ns2"},
						ClientSecret:  &api.NamespacedName{Name: "client1", Namespace: "client2"},
					},
				},
			},
			want: &Destination{
				DestinationConfig: DestinationConfig{
					name:              "dest1",
					address:           "12.23.34.45:9876",
					activeFlowTimeout: 4 * time.Second,
					idleFlowTimeout:   6 * time.Second,
					tlsConfig: &api.FlowExporterTLSConfig{
						ServerName:   "foo.example.com",
						CAConfigMap:  api.NamespacedName{Name: "ca1", Namespace: "ns2"},
						ClientSecret: &api.NamespacedName{Name: "client1", Namespace: "client2"},
					},
					allowProtocolFilter: []string{"udp"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &FlowExporter{}
			got, err := fe.createDestinationFromResource(tt.res)
			require.NoError(t, err)
			assert.Equal(t, tt.want.DestinationConfig, got.DestinationConfig)
		})
	}
}

func TestFlowExporter_syncFlowExporterDestination(t *testing.T) {
	destination := &api.FlowExporterDestination{
		ObjectMeta: metav1.ObjectMeta{Name: "dest1"},
		Spec: api.FlowExporterDestinationSpec{
			ActiveFlowExportTimeoutSeconds: int32(testActiveFlowTimeout.Seconds()),
			IdleFlowExportTimeoutSeconds:   int32(testIdleFlowTimeout.Seconds()),
		},
	}

	tests := []struct {
		name                  string
		key                   string
		hasExistingDest       bool
		expectNumDestinations int
	}{
		{
			name:            "attempt to remove old destination",
			key:             "foo",
			hasExistingDest: true,
		}, {
			name:                  "new resource",
			key:                   "dest1",
			expectNumDestinations: 1,
		}, {
			name:                  "updated resource",
			key:                   "dest1",
			hasExistingDest:       true,
			expectNumDestinations: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSubChannel := channel.NewSubscribableChannel("Test Connections", 5)

			crdClient := fakeversioned.NewSimpleClientset(destination)
			informerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
			destInformer := informerFactory.Crd().V1alpha1().FlowExporterDestinations()

			stopCh := make(chan struct{})
			defer close(stopCh)

			exp := &FlowExporter{
				destinations:          map[string]destinationObj{},
				destinationInformer:   destInformer,
				destinationLister:     destInformer.Lister(),
				destinationSynced:     destInformer.Informer().HasSynced,
				ctConnUpdateChannel:   testSubChannel,
				denyConnUpdateChannel: testSubChannel,
			}
			informerFactory.Start(t.Context().Done())
			informerFactory.WaitForCacheSync(t.Context().Done())

			if tt.hasExistingDest {
				exp.destinations[tt.key] = destinationObj{
					stopCh: make(chan struct{}),
				}
			}

			err := exp.syncFlowExporterDestination(tt.key)
			require.NoError(t, err)
			assert.Len(t, exp.destinations, tt.expectNumDestinations)
		})
	}
}

func TestFlowExporter_deleteDestination(t *testing.T) {
	name := "res1"
	tests := []struct {
		name string
		obj  any
	}{
		{
			name: "is exact type",
			obj: &api.FlowExporterDestination{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
			},
		}, {
			name: "is in deletion state",
			obj: cache.DeletedFinalStateUnknown{
				Obj: &api.FlowExporterDestination{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &FlowExporter{
				queue: workqueue.NewTypedRateLimitingQueue(workqueue.NewTypedItemExponentialFailureRateLimiter[string](0, 0)),
			}
			fe.deleteDestination(tt.obj)
			item, _ := fe.queue.Get()
			assert.Equal(t, name, item)
		})
	}
}

func TestFlowExporter_updateDestination(t *testing.T) {
	meta := metav1.ObjectMeta{
		Name: "res1",
	}
	tests := []struct {
		name        string
		old         *api.FlowExporterDestination
		new         *api.FlowExporterDestination
		shouldQueue bool
	}{
		{
			name: "spec match",
			old: &api.FlowExporterDestination{
				ObjectMeta: meta,
				Spec: api.FlowExporterDestinationSpec{
					Address: "foo:80",
				},
			},
			new: &api.FlowExporterDestination{
				ObjectMeta: meta,
				Spec: api.FlowExporterDestinationSpec{
					Address: "foo:80",
				},
			},
		}, {
			name: "spec differ",
			old: &api.FlowExporterDestination{
				ObjectMeta: meta,
				Spec: api.FlowExporterDestinationSpec{
					Address: "foo:80",
				},
			},
			new: &api.FlowExporterDestination{
				ObjectMeta: meta,
				Spec: api.FlowExporterDestinationSpec{
					Address: "baz:9000",
				},
			},
			shouldQueue: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &FlowExporter{
				queue: workqueue.NewTypedRateLimitingQueue(workqueue.NewTypedItemExponentialFailureRateLimiter[string](0, 0)),
			}
			fe.updateDestination(tt.old, tt.new)
			if tt.shouldQueue {
				require.Equal(t, 1, fe.queue.Len())
				item, _ := fe.queue.Get()
				assert.Equal(t, meta.Name, item)
			} else {
				require.Equal(t, 0, fe.queue.Len())
			}
		})
	}
}

func TestFlowExporter_networkPolicyWait(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)

	networkPolicyWait := utilwait.NewGroup()
	networkPolicyWait.Increment()

	crdClient := fakeversioned.NewSimpleClientset()
	informerFactory := crdinformers.NewSharedInformerFactory(crdClient, 100*time.Millisecond)
	destInformer := informerFactory.Crd().V1alpha1().FlowExporterDestinations()

	testSubChannel := channel.NewSubscribableChannel("Test Connections", 5)

	fe := &FlowExporter{
		destinationInformer:   destInformer,
		destinationLister:     destInformer.Lister(),
		destinationSynced:     destInformer.Informer().HasSynced,
		networkPolicyWait:     networkPolicyWait,
		queue:                 workqueue.NewTypedRateLimitingQueue(workqueue.NewTypedItemExponentialFailureRateLimiter[string](0, 0)),
		poller:                connections.NewPoller(mockConnDumper, testSubChannel, 100*time.Millisecond, true, false, false),
		ctConnUpdateChannel:   testSubChannel,
		denyConnUpdateChannel: testSubChannel,
	}

	informerFactory.Start(t.Context().Done())
	informerFactory.WaitForCacheSync(t.Context().Done())

	// Create a signal channel that will be closed on the first DumpFlows call
	firstPollDoneCh := make(chan struct{})

	// Set up mock expectations - close signal channel on first DumpFlows call, then return normally
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).DoAndReturn(func(uint16) ([]*connection.Connection, int, error) {
		defer close(firstPollDoneCh)
		return []*connection.Connection{}, 0, nil
	}).Times(1)
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return([]*connection.Connection{}, 0, nil).AnyTimes()
	mockConnDumper.EXPECT().GetMaxConnections().Return(0, nil).AnyTimes()

	// Record the time before starting Run
	beforeRunTime := time.Now()

	// Verify that networkPolicyReadyTime is initially zero
	require.Zero(t, fe.networkPolicyReadyTime)

	// Start the connection store in a goroutine
	stopCh := make(chan struct{})
	closeStopCh := sync.OnceFunc(func() { close(stopCh) })
	defer closeStopCh()
	runFinishedCh := make(chan struct{})
	go func() {
		defer close(runFinishedCh)
		fe.Run(stopCh)
	}()

	// Signal that NetworkPolicies are ready
	networkPolicyWait.Done()

	// Wait for the first poll to happen (which means Run has proceeded past the wait)
	select {
	case <-firstPollDoneCh:
	// Expected: Run has started polling
	case <-time.After(1 * time.Second):
		require.Fail(t, "Run should have started polling within 1 second")
	}

	// Stop the connection store
	closeStopCh()

	// Wait for Run to finish
	select {
	case <-runFinishedCh:
		// Expected: Run finished cleanly
	case <-time.After(1 * time.Second):
		require.Fail(t, "Run should have finished within 1 second after stopCh was closed")
	}

	// Verify that networkPolicyReadyTime has been set and is after we started the test
	require.NotZero(t, fe.networkPolicyReadyTime)
	assert.True(t, fe.networkPolicyReadyTime.After(beforeRunTime))
}
