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
	"testing"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func TestFlowExporter_createExporter(t *testing.T) {
	tests := []struct {
		name     string
		protocol exporterProtocol
		want     exporter.Interface
	}{
		{
			name:     "gRPC protocol",
			protocol: &v1alpha1.FlowExporterGRPCConfig{},
			want:     exporter.NewGRPCExporter("", "", 0),
		}, {
			name:     "ipfix protocol",
			protocol: &v1alpha1.FlowExporterIPFIXConfig{},
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
		want *v1alpha1.FlowExporterDestination
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
			want: &v1alpha1.FlowExporterDestination{
				Spec: v1alpha1.FlowExporterDestinationSpec{
					Address: "ns1/svc1:5678",
					Protocol: v1alpha1.FlowExporterProtocol{
						IPFIX: &v1alpha1.FlowExporterIPFIXConfig{
							Transport: v1alpha1.FlowExporterTransportTCP,
						},
					},
					Filter: &v1alpha1.FlowExporterFilter{
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
			want: &v1alpha1.FlowExporterDestination{
				Spec: v1alpha1.FlowExporterDestinationSpec{
					Address: "ns1/svc1:5678",
					Protocol: v1alpha1.FlowExporterProtocol{
						IPFIX: &v1alpha1.FlowExporterIPFIXConfig{
							Transport: v1alpha1.FlowExporterTransportTLS,
						},
					},
					Filter: &v1alpha1.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 5,
					IdleFlowExportTimeoutSeconds:   2,
					TLSConfig: &v1alpha1.FlowExporterTLSConfig{
						ServerName:    "svc1.ns1.svc",
						MinTLSVersion: "",
						CAConfigMap: v1alpha1.NamespacedName{
							Name:      "flow-aggregator-ca",
							Namespace: "flow-aggregator",
						},
						ClientSecret: &v1alpha1.NamespacedName{
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
			want: &v1alpha1.FlowExporterDestination{
				Spec: v1alpha1.FlowExporterDestinationSpec{
					Address: "1.2.3.4:5432",
					Protocol: v1alpha1.FlowExporterProtocol{
						IPFIX: &v1alpha1.FlowExporterIPFIXConfig{
							Transport: v1alpha1.FlowExporterTransportUDP,
						},
					},
					Filter: &v1alpha1.FlowExporterFilter{
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
			want: &v1alpha1.FlowExporterDestination{
				Spec: v1alpha1.FlowExporterDestinationSpec{
					Address: "foo.example.com:5678",
					Protocol: v1alpha1.FlowExporterProtocol{
						GRPC: &v1alpha1.FlowExporterGRPCConfig{},
					},
					Filter: &v1alpha1.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 5,
					IdleFlowExportTimeoutSeconds:   2,
					TLSConfig: &v1alpha1.FlowExporterTLSConfig{
						ServerName:    "",
						MinTLSVersion: "",
						CAConfigMap: v1alpha1.NamespacedName{
							Name:      "flow-aggregator-ca",
							Namespace: "flow-aggregator",
						},
						ClientSecret: &v1alpha1.NamespacedName{
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
			dest, err := createDestinationResFromOptions(tt.o)
			require.NoError(t, err)
			assert.Equal(t, tt.want, dest)
		})
	}
}

func TestFlowExporter_createDestinationFromResource(t *testing.T) {
	tests := []struct {
		name string
		res  *v1alpha1.FlowExporterDestination
		want *Destination
	}{
		{
			name: "populates config",
			res: &v1alpha1.FlowExporterDestination{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name: "dest1",
				},
				Spec: v1alpha1.FlowExporterDestinationSpec{
					Address: "12.23.34.45:9876",
					Protocol: v1alpha1.FlowExporterProtocol{
						GRPC: &v1alpha1.FlowExporterGRPCConfig{},
					},
					Filter:                         &v1alpha1.FlowExporterFilter{Protocols: []string{"udp"}},
					ActiveFlowExportTimeoutSeconds: 4,
					IdleFlowExportTimeoutSeconds:   6,
					TLSConfig: &v1alpha1.FlowExporterTLSConfig{
						ServerName:    "foo.example.com",
						MinTLSVersion: "",
						CAConfigMap:   v1alpha1.NamespacedName{Name: "ca1", Namespace: "ns2"},
						ClientSecret:  &v1alpha1.NamespacedName{Name: "client1", Namespace: "client2"},
					},
				},
			},
			want: &Destination{
				DestinationConfig: DestinationConfig{
					name:              "dest1",
					address:           "12.23.34.45:9876",
					activeFlowTimeout: 4 * time.Second,
					idleFlowTimeout:   6 * time.Second,
					tlsConfig: &v1alpha1.FlowExporterTLSConfig{
						ServerName:   "foo.example.com",
						CAConfigMap:  v1alpha1.NamespacedName{Name: "ca1", Namespace: "ns2"},
						ClientSecret: &v1alpha1.NamespacedName{Name: "client1", Namespace: "client2"},
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
	destination := &v1alpha1.FlowExporterDestination{
		ObjectMeta: metav1.ObjectMeta{Name: "dest1"},
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
			t.Skip()
			crdClient := fakeversioned.NewSimpleClientset(destination)
			informerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
			destInformer := informerFactory.Crd().V1alpha1().FlowExporterDestinations()

			stopCh := make(chan struct{})
			defer close(stopCh)
			informerFactory.Start(stopCh)
			informerFactory.WaitForCacheSync(stopCh)

			exp := &FlowExporter{
				destinations:        map[string]destinationObj{},
				destinationInformer: destInformer,
				destinationLister:   destInformer.Lister(),
			}

			if tt.hasExistingDest {
				exp.destinations[tt.key] = destinationObj{
					stopCh: make(chan struct{}),
				}
			}

			err := exp.syncFlowExporterDestination(tt.key)
			require.Nil(t, err)
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
