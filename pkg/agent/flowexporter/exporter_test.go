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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/flowexporter/options"
	api "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestFlowExporter_createConsumerFromResource(t *testing.T) {
	tests := []struct {
		name string

		target *api.FlowExporterDestination
		want   *Consumer
	}{
		{
			name: "IPFIX target",
			target: &api.FlowExporterDestination{
				Spec: api.FlowExporterDestinationSpec{
					Address: "flow-aggregator/flow-aggregator:4739",
					Protocol: api.FlowExporterProtocol{
						IPFIX: &api.FlowExporterIPFIXConfig{
							Transport: api.FlowExporterTransportTCP,
						},
					},
					ActiveFlowExportTimeoutSeconds: 15,
					IdleFlowExportTimeoutSeconds:   2,
				},
			},
			want: &Consumer{ConsumerConfig: &ConsumerConfig{
				address:     "flow-aggregator/flow-aggregator:4739",
				nodeName:    "nodeName",
				nodeUID:     "nodeUID",
				obsDomainID: 32,
				v4Enabled:   true,
				v6Enabled:   true,
				protocol: &api.FlowExporterIPFIXConfig{
					Transport: api.FlowExporterTransportTCP,
				},
				activeFlowTimeout: 15 * time.Second,
				idleFlowTimeout:   2 * time.Second,
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &FlowExporter{
				nodeName:    "nodeName",
				nodeUID:     "nodeUID",
				obsDomainID: 32,

				v4Enabled: true,
				v6Enabled: true,
			}
			got := fe.createConsumerFromResource(tt.target)

			assert.Equal(t, tt.want.ConsumerConfig, got.ConsumerConfig)
		})
	}
}

func TestFlowExporter_onTargetDelete(t *testing.T) {
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
			fe.onTargetDelete(tt.obj)
			item, _ := fe.queue.Get()
			assert.Equal(t, name, item)
		})
	}
}

func TestFlowExporter_OnUpdateTarget(t *testing.T) {
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
			fe.OnUpdateTarget(tt.old, tt.new)
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

func Test_createDestinationResFromOptions(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		o    *options.FlowExporterOptions
		want *api.FlowExporterDestination
	}{
		{
			name: "static destination disabled",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: false,
			},
			want: nil,
		}, {
			name: "grpc destination",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: true,
				FlowCollectorAddr:       "foo/bar:123",
				FlowCollectorProto:      grpcExporterProtocol,
				ActiveFlowTimeout:       4 * time.Second,
				IdleFlowTimeout:         6 * time.Second,
				ProtocolFilter:          []string{"udp"},
			},
			want: &api.FlowExporterDestination{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Spec: api.FlowExporterDestinationSpec{
					Address: "foo/bar:123",
					Protocol: api.FlowExporterProtocol{
						GRPC: &api.FlowExporterGRPCConfig{},
					},
					Filter: &api.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 4,
					IdleFlowExportTimeoutSeconds:   6,
				},
			},
		}, {
			name: "ipfix destination",
			o: &options.FlowExporterOptions{
				EnableStaticDestination: true,
				FlowCollectorAddr:       "foo/bar:123",
				FlowCollectorProto:      "tcp",
				ActiveFlowTimeout:       4 * time.Second,
				IdleFlowTimeout:         6 * time.Second,
				ProtocolFilter:          []string{"udp"},
			},
			want: &api.FlowExporterDestination{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Spec: api.FlowExporterDestinationSpec{
					Address: "foo/bar:123",
					Protocol: api.FlowExporterProtocol{
						IPFIX: &api.FlowExporterIPFIXConfig{
							Transport: api.FlowExporterTransportTCP,
						},
					},
					Filter: &api.FlowExporterFilter{
						Protocols: []string{"udp"},
					},
					ActiveFlowExportTimeoutSeconds: 4,
					IdleFlowExportTimeoutSeconds:   6,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createDestinationResFromOptions(tt.o)
			assert.Equal(t, tt.want, got)
		})
	}
}
