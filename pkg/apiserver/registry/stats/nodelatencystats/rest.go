// Copyright 2024 Antrea Authors
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

package nodelatencystats

import (
	"context"
	"time"

	"k8s.io/utils/clock"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metatable "k8s.io/apimachinery/pkg/api/meta/table"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/tools/cache"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
)

type REST struct {
	indexer cache.Indexer
	clock   clock.Clock
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.Getter               = &REST{}
	_ rest.Lister               = &REST{}
	_ rest.GracefulDeleter      = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST() *REST {
	return newRESTWithClock(clock.RealClock{})
}

func newRESTWithClock(clock clock.Clock) *REST {
	return &REST{
		indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}),
		clock:   clock,
	}
}

func (r *REST) New() runtime.Object {
	return &statsv1alpha1.NodeLatencyStats{}
}

func (r *REST) Destroy() {
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	// Update will add the object if the key does not exist.
	summary := obj.(*statsv1alpha1.NodeLatencyStats)
	if summary.ObjectMeta.CreationTimestamp.IsZero() {
		summary.ObjectMeta.CreationTimestamp = metav1.Time{Time: r.clock.Now()}
	}
	if err := r.indexer.Update(summary); err != nil {
		return nil, errors.NewInternalError(err)
	}

	return summary, nil
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	obj, exists, err := r.indexer.GetByKey(name)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(statsv1alpha1.Resource("nodelatencystats"), name)
	}

	return obj.(*statsv1alpha1.NodeLatencyStats), nil
}

func (r *REST) NewList() runtime.Object {
	return &statsv1alpha1.NodeLatencyStats{}
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	objs := r.indexer.List()

	// Due to the unordered nature of map iteration and the complexity of controlling 'continue',
	// we will ignore paging here and plan to implement it in the future.

	entries := make([]statsv1alpha1.NodeLatencyStats, 0, len(objs))
	for _, obj := range objs {
		entries = append(entries, *obj.(*statsv1alpha1.NodeLatencyStats))
	}

	return &statsv1alpha1.NodeLatencyStatsList{Items: entries}, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "Node Name", Type: "string", Format: "name", Description: "Name of Node from which latency was measured."},
			{Name: "Num Latency Entries", Type: "integer", Format: "int64", Description: "Number of peers for which latency measurements are available."},
			{Name: "Avg Latency", Type: "string", Format: "", Description: "Average latency value across all peers."},
			{Name: "Max Latency", Type: "string", Format: "", Description: "Largest latency value across all peers."},
		},
	}
	if m, err := meta.ListAccessor(obj); err == nil {
		table.ResourceVersion = m.GetResourceVersion()
		table.Continue = m.GetContinue()
		table.RemainingItemCount = m.GetRemainingItemCount()
	} else {
		if m, err := meta.CommonAccessor(obj); err == nil {
			table.ResourceVersion = m.GetResourceVersion()
		}
	}

	var err error
	table.Rows, err = metatable.MetaToTableRow(obj, func(obj runtime.Object, m metav1.Object, name, age string) ([]interface{}, error) {
		summary := obj.(*statsv1alpha1.NodeLatencyStats)

		// Calculate the max and average latency values.
		peerNodeLatencyEntriesCount := len(summary.PeerNodeLatencyStats)
		var targetIPLatencyCount int64
		var maxLatency int64
		var avgLatency int64

		for i := range summary.PeerNodeLatencyStats {
			targetIPLatency := summary.PeerNodeLatencyStats[i]

			for j := range targetIPLatency.TargetIPLatencyStats {
				targetIPLatencyCount++
				currentLatency := targetIPLatency.TargetIPLatencyStats[j].LastMeasuredRTTNanoseconds
				if currentLatency > maxLatency {
					maxLatency = currentLatency
				}

				// Due to int64 max value is enough for the sum of all latencies,
				// we don't need to check overflow in this case.
				avgLatency += currentLatency
			}
		}

		if targetIPLatencyCount > 0 {
			avgLatency = avgLatency / targetIPLatencyCount
		}

		return []interface{}{name, peerNodeLatencyEntriesCount, time.Duration(avgLatency).String(), time.Duration(maxLatency).String()}, nil
	})
	return table, err
}

func (r *REST) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	// Ignore the deleteValidation and options for now.
	obj, exists, err := r.indexer.GetByKey(name)
	if err != nil {
		return nil, false, errors.NewInternalError(err)
	}
	if !exists {
		return nil, false, errors.NewNotFound(statsv1alpha1.Resource("nodelatencystats"), name)
	}

	if err = r.indexer.Delete(obj); err != nil {
		return nil, false, errors.NewInternalError(err)
	}

	return obj.(*statsv1alpha1.NodeLatencyStats), true, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "nodelatencystats"
}
