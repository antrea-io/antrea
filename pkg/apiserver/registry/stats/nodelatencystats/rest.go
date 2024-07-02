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
	"strconv"

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
	return &REST{
		indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}),
	}
}

func (r *REST) New() runtime.Object {
	return &statsv1alpha1.NodeLatencyStats{}
}

func (r *REST) Destroy() {
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	summary := obj.(*statsv1alpha1.NodeLatencyStats)
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

	if options.Continue != "" {
		start, err := strconv.Atoi(options.Continue)
		if err != nil {
			return nil, errors.NewBadRequest("invalid continue token")
		}
		if start < 0 || start >= len(objs) {
			return r.NewList(), nil
		}
		objs = objs[start:]
	}
	if options.Limit > 0 && int64(len(objs)) > options.Limit {
		objs = objs[:options.Limit]
	}

	entries := make([]statsv1alpha1.NodeLatencyStats, 0, len(objs))
	for _, obj := range objs {
		entries = append(entries, *obj.(*statsv1alpha1.NodeLatencyStats))
	}

	return &statsv1alpha1.NodeLatencyStatsList{Items: entries}, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "SourceNodeName", Type: "string", Format: "name", Description: "Source node name."},
			{Name: "PeerNodeLatencyStats", Type: "array", Format: "string", Description: "Current Node to each peers latency."},
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
		return []interface{}{name, summary.PeerNodeLatencyStats}, nil
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

	err = r.indexer.Delete(obj)
	if err != nil {
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
