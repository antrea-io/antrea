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

package nodelatencystat

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
)

type REST struct {
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.Getter               = &REST{}
	_ rest.Lister               = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST() *REST {
	return &REST{}
}

func (r *REST) New() runtime.Object {
	return &statsv1alpha1.NodeLatencyStats{}
}

func (r *REST) Destroy() {
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	// TODO: fill this function in next PR
	return &statsv1alpha1.NodeLatencyStats{}, nil
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	// TODO: fill this function in next PR
	return &statsv1alpha1.NodeLatencyStats{}, nil
}

func (r *REST) NewList() runtime.Object {
	return &statsv1alpha1.NodeLatencyStats{}
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	// TODO: fill this function in next PR
	return &statsv1alpha1.NodeLatencyStatList{}, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	// TODO: fill this function in next PR
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "SourceNodeName", Type: "string", Format: "name", Description: "Source node name."},
			{Name: "NodeIPLatencyList", Type: "array", Format: "string", Description: "Node IP latency list."},
		},
	}

	return table, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "nodelatencystat"
}
