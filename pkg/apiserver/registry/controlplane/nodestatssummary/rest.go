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

package nodestatssummary

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
)

// statsCollector is the interface required by the handler.
type statsCollector interface {
	Collect(summary *controlplane.NodeStatsSummary)
}

type REST struct {
	statsCollector statsCollector
}

var (
	_ rest.Creater = &REST{}
	_ rest.Scoper  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(c statsCollector) *REST {
	return &REST{c}
}

func (r *REST) New() runtime.Object {
	return &controlplane.NodeStatsSummary{}
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *v1.CreateOptions) (runtime.Object, error) {
	summary := obj.(*controlplane.NodeStatsSummary)
	r.statsCollector.Collect(summary)
	// a valid runtime.Object must be returned, otherwise the client would throw error.
	return &controlplane.NodeStatsSummary{}, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}
