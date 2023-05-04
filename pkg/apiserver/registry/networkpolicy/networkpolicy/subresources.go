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

package networkpolicy

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
)

// StatusREST implements the REST endpoint for getting NetworkPolicy's status.
type StatusREST struct {
	collector statusCollector
}

// NewStatusREST returns a REST object that will work against API services.
func NewStatusREST(collector statusCollector) *StatusREST {
	return &StatusREST{collector}
}

// statusCollector is the interface required by the handler.
type statusCollector interface {
	UpdateStatus(status *controlplane.NetworkPolicyStatus) error
}

var _ rest.NamedCreater = &StatusREST{}

func (s StatusREST) New() runtime.Object {
	return &controlplane.NetworkPolicyStatus{}
}

func (s StatusREST) Destroy() {
}

func (s StatusREST) Create(ctx context.Context, name string, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	status, ok := obj.(*controlplane.NetworkPolicyStatus)
	if !ok {
		return nil, errors.NewBadRequest(fmt.Sprintf("not a NetworkPolicyStatus object: %T", obj))
	}
	if name != status.Name {
		return nil, errors.NewBadRequest("name in URL does not match name in NetworkPolicyStatus object")
	}
	err := s.collector.UpdateStatus(status)
	if err != nil {
		return nil, err
	}
	return &metav1.Status{Status: metav1.StatusSuccess}, nil
}
