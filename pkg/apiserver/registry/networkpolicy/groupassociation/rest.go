// Copyright 2021 Antrea Authors
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

package groupassociation

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/controller/types"
)

type REST struct {
	querier groupAssociationQuerier
}

var (
	_ rest.Storage = &REST{}
	_ rest.Scoper  = &REST{}
	_ rest.Getter  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(querier groupAssociationQuerier) *REST {
	return &REST{querier}
}

// groupAssociationQuerier is the interface required by the handler.
type groupAssociationQuerier interface {
	GetAssociatedGroups(name, namespace string) ([]types.Group, error)
}

func (r *REST) New() runtime.Object {
	return &controlplane.GroupAssociation{}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	ns, ok := request.NamespaceFrom(ctx)
	if !ok || len(ns) == 0 {
		return nil, errors.NewBadRequest("Namespace parameter required.")
	}
	groups, err := r.querier.GetAssociatedGroups(name, ns)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	items := make([]controlplane.GroupReference, 0, len(groups))
	for i := range groups {
		item := controlplane.GroupReference{
			Name: groups[i].Name,
			UID:  groups[i].UID,
		}
		items = append(items, item)
	}
	members := &controlplane.GroupAssociation{AssociatedGroups: items}
	return members, nil
}

func (r *REST) NamespaceScoped() bool {
	return true
}
