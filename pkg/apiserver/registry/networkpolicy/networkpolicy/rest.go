// Copyright 2019 Antrea Authors
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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
	"github.com/vmware-tanzu/antrea/pkg/k8s"
)

// REST implements rest.Storage for NetworkPolicies.
type REST struct {
	networkPolicyStore storage.Interface
}

var (
	_ rest.Storage = &REST{}
	_ rest.Watcher = &REST{}
	_ rest.Scoper  = &REST{}
	_ rest.Lister  = &REST{}
	_ rest.Getter  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(networkPolicyStore storage.Interface) *REST {
	return &REST{networkPolicyStore}
}

func (r *REST) New() runtime.Object {
	return &networking.NetworkPolicy{}
}

func (r *REST) NewList() runtime.Object {
	return &networking.NetworkPolicyList{}
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	ns, ok := request.NamespaceFrom(ctx)
	if !ok || len(ns) == 0 {
		return nil, errors.NewBadRequest("Namespace parameter required.")
	}
	key := k8s.NamespacedName(ns, name)
	networkPolicy, exists, err := r.networkPolicyStore.Get(key)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(networking.Resource("networkpolicy"), name)
	}
	obj := new(networking.NetworkPolicy)
	store.ToNetworkPolicyMsg(networkPolicy.(*types.NetworkPolicy), obj, true)
	return obj, nil
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	ns, namespaceScoped := request.NamespaceFrom(ctx)
	networkPolicies := r.networkPolicyStore.List()
	list := new(networking.NetworkPolicyList)
	for i := range networkPolicies {
		if !namespaceScoped || len(ns) == 0 || networkPolicies[i].(*types.NetworkPolicy).Namespace == ns {
			policy := networking.NetworkPolicy{}
			store.ToNetworkPolicyMsg(networkPolicies[i].(*types.NetworkPolicy), &policy, true)
			list.Items = append(list.Items, policy)
		}
	}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return true
}

func (r *REST) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	key, label, field := networkpolicy.GetSelectors(options)
	if len(key) > 0 {
		ns, ok := request.NamespaceFrom(ctx)
		if !ok || len(ns) == 0 {
			return nil, errors.NewBadRequest("Namespace parameter required.")
		}
		key = k8s.NamespacedName(ns, key)
	}
	return r.networkPolicyStore.Watch(ctx, key, label, field)
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(networking.Resource("networkpolicy")).ConvertToTable(ctx, obj, tableOptions)
}
