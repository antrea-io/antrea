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

package addressgroup

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/registry/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// REST implements rest.Storage for AddressGroups.
type REST struct {
	addressGroupStore storage.Interface
}

var (
	_ rest.Storage = &REST{}
	_ rest.Watcher = &REST{}
	_ rest.Scoper  = &REST{}
	_ rest.Lister  = &REST{}
	_ rest.Getter  = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(addressGroupStore storage.Interface) *REST {
	return &REST{addressGroupStore}
}

func (r *REST) New() runtime.Object {
	return &networking.AddressGroup{}
}

func (r *REST) NewList() runtime.Object {
	return &networking.AddressGroupList{}
}

func (r *REST) Get(ctx context.Context, name string, options *v1.GetOptions) (runtime.Object, error) {
	addressGroup, exists, err := r.addressGroupStore.Get(name)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	if !exists {
		return nil, errors.NewNotFound(networking.Resource("addressgroup"), name)
	}
	obj := new(networking.AddressGroup)
	store.ToAddressGroupMsg(addressGroup.(*types.AddressGroup), obj, true)
	return obj, nil
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	addressGroups := r.addressGroupStore.List()
	list := new(networking.AddressGroupList)
	list.Items = make([]networking.AddressGroup, len(addressGroups))
	for i := range addressGroups {
		store.ToAddressGroupMsg(addressGroups[i].(*types.AddressGroup), &list.Items[i], true)
	}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Watch(ctx context.Context, options *internalversion.ListOptions) (watch.Interface, error) {
	key, label, field := networkpolicy.GetSelectors(options)
	return r.addressGroupStore.Watch(ctx, key, label, field)
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*v1.Table, error) {
	return rest.NewDefaultTableConvertor(networking.Resource("addressgroup")).ConvertToTable(ctx, obj, tableOptions)
}
