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

package controllerinfo

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	clusterinfo "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	system "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/controller/querier"
)

// REST implements rest.Storage for ControllerInfo.
type REST struct {
	controllerQuerier querier.ControllerQuerier
}

// Name of the AntreaControllerInfo resource.
const ControllerInfoResourceName = "antrea-controller"

var (
	_ rest.Scoper = &REST{}
	_ rest.Getter = &REST{}
	_ rest.Lister = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(querier querier.ControllerQuerier) *REST {
	return &REST{querier}
}

func (r *REST) New() runtime.Object {
	return &clusterinfo.AntreaControllerInfo{}
}

func (r *REST) getControllerInfo() *clusterinfo.AntreaControllerInfo {
	// Now AntreaControllerInfo has a single instance.
	info := new(clusterinfo.AntreaControllerInfo)
	r.controllerQuerier.GetControllerInfo(info, false)
	info.Name = ControllerInfoResourceName
	return info
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	info := r.getControllerInfo()
	// The provided name should match the AntreaControllerInfo.Name.
	if info.Name != name {
		return nil, errors.NewNotFound(system.Resource("clusterinfos"), name)
	}
	return info, nil
}

func (r *REST) NewList() runtime.Object {
	return &clusterinfo.AntreaControllerInfoList{}
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	list := new(clusterinfo.AntreaControllerInfoList)
	list.Items = []clusterinfo.AntreaControllerInfo{*r.getControllerInfo()}
	return list, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(system.Resource("clusterinfos")).ConvertToTable(ctx, obj, tableOptions)
}
