// Copyright 2023 Antrea Authors
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

package groupmember

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/clustergroupmember"
	"antrea.io/antrea/pkg/util/k8s"
)

type REST struct {
	querier clustergroupmember.GroupMembershipQuerier
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.GetterWithOptions    = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(querier clustergroupmember.GroupMembershipQuerier) *REST {
	return &REST{querier}
}

func (r *REST) New() runtime.Object {
	return &controlplane.GroupMembers{}
}

func (r *REST) Destroy() {
}

func (r *REST) Get(ctx context.Context, name string, options runtime.Object) (runtime.Object, error) {
	ns, ok := request.NamespaceFrom(ctx)
	if !ok || len(ns) == 0 {
		return nil, errors.NewBadRequest("Namespace parameter required.")
	}
	groupName := k8s.NamespacedName(ns, name)
	var err error
	memberList := &controlplane.GroupMembers{}
	memberList.Namespace = ns
	memberList.Name = name
	memberList.EffectiveMembers, memberList.EffectiveIPBlocks, memberList.TotalMembers, memberList.TotalPages, memberList.CurrentPage, err = clustergroupmember.GetPaginatedMembers(r.querier, groupName, options)
	return memberList, err
}

// NewGetOptions returns the default options for Get, so options object is never nil.
func (r *REST) NewGetOptions() (runtime.Object, bool, string) {
	return &controlplane.PaginationGetOptions{}, false, ""
}

func (r *REST) NamespaceScoped() bool {
	return true
}

func (r *REST) GetSingularName() string {
	return "groupmembers"
}
