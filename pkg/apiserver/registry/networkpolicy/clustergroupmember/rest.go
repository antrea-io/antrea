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

package clustergroupmember

import (
	"context"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/apis/controlplane"
)

type REST struct {
	querier GroupMembershipQuerier
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.GetterWithOptions    = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(querier GroupMembershipQuerier) *REST {
	return &REST{querier}
}

type GroupMembershipQuerier interface {
	GetGroupMembers(name string) (controlplane.GroupMemberSet, []controlplane.IPBlock, error)
}

func (r *REST) New() runtime.Object {
	return &controlplane.ClusterGroupMembers{}
}

func (r *REST) Destroy() {
}

func (r *REST) Get(ctx context.Context, name string, options runtime.Object) (runtime.Object, error) {
	var err error
	memberList := &controlplane.ClusterGroupMembers{}
	memberList.Name = name
	memberList.EffectiveMembers, memberList.EffectiveIPBlocks, memberList.TotalMembers, memberList.TotalPages, memberList.CurrentPage, err = GetPaginatedMembers(r.querier, name, options)
	return memberList, err
}

// NewGetOptions returns the default options for Get, so options object is never nil.
func (r *REST) NewGetOptions() (runtime.Object, bool, string) {
	return &controlplane.PaginationGetOptions{}, false, ""
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "clustergroupmembers"
}

func GetPaginatedMembers(querier GroupMembershipQuerier, name string, options runtime.Object) (members []controlplane.GroupMember, ipNets []controlplane.IPNet, totalMembers, totalPages, currentPage int64, err error) {
	groupMembers, ipBlocks, err := querier.GetGroupMembers(name)
	if err != nil {
		return nil, nil, 0, 0, 0, errors.NewInternalError(err)
	}
	// Retrieve options used for pagination.
	getOptions, ok := options.(*controlplane.PaginationGetOptions)
	if !ok || getOptions == nil {
		return nil, nil, 0, 0, 0, errors.NewInternalError(fmt.Errorf("received error while retrieving options for pagination"))
	}
	if len(ipBlocks) > 0 {
		ipNets = make([]controlplane.IPNet, 0, len(ipBlocks))
		for _, ipb := range ipBlocks {
			// ClusterGroup ipBlock does not support Except slices, so no need to generate an effective
			// list of IPs by removing Except slices from allowed CIDR.
			ipNets = append(ipNets, ipb.CIDR)
		}
	}
	if len(groupMembers) > 0 {
		members = make([]controlplane.GroupMember, 0, len(groupMembers))
		for _, member := range groupMembers {
			members = append(members, *member)
		}
	}
	totalMembers = int64(len(members))
	totalPages, currentPage, err = PaginateMemberList(&members, getOptions)
	return
}

// PaginateMemberList returns paginated results if meaningful options are provided. Options should never be nil.
// Paginated results are continuous only when there is no member change across multiple calls.
// Pagination is not enabled if either page number or limit = 0, in which the full member list is returned.
// An error is returned for invalid options, and an empty list is returned for a page number out of the pages range.
func PaginateMemberList(effectiveMembers *[]controlplane.GroupMember, pageInfo *controlplane.PaginationGetOptions) (int64, int64, error) {
	if pageInfo.Limit < 0 {
		return 0, 0, errors.NewBadRequest(fmt.Sprintf("received invalid page limit %d for pagination", pageInfo.Limit))
	} else if pageInfo.Page < 0 {
		return 0, 0, errors.NewBadRequest(fmt.Sprintf("received invalid page number %d for pagination", pageInfo.Page))
	}
	if len(*effectiveMembers) == 0 {
		return 0, 0, nil
	}
	// Sort members based on EE/Pod names to realize consistent pagination results.
	sort.SliceStable(*effectiveMembers, func(i, j int) bool {
		if (*effectiveMembers)[i].Pod != nil && (*effectiveMembers)[j].Pod != nil {
			return (*effectiveMembers)[i].Pod.Name < (*effectiveMembers)[j].Pod.Name
		} else if (*effectiveMembers)[i].ExternalEntity != nil && (*effectiveMembers)[j].ExternalEntity != nil {
			return (*effectiveMembers)[i].ExternalEntity.Name < (*effectiveMembers)[j].ExternalEntity.Name
		} else {
			return true
		}
	})
	if pageInfo.Limit == 0 {
		return 1, 1, nil
	}
	totalPages := (int64(len(*effectiveMembers)) + pageInfo.Limit - 1) / pageInfo.Limit
	if totalPages >= pageInfo.Page && pageInfo.Page > 0 {
		beginMember := (pageInfo.Page - 1) * pageInfo.Limit
		*effectiveMembers = (*effectiveMembers)[beginMember:]
		if pageInfo.Limit < int64(len(*effectiveMembers)) {
			*effectiveMembers = (*effectiveMembers)[:pageInfo.Limit]
		}
	} else if totalPages < pageInfo.Page {
		// Returns an empty member list if the page number exceeds total pages, to indicate end of list.
		*effectiveMembers = (*effectiveMembers)[:0]
	}
	return totalPages, pageInfo.Page, nil
}
