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
	querier groupMembershipQuerier
}

var (
	_ rest.Storage           = &REST{}
	_ rest.Scoper            = &REST{}
	_ rest.GetterWithOptions = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(querier groupMembershipQuerier) *REST {
	return &REST{querier}
}

type groupMembershipQuerier interface {
	GetGroupMembers(name string) (controlplane.GroupMemberSet, []controlplane.IPBlock, error)
}

func (r *REST) New() runtime.Object {
	return &controlplane.ClusterGroupMembers{}
}

func (r *REST) Get(ctx context.Context, name string, options runtime.Object) (runtime.Object, error) {
	groupMembers, ipBlocks, err := r.querier.GetGroupMembers(name)
	if err != nil {
		return nil, errors.NewInternalError(err)
	}
	// Retrieve options used for pagination.
	getOptions, ok := options.(*controlplane.PaginationGetOptions)
	if !ok || getOptions == nil {
		return nil, errors.NewInternalError(fmt.Errorf("received error while retrieving options for pagination"))
	}
	memberList := &controlplane.ClusterGroupMembers{}
	if len(ipBlocks) > 0 {
		effectiveIPBlocks := make([]controlplane.IPNet, 0, len(ipBlocks))
		for _, ipb := range ipBlocks {
			// ClusterGroup ipBlock does not support Except slices, so no need to generate an effective
			// list of IPs by removing Except slices from allowed CIDR.
			effectiveIPBlocks = append(effectiveIPBlocks, ipb.CIDR)
		}
		memberList.EffectiveIPBlocks = effectiveIPBlocks
	}
	if len(groupMembers) > 0 {
		effectiveMembers := make([]controlplane.GroupMember, 0, len(groupMembers))
		for _, member := range groupMembers {
			effectiveMembers = append(effectiveMembers, *member)
		}
		memberList.EffectiveMembers = effectiveMembers
	}
	memberList.Name = name
	memberList.TotalMembers = int64(len(memberList.EffectiveMembers))
	err = paginateMemberList(memberList, getOptions)
	return memberList, err
}

// NewGetOptions returns the default options for Get, so options object is never nil.
func (r *REST) NewGetOptions() (runtime.Object, bool, string) {
	return &controlplane.PaginationGetOptions{}, false, ""
}

func (r *REST) NamespaceScoped() bool {
	return false
}

// paginateMemberList returns paginated results if meaningful options are provided, options should never be nil.
// Paginated results are continuous only when there is no member change across multiple calls.
// Pagination is not processed if either page number or limit = 0, thus returns full member list.
// Returns an error for invalid options; returns empty list for page number beyond the total pages range.
func paginateMemberList(memberList *controlplane.ClusterGroupMembers, pageInfo *controlplane.PaginationGetOptions) error {
	if pageInfo.Limit < 0 {
		return errors.NewBadRequest(fmt.Sprintf("received invalid page limit %d for pagination", pageInfo.Limit))
	} else if pageInfo.Page < 0 {
		return errors.NewBadRequest(fmt.Sprintf("received invalid page number %d for pagination", pageInfo.Page))
	}
	if memberList.TotalMembers == 0 {
		memberList.TotalPages, memberList.CurrentPage = 0, 0
		return nil
	}
	// Sort members based on name of ee/pod to realize consistent pagination support.
	sort.SliceStable(memberList.EffectiveMembers, func(i, j int) bool {
		if memberList.EffectiveMembers[i].Pod != nil && memberList.EffectiveMembers[j].Pod != nil {
			return memberList.EffectiveMembers[i].Pod.Name < memberList.EffectiveMembers[j].Pod.Name
		} else if memberList.EffectiveMembers[i].ExternalEntity != nil && memberList.EffectiveMembers[j].ExternalEntity != nil {
			return memberList.EffectiveMembers[i].ExternalEntity.Name < memberList.EffectiveMembers[j].ExternalEntity.Name
		} else {
			return true
		}
	})
	if pageInfo.Limit == 0 {
		memberList.TotalPages, memberList.CurrentPage = 1, 1
		return nil
	}
	totalPages := (int64(len(memberList.EffectiveMembers)) + pageInfo.Limit - 1) / pageInfo.Limit
	memberList.TotalPages = totalPages
	memberList.CurrentPage = pageInfo.Page
	if totalPages >= pageInfo.Page && pageInfo.Page > 0 {
		beginMember := (pageInfo.Page - 1) * pageInfo.Limit
		memberList.EffectiveMembers = memberList.EffectiveMembers[beginMember:]
		if pageInfo.Limit < int64(len(memberList.EffectiveMembers)) {
			memberList.EffectiveMembers = memberList.EffectiveMembers[:pageInfo.Limit]
		}
	} else if totalPages < pageInfo.Page {
		// Returns empty memberList if page number exceeds total pages, to indicate end of list.
		memberList.EffectiveMembers = memberList.EffectiveMembers[:0]
	}
	return nil
}
