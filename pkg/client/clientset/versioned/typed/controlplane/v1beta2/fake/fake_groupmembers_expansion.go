// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fake

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apiserver/registry/networkpolicy/clustergroupmember"
)

func (c *FakeGroupMembers) PaginatedGet(ctx context.Context, name string, pagination v1beta2.PaginationGetOptions, options v1.GetOptions) (result *v1beta2.GroupMembers, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(groupmembersResource, c.ns, name), &v1beta2.GroupMembers{})

	if obj == nil {
		return nil, err
	}
	result = obj.(*v1beta2.GroupMembers)
	var oriMembers *controlplane.GroupMembers
	v1beta2.Convert_v1beta2_GroupMembers_To_controlplane_GroupMembers(result, oriMembers, nil)
	result.TotalPages, result.CurrentPage, err = clustergroupmember.PaginateMemberList(&oriMembers.EffectiveMembers, &controlplane.PaginationGetOptions{Page: pagination.Page, Limit: pagination.Limit})
	v1beta2.Convert_controlplane_GroupMembers_To_v1beta2_GroupMembers(oriMembers, result, nil)
	return result, err
}
