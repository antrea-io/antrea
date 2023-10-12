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

package v1beta2

import (
	"context"
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
)

// The ClusterGroupMembersExpansion interface allows manually adding extra methods to the ClusterGroupMembersInterface.
type ClusterGroupMembersExpansion interface {
	PaginatedGet(ctx context.Context, name string, pagination v1beta2.PaginationGetOptions, options v1.GetOptions) (result *v1beta2.ClusterGroupMembers, err error)
}

func (c *clusterGroupMembers) PaginatedGet(ctx context.Context, name string, pagination v1beta2.PaginationGetOptions, options v1.GetOptions) (result *v1beta2.ClusterGroupMembers, err error) {
	result = &v1beta2.ClusterGroupMembers{}
	err = c.client.Get().
		Resource("clustergroupmembers").
		Name(name).
		Param("limit", fmt.Sprint(pagination.Limit)).
		Param("page", fmt.Sprint(pagination.Page)).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}
