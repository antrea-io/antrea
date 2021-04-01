// Copyright 2021 Antrea Authors
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

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
)

// The NetworkPolicyExpansion interface allows manually adding extra methods to the NetworkPolicyInterface.
type NetworkPolicyExpansion interface {
	UpdateStatus(ctx context.Context, name string, status *v1beta2.NetworkPolicyStatus) error
}

func (c *networkPolicies) UpdateStatus(ctx context.Context, name string, status *v1beta2.NetworkPolicyStatus) error {
	return c.client.Post().Name(name).Resource("networkpolicies").SubResource("status").Body(status).Do(ctx).Error()
}
