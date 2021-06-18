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

package types

import (
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane"
)

// EgressGroup describes a set of GroupMembers to apply Egress to.
// TODO: Unify it with NetworkPolicy AppliedToGroup.
type EgressGroup struct {
	SpanMeta
	// UID of this EgressGroup, it's same as the UID of the Egress.
	UID types.UID
	// Name of this EgressGroup, it's same as the name of the Egress.
	Name string
	// GroupMemberByNode is a mapping from nodeName to a set of GroupMembers on the Node.
	// It will be converted to a slice of GroupMember for transferring according to client's selection.
	GroupMemberByNode map[string]controlplane.GroupMemberSet
}
