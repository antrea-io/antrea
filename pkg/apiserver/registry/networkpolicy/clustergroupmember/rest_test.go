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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"

	"antrea.io/antrea/pkg/apis/controlplane"
)

type fakeQuerier struct {
	members map[string]controlplane.GroupMemberSet
}

func (q fakeQuerier) GetGroupMembers(uid string) (controlplane.GroupMemberSet, []controlplane.IPBlock, error) {
	if memberList, ok := q.members[uid]; ok {
		return memberList, nil, nil
	} else if uid == "cgIPBlock" {
		testCIDR := controlplane.IPNet{
			IP:           controlplane.IPAddress(net.ParseIP("10.0.0.1")),
			PrefixLength: int32(24),
		}
		return nil, []controlplane.IPBlock{{CIDR: testCIDR}}, nil
	}
	return nil, nil, nil
}

func TestRESTGet(t *testing.T) {
	members := map[string]controlplane.GroupMemberSet{
		"cgA": {
			"memberKey1": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod1",
					Namespace: "ns1",
				},
				IPs: []controlplane.IPAddress{
					[]byte{127, 10, 0, 1},
				},
			},
		},
		"cgB": {
			"memberKey2": &controlplane.GroupMember{
				ExternalEntity: &controlplane.ExternalEntityReference{
					Name:      "ee2",
					Namespace: "ns1",
				},
				IPs: []controlplane.IPAddress{
					[]byte{127, 10, 0, 2},
				},
			},
		},
	}
	tests := []struct {
		name        string
		groupName   string
		expectedObj runtime.Object
		expectedErr bool
	}{
		{
			name:      "single-pod-group-member",
			groupName: "cgA",
			expectedObj: &controlplane.ClusterGroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgA",
				},
				EffectiveMembers: []controlplane.GroupMember{
					{
						Pod: &controlplane.PodReference{
							Name:      "pod1",
							Namespace: "ns1",
						},
						IPs: []controlplane.IPAddress{
							[]byte{127, 10, 0, 1},
						},
					},
				},
			},
			expectedErr: false,
		},
		{
			name:      "single-ee-group-member",
			groupName: "cgB",
			expectedObj: &controlplane.ClusterGroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgB",
				},
				EffectiveMembers: []controlplane.GroupMember{
					{
						ExternalEntity: &controlplane.ExternalEntityReference{
							Name:      "ee2",
							Namespace: "ns1",
						},
						IPs: []controlplane.IPAddress{
							[]byte{127, 10, 0, 2},
						},
					},
				},
			},
			expectedErr: false,
		},
		{
			name:      "no-group-member",
			groupName: "cgC",
			expectedObj: &controlplane.ClusterGroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgC",
				},
				EffectiveMembers: []controlplane.GroupMember{},
			},
			expectedErr: false,
		},
		{
			name:      "ipBlock-cg",
			groupName: "cgIPBlock",
			expectedObj: &controlplane.ClusterGroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgIPBlock",
				},
				EffectiveIPBlocks: []controlplane.IPNet{
					{
						IP:           controlplane.IPAddress(net.ParseIP("10.0.0.1")),
						PrefixLength: int32(24),
					},
				},
			},
			expectedErr: false,
		},
	}
	rest := NewREST(fakeQuerier{members: members})
	for _, tt := range tests {
		actualGroupList, err := rest.Get(request.NewDefaultContext(), tt.groupName, &metav1.GetOptions{})
		if tt.expectedErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, tt.expectedObj, actualGroupList)
	}
}
