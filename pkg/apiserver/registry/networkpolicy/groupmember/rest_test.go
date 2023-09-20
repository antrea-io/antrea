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
	members   map[string]controlplane.GroupMemberSet
	ipMembers map[string][]controlplane.IPBlock
}

func (q fakeQuerier) GetGroupMembers(uid string) (controlplane.GroupMemberSet, []controlplane.IPBlock, error) {
	if ipMemberList, ok := q.ipMembers[uid]; ok {
		return nil, ipMemberList, nil
	}
	if memberList, ok := q.members[uid]; ok {
		return memberList, nil, nil
	}
	return nil, nil, nil
}

func getTestMembers() map[string]controlplane.GroupMemberSet {
	return map[string]controlplane.GroupMemberSet{
		"default/ngA": {
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
		"default/ngB": {
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
}

func getTestIPMembers() map[string][]controlplane.IPBlock {
	testCIDR := controlplane.IPNet{
		IP:           controlplane.IPAddress(net.ParseIP("10.0.0.1")),
		PrefixLength: int32(24),
	}
	ipb := []controlplane.IPBlock{{CIDR: testCIDR}}
	return map[string][]controlplane.IPBlock{
		"ns2/ngIPBlock": ipb,
	}
}

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &controlplane.GroupMembers{}, r.New())
	assert.True(t, r.NamespaceScoped())
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name        string
		groupName   string
		namespace   string
		expectedObj runtime.Object
		expectedErr bool
	}{
		{
			name:      "single-pod-group-member",
			groupName: "ngA",
			namespace: "default",
			expectedObj: &controlplane.GroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ngA",
					Namespace: "default",
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
				TotalMembers: 1,
				TotalPages:   1,
				CurrentPage:  1,
			},
			expectedErr: false,
		},
		{
			name:      "single-ee-group-member",
			groupName: "ngB",
			namespace: "default",
			expectedObj: &controlplane.GroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ngB",
					Namespace: "default",
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
				TotalMembers: 1,
				TotalPages:   1,
				CurrentPage:  1,
			},
			expectedErr: false,
		},
		{
			name:      "no-group-member",
			groupName: "ngC",
			namespace: "default",
			expectedObj: &controlplane.GroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ngC",
					Namespace: "default",
				},
				TotalMembers: 0,
				TotalPages:   0,
				CurrentPage:  0,
			},
			expectedErr: false,
		},
		{
			name:      "no-group-member-in-namespace",
			groupName: "ngA",
			namespace: "test",
			expectedObj: &controlplane.GroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ngA",
					Namespace: "test",
				},
				TotalMembers: 0,
				TotalPages:   0,
				CurrentPage:  0,
			},
			expectedErr: false,
		},
		{
			name:      "ipBlock-ng",
			groupName: "ngIPBlock",
			namespace: "ns2",
			expectedObj: &controlplane.GroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ngIPBlock",
					Namespace: "ns2",
				},
				EffectiveIPBlocks: []controlplane.IPNet{
					{
						IP:           controlplane.IPAddress(net.ParseIP("10.0.0.1")),
						PrefixLength: int32(24),
					},
				},
				TotalMembers: 0,
				TotalPages:   0,
				CurrentPage:  0,
			},
			expectedErr: false,
		},
	}
	rest := NewREST(fakeQuerier{members: getTestMembers(), ipMembers: getTestIPMembers()})
	for _, tt := range tests {
		actualGroupList, err := rest.Get(request.WithNamespace(request.NewContext(), tt.namespace), tt.groupName, &controlplane.PaginationGetOptions{})
		if tt.expectedErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, tt.expectedObj, actualGroupList)
	}
}
