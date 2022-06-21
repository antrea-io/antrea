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

func getTestMembersBasic() map[string]controlplane.GroupMemberSet {
	return map[string]controlplane.GroupMemberSet{
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
}

func getTestMembersPagination() map[string]controlplane.GroupMemberSet {
	return map[string]controlplane.GroupMemberSet{
		"cgA": {
			"memberKey1": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod3",
					Namespace: "ns1",
				},
				IPs: []controlplane.IPAddress{
					[]byte{127, 10, 0, 1},
				},
			},
			"memberKey2": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod2",
					Namespace: "ns1",
				},
				IPs: []controlplane.IPAddress{
					[]byte{127, 10, 0, 1},
				},
			},
			"memberKey3": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod1",
					Namespace: "ns1",
				},
				IPs: []controlplane.IPAddress{
					[]byte{127, 10, 0, 1},
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
		"cgIPBlock": ipb,
	}
}

func TestRESTGetBasic(t *testing.T) {
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
				TotalMembers: 1,
				TotalPages:   1,
				CurrentPage:  1,
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
				TotalMembers: 1,
				TotalPages:   1,
				CurrentPage:  1,
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
				TotalMembers: 0,
				TotalPages:   0,
				CurrentPage:  0,
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
				TotalMembers: 0,
				TotalPages:   0,
				CurrentPage:  0,
			},
			expectedErr: false,
		},
	}
	rest := NewREST(fakeQuerier{members: getTestMembersBasic(), ipMembers: getTestIPMembers()})
	for _, tt := range tests {
		actualGroupList, err := rest.Get(request.NewDefaultContext(), tt.groupName, &controlplane.PaginationGetOptions{})
		if tt.expectedErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, tt.expectedObj, actualGroupList)
	}
}

func TestRESTGetPagination(t *testing.T) {
	tests := []struct {
		name              string
		groupName         string
		paginationOptions runtime.Object
		expectedObj       runtime.Object
		expectedErr       bool
	}{
		{
			name:              "page1/2-group-member-pagination",
			groupName:         "cgA",
			paginationOptions: &controlplane.PaginationGetOptions{Page: 1, Limit: 2},
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
					{
						Pod: &controlplane.PodReference{
							Name:      "pod2",
							Namespace: "ns1",
						},
						IPs: []controlplane.IPAddress{
							[]byte{127, 10, 0, 1},
						},
					},
				},
				TotalMembers: 3,
				TotalPages:   2,
				CurrentPage:  1,
			},
			expectedErr: false,
		},
		{
			name:              "page2/2-group-member-pagination",
			groupName:         "cgA",
			paginationOptions: &controlplane.PaginationGetOptions{Page: 2, Limit: 2},
			expectedObj: &controlplane.ClusterGroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgA",
				},
				EffectiveMembers: []controlplane.GroupMember{
					{
						Pod: &controlplane.PodReference{
							Name:      "pod3",
							Namespace: "ns1",
						},
						IPs: []controlplane.IPAddress{
							[]byte{127, 10, 0, 1},
						},
					},
				},
				TotalMembers: 3,
				TotalPages:   2,
				CurrentPage:  2,
			},
			expectedErr: false,
		},
		{
			name:              "exceed-page-group-member-pagination",
			groupName:         "cgA",
			paginationOptions: &controlplane.PaginationGetOptions{Page: 5, Limit: 2},
			expectedObj: &controlplane.ClusterGroupMembers{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cgA",
				},
				EffectiveMembers: []controlplane.GroupMember{},
				TotalMembers:     3,
				TotalPages:       2,
				CurrentPage:      5,
			},
			expectedErr: false,
		},
		{
			name:              "default-zero-group-member-pagination",
			groupName:         "cgA",
			paginationOptions: &controlplane.PaginationGetOptions{Page: 0, Limit: 0},
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
					{
						Pod: &controlplane.PodReference{
							Name:      "pod2",
							Namespace: "ns1",
						},
						IPs: []controlplane.IPAddress{
							[]byte{127, 10, 0, 1},
						},
					},
					{
						Pod: &controlplane.PodReference{
							Name:      "pod3",
							Namespace: "ns1",
						},
						IPs: []controlplane.IPAddress{
							[]byte{127, 10, 0, 1},
						},
					},
				},
				TotalMembers: 3,
				TotalPages:   1,
				CurrentPage:  1,
			},
			expectedErr: false,
		},
		{
			name:              "err-page-group-member-pagination",
			groupName:         "cgA",
			paginationOptions: &controlplane.PaginationGetOptions{Page: -1, Limit: 2},
			expectedErr:       true,
		},
		{
			name:              "err-limit-group-member-pagination",
			groupName:         "cgA",
			paginationOptions: &controlplane.PaginationGetOptions{Page: 1, Limit: -2},
			expectedErr:       true,
		},
	}
	rest := NewREST(fakeQuerier{members: getTestMembersPagination()})
	for _, tt := range tests {
		actualGroupList, err := rest.Get(request.NewDefaultContext(), tt.groupName, tt.paginationOptions)
		if tt.expectedErr {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tt.expectedObj, actualGroupList)
	}
}
