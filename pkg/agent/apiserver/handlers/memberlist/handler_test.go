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

package memberlist

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/memberlist"
	memberlisttest "antrea.io/antrea/pkg/agent/memberlist/testing"
	queriertest "antrea.io/antrea/pkg/agent/querier/testing"
)

var (
	node1 = v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Address: "172.16.0.11",
				},
			},
		},
	}
	node2 = v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node2"},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Address: "172.16.0.12",
				},
			},
		},
	}
)

func TestMemberlistQuery(t *testing.T) {
	clientset := fake.NewSimpleClientset(&node1, &node2)
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	nodeLister := nodeInformer.Lister()

	stopCh := make(chan struct{})
	defer close(stopCh)

	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	tests := []struct {
		name                string
		memberlistInterface func(*gomock.Controller) memberlist.Interface
		nodeLister          corelisters.NodeLister
		expectedStatus      int
		expectedResponse    []apis.MemberlistResponse
	}{
		{
			name: "memberlist not running",
			memberlistInterface: func(c *gomock.Controller) memberlist.Interface {
				var cluster *memberlist.Cluster
				var m memberlist.Interface = cluster
				return m
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name: "get memberlist",
			memberlistInterface: func(c *gomock.Controller) memberlist.Interface {
				m := memberlisttest.NewMockInterface(c)
				m.EXPECT().AliveNodes().Return(sets.New[string]("node1"))
				return m
			},
			nodeLister:     nodeLister,
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.MemberlistResponse{
				{
					NodeName: "node1",
					IP:       "172.16.0.11",
					Status:   "Alive",
				},
				{
					NodeName: "node2",
					IP:       "172.16.0.12",
					Status:   "Dead",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentQuerier(ctrl)
			q.EXPECT().GetMemberlistCluster().Return(tt.memberlistInterface(ctrl))
			if tt.nodeLister != nil {
				q.EXPECT().GetNodeLister().Return(tt.nodeLister)
			}
			handler := HandleFunc(q)

			req, err := http.NewRequest(http.MethodGet, "", nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)

			if tt.expectedStatus == http.StatusOK {
				var received []apis.MemberlistResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &received)
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedResponse, received)
			}
		})
	}
}
