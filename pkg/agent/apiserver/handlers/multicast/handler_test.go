// Copyright 2022 Antrea Authors.
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

package multicast

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/multicast"
	"antrea.io/antrea/pkg/features"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

func TestPodMulticastStatsQuery(t *testing.T) {
	features.DefaultMutableFeatureGate.Set("Multicast=true")
	defer features.DefaultMutableFeatureGate.Set("Multicast=false")
	ctrl := gomock.NewController(t)

	testcases := map[string]struct {
		name                   string
		namespace              string
		expectedStatus         int
		expectedContent        []apis.MulticastResponse
		getPodStatsResult      *multicast.PodTrafficStats
		gettAllPodsStatsResult map[*interfacestore.InterfaceConfig]*multicast.PodTrafficStats
	}{
		"Hit PodMulticastStats query, namespace provided": {
			name:           "pod1",
			namespace:      "namespaceA",
			expectedStatus: http.StatusOK,
			expectedContent: []apis.MulticastResponse{
				{
					PodName:      "pod1",
					PodNamespace: "namespaceA",
					Inbound:      "22",
					Outbound:     "33",
				},
			},
			getPodStatsResult: &multicast.PodTrafficStats{Inbound: 22, Outbound: 33},
		},
		"Miss PodMulticastStats query, namespace and name provided": {
			name:              "pod1",
			namespace:         "namespaceA",
			expectedStatus:    http.StatusNotFound,
			getPodStatsResult: nil,
		},
		"Namespace not provided": {
			name:           "pod1",
			namespace:      "",
			expectedStatus: http.StatusServiceUnavailable,
		},
		"Name not provided": {
			name:           "",
			namespace:      "namespaceA",
			expectedStatus: http.StatusOK,
			gettAllPodsStatsResult: map[*interfacestore.InterfaceConfig]*multicast.PodTrafficStats{
				{ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "test1"}}:      {Inbound: 22, Outbound: 33},
				{ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod2", PodNamespace: "namespaceA"}}: {Inbound: 44, Outbound: 69},
			},
			expectedContent: []apis.MulticastResponse{
				{
					PodName:      "pod2",
					PodNamespace: "namespaceA",
					Inbound:      "44",
					Outbound:     "69",
				},
			},
		},
		"Both name and namespace not provided": {
			name:           "",
			namespace:      "",
			expectedStatus: http.StatusOK,
			gettAllPodsStatsResult: map[*interfacestore.InterfaceConfig]*multicast.PodTrafficStats{
				{ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "test1"}}: {Inbound: 22, Outbound: 33},
				{ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod2", PodNamespace: "test2"}}: {Inbound: 44, Outbound: 66},
			},
			expectedContent: []apis.MulticastResponse{
				{
					PodName:      "pod1",
					PodNamespace: "test1",
					Inbound:      "22",
					Outbound:     "33",
				},
				{
					PodName:      "pod2",
					PodNamespace: "test2",
					Inbound:      "44",
					Outbound:     "66",
				},
			},
		},
	}

	for k, tc := range testcases {
		q := queriertest.NewMockAgentMulticastInfoQuerier(ctrl)
		q.EXPECT().GetPodStats(tc.name, tc.namespace).Return(tc.getPodStatsResult).AnyTimes()
		q.EXPECT().GetAllPodsStats().Return(tc.gettAllPodsStatsResult).AnyTimes()
		handler := HandleFunc(q)
		query := fmt.Sprintf("?name=%s&&namespace=%s", tc.name, tc.namespace)
		req, err := http.NewRequest(http.MethodGet, query, nil)
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, tc.expectedStatus, recorder.Code, k)

		if tc.expectedStatus == http.StatusOK {
			var received []apis.MulticastResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &received)
			assert.Nil(t, err)
			assert.ElementsMatch(t, tc.expectedContent, received)
		}
	}
}
