// Copyright 2020 Antrea Authors
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

package ovsflows

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	agentquerier "antrea.io/antrea/pkg/agent/querier"
	aqtest "antrea.io/antrea/pkg/agent/querier/testing"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/pkg/querier"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

var (
	testFlowKeys       = []string{"flowKey1", "flowKey2"}
	testDumpFlows      = []string{"flow1", "flow2"}
	testGroupIDs       = []binding.GroupIDType{1, 2}
	testDumpGroups     = []string{"group1", "group2"}
	testResponses      = []Response{{"flow1"}, {"flow2"}}
	testGroupResponses = []Response{{"group1"}, {"group2"}}
)

type testCase struct {
	test           string
	name           string
	namespace      string
	query          string
	expectedStatus int
	resps          []Response
}

func TestBadRequests(t *testing.T) {
	badRequests := map[string]string{
		"Pod only":                  "?pod=pod1",
		"Service only":              "?service=svc1",
		"NetworkPolicy only":        "?networkpolicy=np1",
		"Namespace only":            "?namespace=ns1",
		"Pod and NetworkPolicy":     "?pod=pod1&&networkpolicy=np1",
		"Pod and table":             "?pod=pod1&&table=0",
		"Non-existing table number": "?table=123",
		"Non-existing table name":   "?table=notexist",
		"Too big table number":      "?table=256",
		"Invalid table number":      "?table=0classification",
		"Invalid table name":        "?table=classification0",
		"Invalid group IDs":         "?groups=all,0",
		"Too big group ID":          "?groups=123,4294967296",
		"Negative group ID":         "?groups=-1",
	}

	handler := HandleFunc(nil)
	for k, r := range badRequests {
		req, err := http.NewRequest(http.MethodGet, r, nil)
		assert.Nil(t, err)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusBadRequest, recorder.Code, k)
	}
}

func TestPodFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testInterface := &interfacestore.InterfaceConfig{InterfaceName: "interface0"}
	testcases := []testCase{
		{
			test:           "Existing Pod",
			name:           "pod1",
			namespace:      "ns1",
			query:          "?pod=pod1&&namespace=ns1",
			expectedStatus: http.StatusOK,
		},
		{
			test:           "Non-existing Pod",
			name:           "pod2",
			namespace:      "ns2",
			query:          "?pod=pod2&&namespace=ns2",
			expectedStatus: http.StatusNotFound,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		i := interfacestoretest.NewMockInterfaceStore(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetInterfaceStore().Return(i).Times(1)

		if tc.expectedStatus != http.StatusNotFound {
			ofc := oftest.NewMockClient(ctrl)
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			i.EXPECT().GetContainerInterfacesByPod(tc.name, tc.namespace).Return([]*interfacestore.InterfaceConfig{testInterface}).Times(1)
			ofc.EXPECT().GetPodFlowKeys(testInterface.InterfaceName).Return(testFlowKeys).Times(1)
			q.EXPECT().GetOpenflowClient().Return(ofc).Times(1)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(testFlowKeys))
			for i := range testFlowKeys {
				ovsctl.EXPECT().DumpMatchedFlow(testFlowKeys[i]).Return(testDumpFlows[i], nil).Times(1)
			}
		} else {
			i.EXPECT().GetContainerInterfacesByPod(tc.name, tc.namespace).Return(nil).Times(1)
		}

		runHTTPTest(t, &tc, q)
	}
}

func TestServiceFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := []testCase{
		{
			test:           "Existing Service",
			name:           "svc1",
			namespace:      "ns1",
			query:          "?service=svc1&&namespace=ns1",
			expectedStatus: http.StatusOK,
			resps:          append(testResponses, testGroupResponses...),
		},
		{
			test:           "Non-existing Service",
			name:           "svc2",
			namespace:      "ns2",
			query:          "?service=svc2&&namespace=ns2",
			expectedStatus: http.StatusNotFound,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		p := proxytest.NewMockProxier(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetProxier().Return(p).Times(1)

		if tc.expectedStatus != http.StatusNotFound {
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			p.EXPECT().GetServiceFlowKeys(tc.name, tc.namespace).Return(testFlowKeys, testGroupIDs, true).Times(1)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(testFlowKeys) + len(testGroupIDs))
			for i, f := range testFlowKeys {
				ovsctl.EXPECT().DumpMatchedFlow(f).Return(testDumpFlows[i], nil).Times(1)
			}
			for i, g := range testGroupIDs {
				ovsctl.EXPECT().DumpGroup(uint32(g)).Return(testDumpGroups[i], nil).Times(1)
			}
		} else {
			p.EXPECT().GetServiceFlowKeys(tc.name, tc.namespace).Return(nil, nil, false).Times(1)
		}

		runHTTPTest(t, &tc, q)
	}
}

func TestNetworkPolicyFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testNetworkPolicy := &cpv1beta.NetworkPolicy{}
	testcases := []testCase{
		{
			test:           "Existing NetworkPolicy",
			name:           "np1",
			namespace:      "ns1",
			query:          "?networkpolicy=np1&&namespace=ns1",
			expectedStatus: http.StatusOK,
		},
		{
			test:           "Non-existing NetworkPolicy",
			name:           "np2",
			namespace:      "ns2",
			query:          "?networkpolicy=np2&&namespace=ns2",
			expectedStatus: http.StatusNotFound,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		npq := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetNetworkPolicyInfoQuerier().Return(npq).Times(1)

		if tc.expectedStatus != http.StatusNotFound {
			ofc := oftest.NewMockClient(ctrl)
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			npq.EXPECT().GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{SourceName: tc.name, Namespace: tc.namespace}).Return([]cpv1beta.NetworkPolicy{*testNetworkPolicy}).Times(1)
			ofc.EXPECT().GetNetworkPolicyFlowKeys(tc.name, tc.namespace).Return(testFlowKeys).Times(1)
			q.EXPECT().GetOpenflowClient().Return(ofc).Times(1)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(testFlowKeys))
			for i := range testFlowKeys {
				ovsctl.EXPECT().DumpMatchedFlow(testFlowKeys[i]).Return(testDumpFlows[i], nil).Times(1)
			}
		} else {
			npq.EXPECT().GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{SourceName: tc.name, Namespace: tc.namespace}).Return(nil).Times(1)
		}

		runHTTPTest(t, &tc, q)
	}

}

func TestTableFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := []testCase{
		{
			test:           "Table 80",
			query:          "?table=80",
			expectedStatus: http.StatusOK,
		},
		{
			test:           "Table IngressRule",
			query:          "?table=IngressRule",
			expectedStatus: http.StatusOK,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(1)
		ovsctl.EXPECT().DumpTableFlows(gomock.Any()).Return(testDumpFlows, nil).Times(1)

		runHTTPTest(t, &tc, q)
	}

}

func TestGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := []struct {
		testCase
		groupIDs     []uint32
		dumpedGroups []string
	}{
		{
			testCase: testCase{
				test:           "All groups",
				query:          "?groups=all",
				expectedStatus: http.StatusOK,
				resps:          testGroupResponses,
			},
			dumpedGroups: testDumpGroups,
		},
		{
			testCase: testCase{
				test:           "Group 1234",
				query:          "?groups=1234",
				expectedStatus: http.StatusOK,
				resps:          []Response{{"group1234"}},
			},
			groupIDs:     []uint32{1234},
			dumpedGroups: []string{"group1234"},
		},
		{
			testCase: testCase{
				test:           "Non-existing group 1234",
				query:          "?groups=1234",
				expectedStatus: http.StatusOK,
				resps:          []Response{},
			},
			groupIDs:     []uint32{1234},
			dumpedGroups: []string{""},
		},
		{
			testCase: testCase{
				test:           "Group 10, 100, and 1000",
				query:          "?groups=10,100,1000",
				expectedStatus: http.StatusOK,
				resps:          []Response{{"group10"}, {"group1000"}},
			},
			groupIDs:     []uint32{10, 100, 1000},
			dumpedGroups: []string{"group10", "", "group1000"},
		},
	}
	for _, tc := range testcases {
		ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		if tc.groupIDs == nil {
			// Get all.
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(1)
			ovsctl.EXPECT().DumpGroups().Return(tc.dumpedGroups, nil).Times(1)
		} else {
			// Get all.
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(tc.groupIDs))
			for i, id := range tc.groupIDs {
				ovsctl.EXPECT().DumpGroup(id).Return(tc.dumpedGroups[i], nil).Times(1)
			}
		}

		runHTTPTest(t, &tc.testCase, q)
	}
}

func runHTTPTest(t *testing.T, tc *testCase, aq agentquerier.AgentQuerier) {
	handler := HandleFunc(aq)
	req, err := http.NewRequest(http.MethodGet, tc.query, nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, tc.expectedStatus, recorder.Code, tc.test)

	if tc.expectedStatus == http.StatusOK {
		var received []Response
		err = json.Unmarshal(recorder.Body.Bytes(), &received)
		assert.Nil(t, err)
		if tc.resps != nil {
			assert.Equal(t, tc.resps, received)
		} else {
			assert.Equal(t, testResponses, received)
		}
	}
}
