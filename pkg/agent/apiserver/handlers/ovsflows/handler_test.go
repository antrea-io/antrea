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

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	interfacestoretest "github.com/vmware-tanzu/antrea/pkg/agent/interfacestore/testing"
	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	proxytest "github.com/vmware-tanzu/antrea/pkg/agent/proxy/testing"
	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	aqtest "github.com/vmware-tanzu/antrea/pkg/agent/querier/testing"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	ovsctltest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl/testing"
	"github.com/vmware-tanzu/antrea/pkg/querier"
	queriertest "github.com/vmware-tanzu/antrea/pkg/querier/testing"
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
	dumpGroups     bool
}

func TestBadRequests(t *testing.T) {
	badRequests := map[string]string{
		"Pod only":                  "?pod=pod1",
		"Service only":              "?service=svc1",
		"NetworkPolicy only":        "?networkpolicy=np1",
		"Namespace only":            "?namespace=ns1",
		"Pod and NetworkPolicy":     "?pod=pod1&&networkpolicy=np1",
		"Pod and Table":             "?pod=pod1&&table=0",
		"Non-existing table number": "?table=123",
		"Non-existing table name":   "?table=notexist",
		"Too big table number":      "?table=256",
		"Invalid table number":      "?table=0classification",
		"Invalid table name":        "?table=classification0",
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
			dumpGroups:     true,
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
				ovsctl.EXPECT().DumpGroup(int(g)).Return(testDumpGroups[i], nil).Times(1)
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
		if tc.dumpGroups {
			assert.Equal(t, append(testResponses, testGroupResponses...), received)
		} else {
			assert.Equal(t, testResponses, received)
		}
	}
}
