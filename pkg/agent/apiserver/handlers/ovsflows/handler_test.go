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
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	aqtest "github.com/vmware-tanzu/antrea/pkg/agent/querier/testing"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	ovsctltest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl/testing"
	queriertest "github.com/vmware-tanzu/antrea/pkg/querier/testing"
)

var (
	testFlowKeys    = []string{"flowKey1", "flowKey2"}
	testDumpResults = []string{"flow1", "flow2"}
	testResponses   = []Response{{"flow1"}, {"flow2"}}
)

type testCase struct {
	test           string
	name           string
	namespace      string
	query          string
	expectedStatus int
}

func TestBadRequests(t *testing.T) {
	badRequests := map[string]string{
		"Pod only":                  "?pod=pod1",
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
	for _, tc := range testcases {
		i := interfacestoretest.NewMockInterfaceStore(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetInterfaceStore().Return(i).Times(1)

		if tc.expectedStatus != http.StatusNotFound {
			ofc := oftest.NewMockClient(ctrl)
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			i.EXPECT().GetContainerInterface(tc.name, tc.namespace).Return(testInterface, true).Times(1)
			ofc.EXPECT().GetPodFlowKeys(testInterface.InterfaceName).Return(testFlowKeys).Times(1)
			q.EXPECT().GetOpenflowClient().Return(ofc).Times(1)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(testFlowKeys))
			for i := range testFlowKeys {
				ovsctl.EXPECT().DumpMatchedFlow(testFlowKeys[i]).Return(testDumpResults[i], nil).Times(1)
			}
		} else {
			i.EXPECT().GetContainerInterface(tc.name, tc.namespace).Return(nil, false).Times(1)
		}

		runHTTPTest(t, &tc, q)
	}
}

func TestNetworkPolicyFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testNetworkPolicy := &networkingv1beta1.NetworkPolicy{}

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
	for _, tc := range testcases {
		npq := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetNetworkPolicyInfoQuerier().Return(npq).Times(1)

		if tc.expectedStatus != http.StatusNotFound {
			ofc := oftest.NewMockClient(ctrl)
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			npq.EXPECT().GetNetworkPolicy(tc.name, tc.namespace).Return(testNetworkPolicy).Times(1)
			ofc.EXPECT().GetNetworkPolicyFlowKeys(tc.name, tc.namespace).Return(testFlowKeys).Times(1)
			q.EXPECT().GetOpenflowClient().Return(ofc).Times(1)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(testFlowKeys))
			for i := range testFlowKeys {
				ovsctl.EXPECT().DumpMatchedFlow(testFlowKeys[i]).Return(testDumpResults[i], nil).Times(1)
			}
		} else {
			npq.EXPECT().GetNetworkPolicy(tc.name, tc.namespace).Return(nil).Times(1)
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
	for _, tc := range testcases {
		ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
		q := aqtest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(1)
		ovsctl.EXPECT().DumpTableFlows(gomock.Any()).Return(testDumpResults, nil).Times(1)

		runHTTPTest(t, &tc, q)
	}

}

func runHTTPTest(t *testing.T, tc *testCase, aq querier.AgentQuerier) {
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
		assert.Equal(t, testResponses, received)
	}
}
