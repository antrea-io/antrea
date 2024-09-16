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

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/apis"
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
	testResponses      = []apis.OVSFlowResponse{{Flow: "flow1"}, {Flow: "flow2"}}
	testGroupResponses = []apis.OVSFlowResponse{{Flow: "group1"}, {Flow: "group2"}}

	testNetworkPolicy = &cpv1beta.NetworkPolicy{
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Type:      cpv1beta.K8sNetworkPolicy,
			Namespace: "default",
		},
	}
	testANNP = &cpv1beta.NetworkPolicy{
		SourceRef: &cpv1beta.NetworkPolicyReference{
			Type:      cpv1beta.AntreaNetworkPolicy,
			Namespace: "default",
		},
	}
)

type testCase struct {
	testName           string
	name               string
	namespace          string
	policyType         cpv1beta.NetworkPolicyType
	policyTypeToReturn cpv1beta.NetworkPolicyType
	query              string
	expectedStatus     int
	resps              []apis.OVSFlowResponse
}

func TestBadRequests(t *testing.T) {
	badRequests := map[string]string{
		"Pod only":                  "?pod=pod1",
		"Service only":              "?service=svc1",
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
	testInterface := &interfacestore.InterfaceConfig{InterfaceName: "interface0"}
	testcases := []testCase{
		{
			testName:       "Existing Pod",
			name:           "pod1",
			namespace:      "ns1",
			query:          "?pod=pod1&&namespace=ns1",
			expectedStatus: http.StatusOK,
		},
		{
			testName:       "Non-existing Pod",
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
	testcases := []testCase{
		{
			testName:       "Existing Service",
			name:           "svc1",
			namespace:      "ns1",
			query:          "?service=svc1&&namespace=ns1",
			expectedStatus: http.StatusOK,
			resps:          append(testResponses, testGroupResponses...),
		},
		{
			testName:       "Non-existing Service",
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
		q.EXPECT().GetProxier().Return(p).Times(2)

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

func TestNetworkPolicyFlowsSuccess(t *testing.T) {
	testcases := []testCase{
		{
			testName:       "Existing NetworkPolicy",
			name:           "np1",
			namespace:      "default",
			policyType:     cpv1beta.K8sNetworkPolicy,
			query:          "?networkpolicy=np1&namespace=default&type=K8sNP",
			expectedStatus: http.StatusOK,
		},
		{
			testName:       "Existing ACNP",
			name:           "acnp1",
			policyType:     cpv1beta.AntreaClusterNetworkPolicy,
			query:          "?networkpolicy=acnp1&type=ACNP",
			expectedStatus: http.StatusOK,
		},
		{
			testName:       "Existing ANNP",
			name:           "annp1",
			namespace:      "default",
			policyType:     cpv1beta.AntreaNetworkPolicy,
			query:          "?networkpolicy=annp1&namespace=default&type=ANNP",
			expectedStatus: http.StatusOK,
		},
		{
			testName:           "Existing ANNP - no type provided",
			name:               "annp1",
			namespace:          "default",
			query:              "?networkpolicy=annp1&namespace=default",
			policyTypeToReturn: cpv1beta.AntreaNetworkPolicy,
			expectedStatus:     http.StatusOK,
		},
		{
			testName:       "Existing ANP",
			name:           "anp1",
			policyType:     cpv1beta.AdminNetworkPolicy,
			query:          "?networkpolicy=anp1&type=ANP",
			expectedStatus: http.StatusOK,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			npq := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			q := aqtest.NewMockAgentQuerier(ctrl)
			ofc := oftest.NewMockClient(ctrl)
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			npFilter := &querier.NetworkPolicyQueryFilter{
				SourceName: tc.name,
				Namespace:  tc.namespace,
				SourceType: tc.policyType,
			}
			q.EXPECT().GetNetworkPolicyInfoQuerier().Return(npq).Times(1)
			if tc.policyTypeToReturn == "" {
				tc.policyTypeToReturn = tc.policyType
			}
			npq.EXPECT().GetNetworkPolicies(npFilter).Return([]cpv1beta.NetworkPolicy{
				{
					SourceRef: &cpv1beta.NetworkPolicyReference{
						Type:      tc.policyTypeToReturn,
						Namespace: tc.namespace,
						Name:      tc.name,
					},
				},
			}).Times(1)
			ofc.EXPECT().GetNetworkPolicyFlowKeys(tc.name, tc.namespace, tc.policyTypeToReturn).Return(testFlowKeys).Times(1)
			q.EXPECT().GetOpenflowClient().Return(ofc).Times(1)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(len(testFlowKeys))
			for i := range testFlowKeys {
				ovsctl.EXPECT().DumpMatchedFlow(testFlowKeys[i]).Return(testDumpFlows[i], nil).Times(1)
			}
			runHTTPTest(t, &tc, q)
		})
	}
}

func TestNetworkPolicyFlowsBadRequest(t *testing.T) {
	testcases := []testCase{
		{
			testName:       "ACNP bad request - namespace should not be provided",
			name:           "acnp2",
			policyType:     cpv1beta.AntreaClusterNetworkPolicy,
			query:          "?networkpolicy=acnp2&type=ACNP&namespace=default",
			expectedStatus: http.StatusBadRequest,
		},
		{
			testName:       "ANNP bad request - namespace should be provided",
			name:           "annp2",
			policyType:     cpv1beta.AntreaNetworkPolicy,
			query:          "?networkpolicy=annp2&type=ANNP",
			expectedStatus: http.StatusBadRequest,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := aqtest.NewMockAgentQuerier(ctrl)
			runHTTPTest(t, &tc, q)
		})
	}
}

func TestNetworkPolicyFlowsPolicyAmbiguousQuery(t *testing.T) {
	tc := &testCase{
		testName:       "Ambiguous query",
		name:           "np-annp-same-name",
		namespace:      "ns1",
		query:          "?networkpolicy=np-annp-same-name&namespace=ns1",
		expectedStatus: http.StatusBadRequest,
	}
	ctrl := gomock.NewController(t)
	q := aqtest.NewMockAgentQuerier(ctrl)
	// Simulates an ambiguous query where more than one matching NP is returned
	npq := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	q.EXPECT().GetNetworkPolicyInfoQuerier().Return(npq).Times(1)
	npFilter := &querier.NetworkPolicyQueryFilter{
		SourceName: tc.name,
		Namespace:  tc.namespace,
		SourceType: tc.policyType,
	}
	npq.EXPECT().GetNetworkPolicies(npFilter).Return([]cpv1beta.NetworkPolicy{*testNetworkPolicy, *testANNP}).Times(1)
	runHTTPTest(t, tc, q)
}

func TestNetworkPolicyFlowsPolicyNotFound(t *testing.T) {
	tc := &testCase{
		testName:       "Non-existing NetworkPolicy",
		name:           "np1",
		namespace:      "ns1",
		policyType:     cpv1beta.K8sNetworkPolicy,
		query:          "?networkpolicy=np1&namespace=ns1&type=K8sNP",
		expectedStatus: http.StatusNotFound,
	}
	ctrl := gomock.NewController(t)
	q := aqtest.NewMockAgentQuerier(ctrl)
	npq := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	q.EXPECT().GetNetworkPolicyInfoQuerier().Return(npq).Times(1)
	npFilter := &querier.NetworkPolicyQueryFilter{
		SourceName: tc.name,
		Namespace:  tc.namespace,
		SourceType: tc.policyType,
	}
	npq.EXPECT().GetNetworkPolicies(npFilter).Return(nil).Times(1)
	runHTTPTest(t, tc, q)
}

func TestTableFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	getFlowTableName = mockGetFlowTableName
	getFlowTableID = mockGetFlowTableID
	testcases := []testCase{
		{
			testName:       "Table 80",
			query:          "?table=80",
			expectedStatus: http.StatusOK,
		},
		{
			testName:       "Table IngressRule",
			query:          "?table=IngressRule",
			expectedStatus: http.StatusOK,
		},
	}
	for i := range testcases {
		tc := testcases[i]
		t.Run(tc.testName, func(t *testing.T) {
			ovsctl := ovsctltest.NewMockOVSCtlClient(ctrl)
			q := aqtest.NewMockAgentQuerier(ctrl)
			q.EXPECT().GetOVSCtlClient().Return(ovsctl).Times(1)
			ovsctl.EXPECT().DumpTableFlows(gomock.Any()).Return(testDumpFlows, nil).Times(1)

			runHTTPTest(t, &tc, q)
		})
	}
}

func TestTableNamesOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	getFlowTableList = mockGetTableList
	tc := testCase{
		testName:       "Get table names only",
		query:          "?table-names-only",
		expectedStatus: http.StatusOK,
		resps:          []apis.OVSFlowResponse{{Flow: "table0"}, {Flow: "table1"}},
	}
	q := aqtest.NewMockAgentQuerier(ctrl)
	runHTTPTest(t, &tc, q)
}

func mockGetFlowTableName(id uint8) string {
	if id == 80 {
		return "IngressRule"
	}
	return ""
}

func mockGetFlowTableID(tableName string) uint8 {
	if tableName == "IngressRule" {
		return 80
	}
	return binding.TableIDAll
}

func mockGetTableList() []binding.Table {
	return []binding.Table{
		binding.NewOFTable(0, "table0", 0, 0, 0),
		binding.NewOFTable(0, "table1", 0, 0, 0),
	}
}

func TestGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	testcases := []struct {
		testCase
		groupIDs     []uint32
		dumpedGroups []string
	}{
		{
			testCase: testCase{
				testName:       "All groups",
				query:          "?groups=all",
				expectedStatus: http.StatusOK,
				resps:          testGroupResponses,
			},
			dumpedGroups: testDumpGroups,
		},
		{
			testCase: testCase{
				testName:       "Group 1234",
				query:          "?groups=1234",
				expectedStatus: http.StatusOK,
				resps:          []apis.OVSFlowResponse{{Flow: "group1234"}},
			},
			groupIDs:     []uint32{1234},
			dumpedGroups: []string{"group1234"},
		},
		{
			testCase: testCase{
				testName:       "Non-existing group 1234",
				query:          "?groups=1234",
				expectedStatus: http.StatusOK,
				resps:          []apis.OVSFlowResponse{},
			},
			groupIDs:     []uint32{1234},
			dumpedGroups: []string{""},
		},
		{
			testCase: testCase{
				testName:       "Group 10, 100, and 1000",
				query:          "?groups=10,100,1000",
				expectedStatus: http.StatusOK,
				resps:          []apis.OVSFlowResponse{{Flow: "group10"}, {Flow: "group1000"}},
			},
			groupIDs:     []uint32{10, 100, 1000},
			dumpedGroups: []string{"group10", "", "group1000"},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.testName, func(t *testing.T) {
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
		})
	}
}

func runHTTPTest(t *testing.T, tc *testCase, aq agentquerier.AgentQuerier) {
	handler := HandleFunc(aq)
	req, err := http.NewRequest(http.MethodGet, tc.query, nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, tc.expectedStatus, recorder.Code, tc.testName)

	if tc.expectedStatus == http.StatusOK {
		var received []apis.OVSFlowResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &received)
		assert.Nil(t, err)
		if tc.resps != nil {
			assert.Equal(t, tc.resps, received)
		} else {
			assert.Equal(t, testResponses, received)
		}
	}
}
