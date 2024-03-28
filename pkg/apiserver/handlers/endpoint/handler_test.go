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

package endpoint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apiserver/apis"
	queriermock "antrea.io/antrea/pkg/controller/networkpolicy/testing"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

type TestCase struct {
	// query arguments sent to handler function
	handlerRequest string
	expectedStatus int
	// expected result written by handler function
	expectedResponse *apis.EndpointQueryResponse

	// arguments of call to mock
	argsMock []string
	// results of call to mock
	mockQueryResponse *antreatypes.EndpointNetworkPolicyRules
}

// TestIncompleteArguments tests how the handler function responds when the user passes in a query command
// with incomplete arguments (for now, missing pod or namespace)
func TestIncompleteArguments(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	// sample selector arguments (right now, only supports podname and namespace)
	namespace := "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with error given no name and no namespace": {
			handlerRequest: "",
			expectedStatus: http.StatusBadRequest,
			argsMock:       []string{"", ""},
		},
		"Responds with error given no name": {
			handlerRequest: "?namespace=namespace",
			expectedStatus: http.StatusBadRequest,
			argsMock:       []string{namespace, ""},
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

// TestInvalidArguments tests how the handler function responds when the user passes in a selector which does not select
// any existing endpoint
func TestInvalidArguments(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	// sample selector arguments (right now, only supports podname and namespace)
	pod, namespace := "pod", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with error given no invalid selection": {
			handlerRequest:    "?namespace=namespace&pod=pod",
			expectedStatus:    http.StatusNotFound,
			argsMock:          []string{namespace, pod},
			mockQueryResponse: nil,
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

// TestSinglePolicyResponse tests how the handler function responds when the user passes in an endpoint with a
// single policy response
func TestSinglePolicyResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	// sample selector arguments (right now, only supports podName and namespace)
	pod, namespace := "pod", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with list of single element": {
			handlerRequest: "?namespace=namespace&pod=pod",
			expectedStatus: http.StatusOK,
			expectedResponse: &apis.EndpointQueryResponse{Endpoints: []apis.Endpoint{
				{
					AppliedPolicies: []v1beta2.NetworkPolicyReference{
						{Name: "policy1"},
					},
					IngressSrcRules: []apis.Rule{
						{PolicyRef: v1beta2.NetworkPolicyReference{Name: "policy2"}},
					},
				},
			},
			},
			argsMock: []string{namespace, pod},
			mockQueryResponse: &antreatypes.EndpointNetworkPolicyRules{
				AppliedPolicies: []*antreatypes.NetworkPolicy{
					{SourceRef: &controlplane.NetworkPolicyReference{Name: "policy1"}},
				},
				EndpointAsIngressSrcRules: []*antreatypes.RuleInfo{
					{
						Policy: &antreatypes.NetworkPolicy{
							SourceRef: &controlplane.NetworkPolicyReference{Name: "policy2"},
						},
						Index: 0,
						Rule: &controlplane.NetworkPolicyRule{
							Direction: controlplane.DirectionIn,
						},
					},
				},
			},
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

// TestMultiPolicyResponse tests how the handler function responds when the user passes in an endpoint with
// multiple policy responses
func TestMultiPolicyResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	// sample selector arguments (right now, only supports podName and namespace)
	pod, namespace := "pod", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with list of single element": {
			handlerRequest: "?namespace=namespace&pod=pod",
			expectedStatus: http.StatusOK,
			expectedResponse: &apis.EndpointQueryResponse{Endpoints: []apis.Endpoint{
				{
					AppliedPolicies: []v1beta2.NetworkPolicyReference{
						{Name: "policy1"}, {Name: "policy2"},
					},
				},
			},
			},
			argsMock: []string{namespace, pod},
			mockQueryResponse: &antreatypes.EndpointNetworkPolicyRules{
				AppliedPolicies: []*antreatypes.NetworkPolicy{
					{SourceRef: &controlplane.NetworkPolicyReference{Name: "policy1"}},
					{SourceRef: &controlplane.NetworkPolicyReference{Name: "policy2"}},
				},
			},
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

func evaluateTestCases(testCases map[string]TestCase, mockCtrl *gomock.Controller, t *testing.T) {
	for _, tc := range testCases {
		// create mock querier with expected behavior outlined in testCase
		mockQuerier := queriermock.NewMockEndpointQuerier(mockCtrl)
		if tc.expectedStatus != http.StatusBadRequest {
			mockQuerier.EXPECT().QueryNetworkPolicyRules(tc.argsMock[0], tc.argsMock[1]).Return(tc.mockQueryResponse, nil)
		}
		// initialize handler with mockQuerier
		handler := HandleFunc(mockQuerier)
		// create http using handlerArgs and serve the http request
		req, err := http.NewRequest(http.MethodGet, tc.handlerRequest, nil)
		assert.Nil(t, err)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, tc.expectedStatus, recorder.Code)
		if tc.expectedStatus != http.StatusOK {
			return
		}
		// check response is expected
		var received apis.EndpointQueryResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &received)
		assert.Nil(t, err)
		for i, policy := range tc.expectedResponse.Endpoints[0].AppliedPolicies {
			assert.Equal(t, policy.Name, received.Endpoints[0].AppliedPolicies[i].Name)
		}
		for i, rule := range tc.expectedResponse.Endpoints[0].IngressSrcRules {
			assert.Equal(t, rule.PolicyRef.Name, received.Endpoints[0].IngressSrcRules[i].PolicyRef.Name)
		}
		for i, rule := range tc.expectedResponse.Endpoints[0].EgressDstRules {
			assert.Equal(t, rule.PolicyRef.Name, received.Endpoints[0].EgressDstRules[i].PolicyRef.Name)
		}
	}
}
