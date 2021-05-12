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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"antrea.io/antrea/pkg/controller/networkpolicy"
	queriermock "antrea.io/antrea/pkg/controller/networkpolicy/testing"
)

type TestCase struct {
	// query arguments sent to handler function
	handlerRequest string
	expectedStatus int
	// expected result written by handler function
	expectedContent response

	// arguments of call to mock
	argsMock []string
	// results of call to mock
	mockQueryResponse response
}

type response struct {
	response *networkpolicy.EndpointQueryResponse
	error    error
}

var responses = []response{
	{
		response: &networkpolicy.EndpointQueryResponse{Endpoints: nil},
		error:    errors.NewNotFound(v1.Resource("pod"), "pod"),
	},
	{
		response: &networkpolicy.EndpointQueryResponse{Endpoints: []networkpolicy.Endpoint{
			{
				Policies: []networkpolicy.Policy{
					{
						PolicyRef: networkpolicy.PolicyRef{Name: "policy1"},
					},
				},
			},
		},
		},
		error: nil,
	},
	{
		response: &networkpolicy.EndpointQueryResponse{Endpoints: []networkpolicy.Endpoint{
			{
				Policies: []networkpolicy.Policy{
					{
						PolicyRef: networkpolicy.PolicyRef{Name: "policy1"},
					},
					{
						PolicyRef: networkpolicy.PolicyRef{Name: "policy2"},
					},
				},
			},
		},
		},
		error: nil,
	},
}

// TestIncompleteArguments tests how the handler function responds when the user passes in a query command
// with incomplete arguments (for now, missing pod or namespace)
func TestIncompleteArguments(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
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
	defer mockCtrl.Finish()
	// sample selector arguments (right now, only supports podname and namespace)
	pod, namespace := "pod", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with error given no invalid selection": {
			handlerRequest: "?namespace=namespace&pod=pod",
			expectedStatus: http.StatusNotFound,
			argsMock:       []string{namespace, pod},
			mockQueryResponse: response{
				response: nil,
				error:    nil,
			},
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

// TestSinglePolicyResponse tests how the handler function responds when the user passes in a endpoint with a
// single policy response
func TestSinglePolicyResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	// sample selector arguments (right now, only supports podName and namespace)
	pod, namespace := "pod", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with list of single element": {
			handlerRequest:  "?namespace=namespace&pod=pod",
			expectedStatus:  http.StatusOK,
			expectedContent: responses[1],
			argsMock:        []string{namespace, pod},
			mockQueryResponse: response{
				response: &networkpolicy.EndpointQueryResponse{Endpoints: []networkpolicy.Endpoint{
					{
						Policies: []networkpolicy.Policy{
							{
								PolicyRef: networkpolicy.PolicyRef{Name: "policy1"},
							},
						},
					},
				},
				},
				error: nil,
			},
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

// TestMultiPolicyResponse tests how the handler function responds when the user passes in a endpoint with
// multiple policy responses
func TestMultiPolicyResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	// sample selector arguments (right now, only supports podName and namespace)
	pod, namespace := "pod", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with list of single element": {
			handlerRequest:  "?namespace=namespace&pod=pod",
			expectedStatus:  http.StatusOK,
			expectedContent: responses[2],
			argsMock:        []string{namespace, pod},
			mockQueryResponse: response{
				response: &networkpolicy.EndpointQueryResponse{Endpoints: []networkpolicy.Endpoint{
					{
						Policies: []networkpolicy.Policy{
							{
								PolicyRef: networkpolicy.PolicyRef{Name: "policy1"},
							},
							{
								PolicyRef: networkpolicy.PolicyRef{Name: "policy2"},
							},
						},
					},
				},
				},
				error: nil,
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
			mockQuerier.EXPECT().QueryNetworkPolicies(tc.argsMock[0], tc.argsMock[1]).Return(tc.mockQueryResponse.response, tc.mockQueryResponse.error)
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
		var received networkpolicy.EndpointQueryResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &received)
		assert.Nil(t, err)
		for i, policy := range tc.expectedContent.response.Endpoints[0].Policies {
			assert.Equal(t, policy.Name, received.Endpoints[0].Policies[i].Name)
		}
	}
}
