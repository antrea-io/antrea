// Copyright 2019 Antrea Authors
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

package handlers

import (
	"encoding/json"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vmware-tanzu/antrea/pkg/controller/apiserver/handlers/endpoint"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
	queriermock "github.com/vmware-tanzu/antrea/pkg/querier/testing"
	"net/http"
	"net/http/httptest"
	"testing"
)

type TestCase struct {
	// query arguments sent to handler function
	handlerArgs     []string
	expectedStatus  int
	// expected result written by handler function
	expectedContent endpoint.Policies
	// arguments of call to mock
	argsMock       []string
	// results of call to mock
	appliedMock    []antreatypes.NetworkPolicy
	egressMock     []antreatypes.NetworkPolicy
	ingressMock    []antreatypes.NetworkPolicy
}

var responses = []endpoint.Policies{
	{
		Applied: []antreatypes.NetworkPolicy{},
		Egress: []antreatypes.NetworkPolicy{},
		Ingress: []antreatypes.NetworkPolicy{},
	},
	{
		Applied: []antreatypes.NetworkPolicy{
			{
				SpanMeta:  antreatypes.SpanMeta{},
				Name:      "policy1",
			},
		},
		Egress: []antreatypes.NetworkPolicy{},
		Ingress: []antreatypes.NetworkPolicy{},
	},
	{
		Applied: []antreatypes.NetworkPolicy{
			{
				SpanMeta:  antreatypes.SpanMeta{},
				Name:      "policy1",
			},
			{
				SpanMeta:  antreatypes.SpanMeta{},
				Name:      "policy2",
			},
		},
	},
}

func TestIncompleteOrInvalidArguments(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	// sample selector arguments (right now, only supports podname and namespace)
	podName, namespace := "podName", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with empty list given no name and no namespace": {
			handlerArgs:           []string{"", ""},
			expectedStatus:  http.StatusOK,
			expectedContent: responses[0],
			argsMock: []string{"", ""},
			appliedMock: make([]antreatypes.NetworkPolicy, 0),
			egressMock: make([]antreatypes.NetworkPolicy, 0),
			ingressMock: make([]antreatypes.NetworkPolicy, 0),
		},
		"Responds with empty list given no name": {
			handlerArgs:           []string{namespace, ""},
			expectedStatus:  http.StatusOK,
			expectedContent: responses[0],
			argsMock: []string{namespace, ""},
			appliedMock: make([]antreatypes.NetworkPolicy, 0),
			egressMock: make([]antreatypes.NetworkPolicy, 0),
			ingressMock: make([]antreatypes.NetworkPolicy, 0),
		},
		"Responds with empty list given no namespace": {
			handlerArgs:           []string{"", podName},
			expectedStatus:  http.StatusOK,
			expectedContent: responses[0],
			argsMock: []string{"", podName},
			appliedMock: make([]antreatypes.NetworkPolicy, 0),
			egressMock: make([]antreatypes.NetworkPolicy, 0),
			ingressMock: make([]antreatypes.NetworkPolicy, 0),
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

func TestSinglePolicyResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	// sample selector arguments (right now, only supports podName and namespace)
	podName, namespace := "podName", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with list of single element": {
			handlerArgs:           []string{namespace, podName},
			expectedStatus:  http.StatusOK,
			expectedContent: responses[1],
			argsMock: []string{namespace, podName},
			appliedMock: []antreatypes.NetworkPolicy{
				{
					SpanMeta:  antreatypes.SpanMeta{},
					Name:      "policy1",
				},
			},
			egressMock: make([]antreatypes.NetworkPolicy, 0),
			ingressMock: make([]antreatypes.NetworkPolicy, 0),
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

func TestMultiPolicyResponse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	// sample selector arguments (right now, only supports podName and namespace)
	podName, namespace := "podName", "namespace"
	// outline test cases with expected behavior
	testCases := map[string]TestCase{
		"Responds with list of single element": {
			handlerArgs:           []string{namespace, podName},
			expectedStatus:  http.StatusOK,
			expectedContent: responses[2],
			argsMock: []string{namespace, podName},
			appliedMock: []antreatypes.NetworkPolicy{
				{
					SpanMeta:  antreatypes.SpanMeta{},
					Name:      "policy1",
				},
				{
					SpanMeta:   antreatypes.SpanMeta{},
					Name:      "policy2",
				},
			},
			egressMock: make([]antreatypes.NetworkPolicy, 0),
			ingressMock: make([]antreatypes.NetworkPolicy, 0),
		},
	}

	evaluateTestCases(testCases, mockCtrl, t)

}

func evaluateTestCases(testCases map[string]TestCase, mockCtrl *gomock.Controller, t *testing.T) {
	for k, tc := range testCases {
		// create mock querier with expected behavior outlined in testCase
		mockQuerier := queriermock.NewMockControllerNetworkPolicyInfoQuerier(mockCtrl)
		println("hello")
		println(tc.argsMock[0])
		mockQuerier.EXPECT().GetNetworkPolicies(tc.argsMock[0], tc.argsMock[1]).Return(tc.appliedMock, tc.egressMock,
			tc.ingressMock)
		// initialize handler with mockQuerier
		handler := endpoint.HandleFunc(mockQuerier)
		// create http using handlerArgs and serve the http request
		req, err := http.NewRequest(http.MethodGet, genHTTPRequest(tc.handlerArgs), nil)
		assert.Nil(t, err)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		// check http status
		assert.Equal(t, tc.expectedStatus, recorder.Code, k)
		// check response is expected
		var received endpoint.Policies
		err = json.Unmarshal(recorder.Body.Bytes(), &received)
		assert.Nil(t, err)
		assert.Equal(t, tc.expectedContent, received)
	}
}

func genHTTPRequest(args []string) string {
	return "?name=" + args[1] + "&&namespace=" + args[0]
}

func genSampleNetworkPolicies() (np1 antreatypes.NetworkPolicy, np2 antreatypes.NetworkPolicy,
	np3 antreatypes.NetworkPolicy) {
	np1 = antreatypes.NetworkPolicy{
		SpanMeta:        antreatypes.SpanMeta{},
		UID:             "np1",
		Name:            "np1",
	}
	np2 = antreatypes.NetworkPolicy{
		SpanMeta:        antreatypes.SpanMeta{},
		UID:             "np2",
		Name:            "np2",
	}
	np3 = antreatypes.NetworkPolicy{
		SpanMeta:        antreatypes.SpanMeta{},
		UID:             "np3",
		Name:            "np3",
	}
	return
}
