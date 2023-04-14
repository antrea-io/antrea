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

package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"

	"antrea.io/antrea/pkg/controller/networkpolicy"
)

var (
	ar = &admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "uid",
		},
	}

	requestBody, _ = json.Marshal(ar)
)

func TestHandleMutationNetworkPolicy(t *testing.T) {
	testCases := []struct {
		name               string
		contentType        string
		requestBody        []byte
		expectedStatusCode int
	}{
		{
			name:               "empty request body",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "invalid content type",
			expectedStatusCode: http.StatusUnsupportedMediaType,
			requestBody:        requestBody,
			contentType:        contentTypeHtml,
		},
		{
			name:               "run successfully",
			requestBody:        requestBody,
			expectedStatusCode: http.StatusOK,
			contentType:        contentTypeJson,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			request := httptest.NewRequest("", dummyTarget, bytes.NewReader(tt.requestBody))
			request.Header.Add("content-Type", tt.contentType)
			npMutator := &networkpolicy.NetworkPolicyMutator{}
			fn := HandleMutationNetworkPolicy(npMutator)
			fn(resp, request)
			assert.Equal(t, tt.expectedStatusCode, resp.Code)
		})
	}
}
