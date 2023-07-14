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
	admissionv1 "k8s.io/api/admission/v1"
)

func TestHandlerForValidateFunc(t *testing.T) {
	testCases := []struct {
		name               string
		contentType        string
		admissionReview    *admissionv1.AdmissionReview
		expectedStatusCode int
	}{
		{
			name:        "validate successful",
			contentType: contentTypeJson,
			admissionReview: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{},
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "invalid content type",
			contentType: contentTypeHtml,
			admissionReview: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{},
			},
			expectedStatusCode: http.StatusUnsupportedMediaType,
		},
		{
			name:               "empty request body",
			contentType:        contentTypeJson,
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	var validateFn validateFunc = func(*admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
		return &admissionv1.AdmissionResponse{}
	}
	fn := HandlerForValidateFunc(validateFn)

	for _, tt := range testCases {
		resp := httptest.NewRecorder()
		var b []byte
		if tt.admissionReview != nil {
			b, _ = json.Marshal(tt.admissionReview)
		}
		request := httptest.NewRequest("", dummyTarget, bytes.NewReader(b))
		request.Header.Add("content-Type", tt.contentType)
		t.Run(tt.name, func(t *testing.T) {
			fn(resp, request)
			assert.Equal(t, tt.expectedStatusCode, resp.Code)
		})
	}
}
