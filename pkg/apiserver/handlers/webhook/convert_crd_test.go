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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	unstructuredTestData = map[string]interface{}{
		"kind":       "kind",
		"apiVersion": "apiVersion",
	}
	invalidTestData = map[string]interface{}{
		"test": "test",
	}
	unsupportedGVKTestData = &unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind":       "APIVersions",
			"apiVersion": "v1",
		},
	}

	rawData, _        = json.Marshal(unstructuredTestData)
	invalidRawData, _ = json.Marshal(invalidTestData)

	testConvertFunc = func(Object *unstructured.Unstructured, version string) (*unstructured.Unstructured, metav1.Status) {
		if Object.GetAPIVersion() == "" || Object.GetKind() == "" {
			return nil, metav1.Status{
				Status: metav1.StatusFailure,
			}
		}
		return &unstructured.Unstructured{}, metav1.Status{
			Status: metav1.StatusSuccess,
		}
	}

	dummyTarget = "http://127.0.0.1"
)

func TestHandleCRDConversion(t *testing.T) {
	testCases := []struct {
		name               string
		contentType        string
		requestBody        interface{}
		expectedStatusCode int
	}{
		{
			name:               "invalid content type",
			contentType:        contentTypeHtml,
			expectedStatusCode: http.StatusUnsupportedMediaType,
		},
		{
			name:               "invalid request body",
			contentType:        contentTypeJson,
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "unsupported GVK",
			contentType:        contentTypeJson,
			expectedStatusCode: http.StatusBadRequest,
			requestBody:        unsupportedGVKTestData,
		},
		{
			name:               "conversion successful",
			contentType:        contentTypeJson,
			expectedStatusCode: http.StatusOK,
			requestBody:        newTestConversionReview(rawData),
		},
	}

	fn := HandleCRDConversion(testConvertFunc)
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			b, _ := json.Marshal(tt.requestBody)
			request := httptest.NewRequest("", dummyTarget, bytes.NewReader(b))
			request.Header.Add("content-Type", tt.contentType)
			fn(resp, request)
			assert.Equal(t, tt.expectedStatusCode, resp.Code)
		})
	}
}

func TestDoConversionV1(t *testing.T) {
	testCases := []struct {
		name                   string
		requestBody            []byte
		convertFunc            func(Object *unstructured.Unstructured, version string) (*unstructured.Unstructured, metav1.Status)
		expectedResponseStatus string
	}{
		{
			name:                   "conversion successful",
			requestBody:            rawData,
			convertFunc:            testConvertFunc,
			expectedResponseStatus: metav1.StatusSuccess,
		},
		{
			name:                   "conversion failed",
			requestBody:            invalidRawData,
			convertFunc:            testConvertFunc,
			expectedResponseStatus: metav1.StatusFailure,
		},
	}

	for _, tt := range testCases {
		req := &apiextensionsv1.ConversionRequest{
			UID:               "uid",
			DesiredAPIVersion: "v1",
			Objects: []runtime.RawExtension{
				{
					Raw: tt.requestBody,
				},
			},
		}
		t.Run(tt.name, func(t *testing.T) {
			resp := doConversionV1(req, tt.convertFunc)
			assert.Equal(t, tt.expectedResponseStatus, resp.Result.Status)
		})
	}
}

func newTestConversionReview(data []byte) *apiextensionsv1.ConversionReview {
	return &apiextensionsv1.ConversionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConversionReview",
			APIVersion: "apiextensions.k8s.io/v1",
		},
		Request: &apiextensionsv1.ConversionRequest{
			UID:               "uid",
			DesiredAPIVersion: "v1",
			Objects: []runtime.RawExtension{
				{
					Raw: data,
				},
			},
		},
	}
}
