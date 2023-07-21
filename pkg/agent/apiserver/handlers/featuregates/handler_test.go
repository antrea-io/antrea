// Copyright 2021 Antrea Authors
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

package featuregates

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/features"
)

func Test_getStatus(t *testing.T) {
	tests := []struct {
		name   string
		status bool
		want   string
	}{
		{
			name:   "Enabled case",
			status: true,
			want:   "Enabled",
		},
		{
			name:   "Disabled case",
			status: false,
			want:   "Disabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getStatus(tt.status); got != tt.want {
				t.Errorf("getStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleFunc(t *testing.T) {
	tests := []struct {
		name           string
		expectedStatus int
	}{
		{
			name:           "good path",
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := HandleFunc()
			req, err := http.NewRequest(http.MethodGet, "", nil)
			assert.Nil(t, err)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			if tt.expectedStatus != http.StatusOK {
				return
			}
			var resp []Response
			err = json.Unmarshal(recorder.Body.Bytes(), &resp)
			fmt.Println(resp)
			assert.Nil(t, err)
			for _, v := range resp {
				for n, f := range features.DefaultAntreaFeatureGates {
					if v.Name == string(n) {
						assert.Equal(t, v.Status, getStatus(f.Default))
						assert.Equal(t, v.Version, string(f.PreRelease))
					}
				}
			}
		})
	}
}
