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
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vmware-tanzu/antrea/pkg/antctl/mock"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

// TestVersion verifies the functionality of the Version handler.
func TestVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := map[string]struct {
		version        string
		expectedOutput string
		statusCode     int
	}{
		"only agent version": {
			version:        "Antrea 0.0.1",
			expectedOutput: "{\"agentVersion\":\"Antrea 0.0.1\"}\n",
			statusCode:     http.StatusOK,
		},
		"no version": {
			version:        "",
			expectedOutput: "{}\n",
			statusCode:     http.StatusOK,
		},
	}
	for k, tc := range testcases {
		q := mock.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetVersion().Return(tc.version)
		func() {
			s := new(Version)
			ts := httptest.NewServer(s.Handler(q, nil))
			defer ts.Close()

			resp, err := http.Get(ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			var o bytes.Buffer
			io.Copy(&o, resp.Body)
			assert.Equal(t, tc.statusCode, resp.StatusCode, k)
			assert.Equal(t, tc.expectedOutput, o.String(), k)
		}()
	}
}
