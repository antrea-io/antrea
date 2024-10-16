// Copyright 2024 Antrea Authors.
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

package ftp

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFTPUploadUrl(t *testing.T) {
	cases := []struct {
		url           string
		expectedError string
		expectedURL   url.URL
	}{
		{
			url: "sftp://127.0.0.1:22/path",
			expectedURL: url.URL{
				Scheme: "sftp",
				Host:   "127.0.0.1:22",
				Path:   "/path",
			},
		},
		{
			url:           "https://127.0.0.1:22/root/supportbundle",
			expectedError: "not sftp protocol",
		},
	}

	for _, tc := range cases {
		uploadUrl, err := ParseFTPUploadUrl(tc.url)
		if tc.expectedError == "" {
			assert.NoError(t, err)
			if !reflect.DeepEqual(tc.expectedURL, *uploadUrl) {
				t.Errorf("expected %v, got %v", tc.expectedURL, *uploadUrl)

			}
		} else {
			assert.Equal(t, tc.expectedError, err.Error())
		}
	}

}
