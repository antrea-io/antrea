// Copyright 2025 Antrea Authors
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

package fqdncache

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/querier"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

func TestFqdnCacheQuery(t *testing.T) {
	expirationTime := time.Now().Add(1 * time.Hour).UTC()
	tests := []struct {
		name                 string
		filteredCacheEntries []types.DnsCacheEntry
		expectedResponse     []apis.FQDNCacheResponse
	}{
		{
			name: "FQDN cache exists - multiple addresses multiple domains",
			filteredCacheEntries: []types.DnsCacheEntry{
				{
					FQDNName:       "example.com",
					IPAddress:      net.ParseIP("10.0.0.1"),
					ExpirationTime: expirationTime,
				},
				{
					FQDNName:       "foo.com",
					IPAddress:      net.ParseIP("10.0.0.4"),
					ExpirationTime: expirationTime,
				},
				{
					FQDNName:       "bar.com",
					IPAddress:      net.ParseIP("10.0.0.5"),
					ExpirationTime: expirationTime,
				},
			},
			expectedResponse: []apis.FQDNCacheResponse{
				{
					FQDNName:       "example.com",
					IPAddress:      "10.0.0.1",
					ExpirationTime: expirationTime,
				},
				{
					FQDNName:       "foo.com",
					IPAddress:      "10.0.0.4",
					ExpirationTime: expirationTime,
				},
				{
					FQDNName:       "bar.com",
					IPAddress:      "10.0.0.5",
					ExpirationTime: expirationTime,
				},
			},
		},
		{
			name:                 "FQDN cache does not exist",
			filteredCacheEntries: []types.DnsCacheEntry{},
			expectedResponse:     []apis.FQDNCacheResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			q.EXPECT().GetFQDNCache(nil).Return(tt.filteredCacheEntries)
			handler := HandleFunc(q)
			req, err := http.NewRequest(http.MethodGet, "", nil)
			require.NoError(t, err)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			var receivedResponse []apis.FQDNCacheResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &receivedResponse)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResponse, receivedResponse)
		})
	}
}

func TestNewFilterFromURLQuery(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    url.Values
		expectedFilter *querier.FQDNCacheFilter
		expectedError  string
	}{
		{
			name:           "Empty query",
			queryParams:    url.Values{},
			expectedFilter: nil,
		},
		{
			name: "Valid regex domain",
			queryParams: url.Values{
				"domain": {"example.com"},
			},
			expectedFilter: &querier.FQDNCacheFilter{DomainRegex: regexp.MustCompile("^example[.]com$")},
		},
		{
			name: "Valid regex domain",
			queryParams: url.Values{
				"domain": {"*.example.com"},
			},
			expectedFilter: &querier.FQDNCacheFilter{DomainRegex: regexp.MustCompile("^.*[.]example[.]com$")},
		},
		{
			name: "Invalid regex domain",
			queryParams: url.Values{
				"domain": {"^example(abc$"},
			},
			expectedFilter: nil,
			expectedError:  "missing closing )",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := newFilterFromURLQuery(tt.queryParams)
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedFilter, result)
			}
		})
	}
}
