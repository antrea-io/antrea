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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"antrea.io/antrea/pkg/agent/types"
)

func TestTrasnform(t *testing.T) {
	var fqdn1 = types.DnsCacheEntry{
		FqdnName:       "google.com",
		IpAddress:      net.ParseIP("10.0.0.1"),
		ExpirationTime: time.Date(2025, 12, 25, 15, 0, 0, 0, time.Now().Location()),
	}
	var fqdn2 = types.DnsCacheEntry{
		FqdnName:       "google.com",
		IpAddress:      net.ParseIP("10.0.0.2"),
		ExpirationTime: time.Date(2025, 12, 25, 15, 0, 0, 0, time.Now().Location()),
	}
	var fqdn3 = types.DnsCacheEntry{
		FqdnName:       "google.com",
		IpAddress:      net.ParseIP("10.0.0.3"),
		ExpirationTime: time.Date(2025, 12, 25, 15, 0, 0, 0, time.Now().Location()),
	}
	var fqdn4 = types.DnsCacheEntry{
		FqdnName:       "example.com",
		IpAddress:      net.ParseIP("10.0.0.4"),
		ExpirationTime: time.Date(2025, 12, 25, 15, 0, 0, 0, time.Now().Location()),
	}
	var fqdn5 = types.DnsCacheEntry{
		FqdnName:       "antrea.io",
		IpAddress:      net.ParseIP("10.0.0.5"),
		ExpirationTime: time.Date(2025, 12, 25, 15, 0, 0, 0, time.Now().Location()),
	}
	var fqdnList = []types.DnsCacheEntry{fqdn1, fqdn2, fqdn3, fqdn4, fqdn5}

	tests := []struct {
		name             string
		opts             map[string]string
		fqdnList         []types.DnsCacheEntry
		expectedResponse interface{}
		expectedError    string
	}{
		{
			name:             "all",
			fqdnList:         fqdnList,
			expectedResponse: []Response{{&fqdn1}, {&fqdn2}, {&fqdn3}, {&fqdn4}, {&fqdn5}},
		},
		{
			name: "only google.com domain name",
			opts: map[string]string{
				"domain": "google.com",
			},
			fqdnList:         fqdnList,
			expectedResponse: []Response{{&fqdn1}, {&fqdn2}, {&fqdn3}},
		},
		{
			name: "only antrea.io domain name",
			opts: map[string]string{
				"domain": "antrea.io",
			},
			fqdnList:         fqdnList,
			expectedResponse: []Response{{&fqdn5}},
		},
		{
			name: "domain name that doesn't exist",
			opts: map[string]string{
				"domain": "bing.com",
			},
			fqdnList:         fqdnList,
			expectedResponse: []Response{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqByte, _ := json.Marshal(tt.fqdnList)
			reqReader := bytes.NewReader(reqByte)
			result, err := Transform(reqReader, false, tt.opts)
			if tt.expectedError == "" {
				require.NoError(t, err)
				fmt.Printf("expected: %v\nresult: %v\n", tt.expectedResponse.([]Response), result)
				if result == "" {
					assert.Equal(t, len(tt.expectedResponse.([]Response)), 0)
				} else {
					assert.Equal(t, len(tt.expectedResponse.([]Response)), len(result.([]Response)))
					for i, resp := range tt.expectedResponse.([]Response) {
						fmt.Printf("resp: %v\nresult: %v\n", *resp.DnsCacheEntry, *result.([]Response)[i].DnsCacheEntry)
						assert.Equal(t, resp.DnsCacheEntry.FqdnName, result.([]Response)[i].DnsCacheEntry.FqdnName)
						require.True(t, resp.DnsCacheEntry.IpAddress.Equal(result.([]Response)[i].DnsCacheEntry.IpAddress))
						require.True(t, resp.DnsCacheEntry.ExpirationTime.Equal(result.([]Response)[i].DnsCacheEntry.ExpirationTime))
					}
				}
				// assert.Equal(t, tt.expectedResponse, result)
			} else {
				assert.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}
