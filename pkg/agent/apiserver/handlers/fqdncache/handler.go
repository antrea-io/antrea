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
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"k8s.io/klog/v2"

	agentapi "antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/querier"
)

func HandleFunc(npq querier.AgentNetworkPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fqdnFilter, err := newFilterFromURLQuery(w, r.URL.Query())
		if err != nil {
			http.Error(w, "Regex formatted incorrectly to parse: "+err.Error(), http.StatusBadRequest)
			klog.ErrorS(err, "Regex formatted incorrectly to parse")
		}
		dnsEntryCache := npq.GetFQDNCache(fqdnFilter)
		resp := make([]agentapi.FQDNCacheResponse, 0, len(dnsEntryCache))
		for _, entry := range dnsEntryCache {
			resp = append(resp, agentapi.FQDNCacheResponse{
				FQDNName:       entry.FQDNName,
				IPAddress:      entry.IPAddress.String(),
				ExpirationTime: entry.ExpirationTime,
			})
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusBadRequest)
			klog.ErrorS(err, "Failed to encode response")
		}
	}
}

func newFilterFromURLQuery(w http.ResponseWriter, query url.Values) (*querier.FQDNCacheFilter, error) {
	if len(query) == 0 || len(query.Get("domain")) == 0 {
		return nil, nil
	}
	regexPattern := "^" + strings.ReplaceAll(query.Get("domain"), `\*`, ".*") + "$"
	pattern, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, err
	}
	return &querier.FQDNCacheFilter{DomainRegex: pattern}, nil
}
