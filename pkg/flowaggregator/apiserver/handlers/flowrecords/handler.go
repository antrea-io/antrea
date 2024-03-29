// Copyright 2020 Antrea Authors
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

package flowrecords

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/vmware/go-ipfix/pkg/intermediate"

	"antrea.io/antrea/pkg/flowaggregator/apis"
	"antrea.io/antrea/pkg/flowaggregator/querier"
)

// HandleFunc returns the function which can handle the /flowrecords API request.
func HandleFunc(faq querier.FlowAggregatorQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var resps []apis.FlowRecordsResponse
		sourceAddress := r.URL.Query().Get("srcip")
		destinationAddress := r.URL.Query().Get("dstip")
		protocol := r.URL.Query().Get("proto")
		sourcePort := r.URL.Query().Get("srcport")
		destinationPort := r.URL.Query().Get("dstport")
		var flowKey *intermediate.FlowKey
		if sourceAddress == "" && destinationAddress == "" && protocol == "" && sourcePort == "" && destinationPort == "" {
			flowKey = nil
		} else {
			var protocolNum, srcPortNum, dstPortNum uint64
			var err error
			if protocol != "" {
				if protocolNum, err = strconv.ParseUint(protocol, 10, 8); err != nil {
					http.Error(w, "Error when parsing protocol: "+err.Error(), http.StatusNotFound)
					return
				}
			}
			if sourcePort != "" {
				if srcPortNum, err = strconv.ParseUint(sourcePort, 10, 16); err != nil {
					http.Error(w, "Error when parsing source port: "+err.Error(), http.StatusNotFound)
					return
				}
			}
			if destinationPort != "" {
				if dstPortNum, err = strconv.ParseUint(destinationPort, 10, 16); err != nil {
					http.Error(w, "Error when parsing destination port: "+err.Error(), http.StatusNotFound)
					return
				}
			}

			flowKey = &intermediate.FlowKey{
				SourceAddress:      sourceAddress,
				DestinationAddress: destinationAddress,
				Protocol:           uint8(protocolNum),
				SourcePort:         uint16(srcPortNum),
				DestinationPort:    uint16(dstPortNum),
			}
		}
		records := faq.GetFlowRecords(flowKey)
		for _, record := range records {
			resps = append(resps, record)
		}
		err := json.NewEncoder(w).Encode(resps)
		if err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
