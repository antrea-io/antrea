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
	"encoding/json"
	"net/http"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

// FlowTableResponse defines the response data struct of the flow-table command.
type FlowTableResponse struct {
	TableID   string `json:"tableID" yaml:"tableID" antctl:"key,The table id of the flow table"`
	FlowCount uint   `json:"flowCount" yaml:"flowCount"`
}

// FlowTable is a handler.Factory which generates handler function for flow-table command.
type FlowTable struct{}

// Handler returns the function for handling flow-table CLI query.
func (s *FlowTable) Handler(aq monitor.AgentQuerier, _ monitor.ControllerQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// only support on antrea-agent
		if aq == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}

		var flowTables []FlowTableResponse
		key, doFilter := r.URL.Query()["tableID"]
		// 1) query parameter should not be empty; 2) only one parameter is accepted
		if doFilter && (len(key) != 1 || len(key[0]) == 0) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		for tableID, flowCount := range aq.GetOVSFlowTable() {
			resp := FlowTableResponse{TableID: tableID, FlowCount: uint(flowCount)}
			if doFilter && key[0] == tableID {
				err := json.NewEncoder(w).Encode(resp)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			} else {
				flowTables = append(flowTables, resp)
			}
		}

		if doFilter {
			w.WriteHeader(http.StatusNotFound)
		} else {
			err := json.NewEncoder(w).Encode(flowTables)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
}
