// Copyright 2022 Antrea Authors
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

package ovstables

import (
	"encoding/json"
	"net/http"
	"strings"

	"k8s.io/klog/v2"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
)

type Response struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tableStrs, err := aq.GetOVSCtlClient().DumpTables()
		if err != nil {
			klog.ErrorS(err, "Failed to dump tables")
			http.Error(w, "OVS table dumping failed", http.StatusInternalServerError)
			return
		}
		tables := make([]Response, 0, len(tableStrs))
		for _, tableStr := range tableStrs {
			id := strings.Split(tableStr, " ")[0]
			name := strings.Split(tableStr, " ")[1]
			tables = append(tables, Response{id, name})
		}
		err = json.NewEncoder(w).Encode(tables)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding tables to json")
		}
	}
}

func (r Response) GetTableHeader() []string {
	return []string{"TABLE-ID", "TABLE-NAME"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Id, r.Name}
}

func (r Response) SortRows() bool {
	return false
}
