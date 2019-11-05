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

// VersionResponse defines the response data struct of the version command.
type VersionResponse struct {
	AgentVersion      string `json:"agentVersion,omitempty" yaml:"agentVersion,omitempty"`
	ControllerVersion string `json:"controllerVersion,omitempty" yaml:"controllerVersion,omitempty"`
	AntctlVersion     string `json:"antctlVersion,omitempty" yaml:"antctlVersion,omitempty"`
}

// Version is a handler.Factory which generates handler function for version command.
type Version struct{}

// Handler returns the function for handling version CLI query,
// the handler function will write the VersionResponse in JSON format.
func (v *Version) Handler(agentQuerier monitor.AgentQuerier, controllerQuerier monitor.ControllerQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m VersionResponse

		if agentQuerier != nil {
			m.AgentVersion = agentQuerier.GetVersion()
		}
		if controllerQuerier != nil {
			m.ControllerVersion = controllerQuerier.GetVersion()
		}

		err := json.NewEncoder(w).Encode(m)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
