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
	"net/http"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

// Factory is the interface to generate command handlers.
type Factory interface {
	// Handler returns a net/http.HandlerFunc which will be used to handle
	// requests issued by commands from the antctl client. An implementation
	// needs to determine the component it is running in by checking nullable
	// of the AgentQuerier or the ControllerQuerier. If the antctl server is
	// running in the antrea-agent, the AgentQuerier will not be nil, otherwise,
	// the ControllerQuerier will not be nil. If the command has no AddonTransform,
	// the HandlerFunc need to write the data to the response body in JSON format.
	Handler(aq monitor.AgentQuerier, cq monitor.ControllerQuerier) http.HandlerFunc
}
