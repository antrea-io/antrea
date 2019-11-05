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

package antctl

import (
	"fmt"
	"net"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

const (
	// DefaultControllerLocalPort is the default port for antctl server in controller pod
	DefaultControllerLocalPort = 1443
	// DefaultAgentLocalPort is the default port for antctl server in agent pod
	DefaultAgentLocalPort = 2443
)

// ServerOptions defines all options of a cli server.
type ServerOptions struct {
	AgentQuerier      monitor.AgentQuerier
	ControllerQuerier monitor.ControllerQuerier
	CommandBundle     *CommandBundle
	Listener          net.Listener
}

// NewServerOptions creates an options of a server accepts only local access.
func NewServerOptions(bundle *CommandBundle, aq monitor.AgentQuerier, cq monitor.ControllerQuerier, port int) (*ServerOptions, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	o := &ServerOptions{
		AgentQuerier:      aq,
		ControllerQuerier: cq,
		CommandBundle:     bundle,
		Listener:          listener,
	}
	return o, nil
}

// Validate checks if the options is valid.
func (o *ServerOptions) Validate() []error {
	var errs []error
	errs = append(errs, o.CommandBundle.Validate()...)
	if o.AgentQuerier == nil && o.ControllerQuerier == nil {
		errs = append(errs, fmt.Errorf("neither agent querier nor controller querier is set"))
	}
	if o.Listener == nil {
		errs = append(errs, fmt.Errorf("listener is not set"))
	}
	return errs
}
