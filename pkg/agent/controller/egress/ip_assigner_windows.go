// Copyright 2021 Antrea Authors
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

package egress

import (
	"net"
)

type ipAssigner struct {
}

func NewIPAssigner(nodeIPAddr net.IP, dir string) (*ipAssigner, error) {
	return nil, nil
}

func (a *ipAssigner) AssignEgressIP(egressIP, egressName string) error {
	return nil
}

func (a *ipAssigner) UnassignEgressIP(egressName string) error {
	return nil
}

func (a *ipAssigner) AssignedIPs() (ips map[string]string) {
	return
}
