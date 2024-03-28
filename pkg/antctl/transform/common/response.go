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

package common

import (
	"net"

	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type GroupMember struct {
	Pod  *cpv1beta.PodReference  `json:"pod,omitempty"`
	Node *cpv1beta.NodeReference `json:"node,omitempty"`
	// IP maintains the IPAddresses associated with the Pod.
	IP string `json:"ip,omitempty"`
	// Ports maintain the named port mapping of this Pod.
	Ports []cpv1beta.NamedPort `json:"ports,omitempty"`
}

func GroupMemberTransform(member cpv1beta.GroupMember) GroupMember {
	var ipStr string
	for i, ip := range member.IPs {
		if i != 0 {
			ipStr += ", "
		}
		ipStr += net.IP(ip).String()
	}
	return GroupMember{Pod: member.Pod, IP: ipStr, Ports: member.Ports, Node: member.Node}
}

type TableOutput interface {
	GetTableHeader() []string
	GetTableRow(maxColumnLength int) []string
	SortRows() bool
}
