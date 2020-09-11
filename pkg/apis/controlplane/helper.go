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

package controlplane

import "fmt"

// Conversion functions between GroupMember and GroupMemberPod
func (g *GroupMember) ToGroupMemberPod() *GroupMemberPod {
	gmPod := &GroupMemberPod{
		Pod:   g.Pod,
		Ports: g.Endpoints[0].Ports,
	}
	for _, ep := range g.Endpoints {
		gmPod.IPs = append(gmPod.IPs, ep.IP)
	}
	return gmPod
}

func (p *GroupMemberPod) ToGroupMember() *GroupMember {
	gm := &GroupMember{
		Pod: p.Pod,
	}
	for _, ip := range p.IPs {
		gm.Endpoints = append(gm.Endpoints, Endpoint{IP: ip, Ports: p.Ports})
	}
	return gm
}

func (r *NetworkPolicyReference) ToString() string {
	if r.Type == AntreaClusterNetworkPolicy {
		return fmt.Sprintf("%s:%s", r.Type, r.Name)
	} else {
		return fmt.Sprintf("%s:%s/%s", r.Type, r.Namespace, r.Name)
	}
}
