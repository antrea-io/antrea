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

package types

import (
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

type AddressCategory uint8

const (
	IPAddr AddressCategory = iota
	IPNetAddr
	OFPortAddr
)

type AddressType int

const (
	SrcAddress AddressType = iota
	DstAddress
)

type Address interface {
	GetMatchValue() string
	GetMatchKey(addrType AddressType) int
	GetValue() interface{}
}

// PolicyRule groups configurations to set up conjunctive match for egress/ingress policy rules.
type PolicyRule struct {
	Direction       v1beta1.Direction
	From            []Address
	To              []Address
	Service         []v1beta1.Service
	Action          *secv1alpha1.RuleAction
	Priority        *uint16
	FlowID          uint32
	TableID         binding.TableIDType
	PolicyName      string
	PolicyNamespace string
}

// IsAntreaNetworkPolicyRule returns if a PolicyRule is created for Antrea NetworkPolicy types.
func (r *PolicyRule) IsAntreaNetworkPolicyRule() bool {
	return r.Priority != nil
}

// Priority is a struct that is composed of Antrea NetworkPolicy priority, rule priority and Tier priority.
// It is used as the basic unit for priority sorting.
type Priority struct {
	TierPriority   v1beta1.TierPriority
	PolicyPriority float64
	RulePriority   int32
}

func (p *Priority) Less(p2 Priority) bool {
	if p.TierPriority == p2.TierPriority {
		if p.PolicyPriority == p2.PolicyPriority {
			return p.RulePriority > p2.RulePriority
		}
		return p.PolicyPriority > p2.PolicyPriority
	}
	return p.TierPriority > p2.TierPriority
}

type RuleMetric struct {
	Bytes, Packets, Sessions uint64
}

func (m *RuleMetric) Merge(m1 *RuleMetric) {
	m.Bytes += m1.Bytes
	m.Packets += m1.Packets
	m.Sessions += m1.Sessions
}
