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
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
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
	PolicyName      string
	PolicyNamespace string
}

// IsAntreaNetworkPolicyRule returns if a PolicyRule is created for Antrea NetworkPolicy types.
func (r *PolicyRule) IsAntreaNetworkPolicyRule() bool {
	return r.Priority != nil
}

// Priority is a struct that is composed of CNP priority, rule priority and
// tier/category priority in the future. It is used as the basic unit for
// priority sorting.
type Priority struct {
	PolicyPriority float64
	RulePriority   int32
}
