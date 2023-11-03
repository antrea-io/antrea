//go:build !windows
// +build !windows

// Copyright 2023 Antrea Authors
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

package iptables

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type iptablesRule struct {
	chain string
	specs *strings.Builder
}

type iptablesRuleBuilder struct {
	iptablesRule
}

func NewRuleBuilder(chain string) IPTablesRuleBuilder {
	builder := &iptablesRuleBuilder{
		iptablesRule{
			chain: chain,
			specs: &strings.Builder{},
		},
	}
	return builder
}

func (b *iptablesRuleBuilder) MatchIPSetSrc(ipset string) IPTablesRuleBuilder {
	specStr := fmt.Sprintf("-m set --match-ipset %s src ", ipset)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) MatchIPSetDst(ipset string) IPTablesRuleBuilder {
	specStr := fmt.Sprintf("-m set --match-ipset %s dst ", ipset)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) MatchTransProtocol(protocol v1beta2.Protocol) IPTablesRuleBuilder {
	var protoStr string
	switch protocol {
	case v1beta2.ProtocolTCP:
		protoStr = "tcp"
	case v1beta2.ProtocolUDP:
		protoStr = "udp"
	case v1beta2.ProtocolSCTP:
		protoStr = "sctp"
	}
	specStr := fmt.Sprintf("-p %s ", protoStr)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) MatchDstPort(port *intstr.IntOrString, endPort *int32) IPTablesRuleBuilder {
	if port == nil {
		return b
	}
	var specStr string
	if endPort != nil {
		specStr = fmt.Sprintf("--dport %s:%d ", port.String(), *endPort)
	} else {
		specStr = fmt.Sprintf("--dport %s ", port.String())
	}
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) MatchSrcPort(port, endPort *int32) IPTablesRuleBuilder {
	if port == nil {
		return b
	}
	var matchStr string
	if endPort != nil {
		matchStr = fmt.Sprintf("--sport %d:%d ", *port, *endPort)
	} else {
		matchStr = fmt.Sprintf("--sport %d ", *port)
	}
	b.specs.WriteString(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchICMP(icmpType, icmpCode *int32, ipProtocol Protocol) IPTablesRuleBuilder {
	parts := []string{"-p"}
	icmpTypeStr := "icmp"
	if ipProtocol != ProtocolIPv4 {
		icmpTypeStr = "icmpv6"
	}
	parts = append(parts, icmpTypeStr)

	if icmpType != nil {
		icmpTypeFlag := "--icmp-type"
		if ipProtocol != ProtocolIPv4 {
			icmpTypeFlag = "--icmpv6-type"
		}

		if icmpCode != nil {
			parts = append(parts, icmpTypeFlag, fmt.Sprintf("%d/%d", *icmpType, *icmpCode))
		} else {
			parts = append(parts, icmpTypeFlag, strconv.Itoa(int(*icmpType)))
		}
	}
	b.specs.WriteString(strings.Join(parts, " "))
	b.specs.WriteByte(' ')

	return b
}

func (b *iptablesRuleBuilder) MatchInputInterface(interfaceName string) IPTablesRuleBuilder {
	specStr := fmt.Sprintf("-i %s ", interfaceName)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) MatchOutputInterface(interfaceName string) IPTablesRuleBuilder {
	specStr := fmt.Sprintf("-o %s ", interfaceName)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) SetTarget(target string) IPTablesRuleBuilder {
	specStr := fmt.Sprintf("-j %s ", target)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) SetComment(comment string) IPTablesRuleBuilder {
	specStr := fmt.Sprintf("-m comment --comment %s ", comment)
	b.specs.WriteString(specStr)
	return b
}

func (b *iptablesRuleBuilder) CopyBuilder() IPTablesRuleBuilder {
	var copiedSpec strings.Builder
	copiedSpec.Grow(b.specs.Len())
	copiedSpec.WriteString(b.specs.String())
	builder := &iptablesRuleBuilder{
		iptablesRule{
			chain: b.chain,
			specs: &copiedSpec,
		},
	}
	return builder
}

func (b *iptablesRuleBuilder) Done() IPTablesRule {
	return &b.iptablesRule
}

func (e *iptablesRule) GetSpec() string {
	spec := fmt.Sprintf("-A %s %s", e.chain, e.specs)
	return spec[:len(spec)-1] // Remove the last space.
}
