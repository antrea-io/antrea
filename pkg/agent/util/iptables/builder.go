//go:build !windows
// +build !windows

// Copyright 2024 Antrea Authors
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

func (b *iptablesRuleBuilder) writeSpec(spec string) {
	b.specs.WriteString(spec)
	b.specs.WriteByte(' ')
}

func (b *iptablesRuleBuilder) MatchCIDRSrc(cidr string) IPTablesRuleBuilder {
	if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
		return b
	}
	matchStr := fmt.Sprintf("-s %s", cidr)
	b.writeSpec(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchCIDRDst(cidr string) IPTablesRuleBuilder {
	if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
		return b
	}
	matchStr := fmt.Sprintf("-d %s", cidr)
	b.writeSpec(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchIPSetSrc(ipset string) IPTablesRuleBuilder {
	if ipset == "" {
		return b
	}
	matchStr := fmt.Sprintf("-m set --match-set %s src", ipset)
	b.writeSpec(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchIPSetDst(ipset string) IPTablesRuleBuilder {
	if ipset == "" {
		return b
	}
	matchStr := fmt.Sprintf("-m set --match-set %s dst", ipset)
	b.writeSpec(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchTransProtocol(protocol string) IPTablesRuleBuilder {
	if protocol == "" {
		return b
	}
	matchStr := fmt.Sprintf("-p %s", protocol)
	b.writeSpec(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchDstPort(port *intstr.IntOrString, endPort *int32) IPTablesRuleBuilder {
	if port == nil {
		return b
	}
	var matchStr string
	if endPort != nil {
		matchStr = fmt.Sprintf("--dport %s:%d", port.String(), *endPort)
	} else {
		matchStr = fmt.Sprintf("--dport %s", port.String())
	}
	b.writeSpec(matchStr)
	return b
}

func (b *iptablesRuleBuilder) MatchSrcPort(port, endPort *int32) IPTablesRuleBuilder {
	if port == nil {
		return b
	}
	var matchStr string
	if endPort != nil {
		matchStr = fmt.Sprintf("--sport %d:%d", *port, *endPort)
	} else {
		matchStr = fmt.Sprintf("--sport %d", *port)
	}
	b.writeSpec(matchStr)
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
	b.writeSpec(strings.Join(parts, " "))
	return b
}

func (b *iptablesRuleBuilder) MatchEstablishedOrRelated() IPTablesRuleBuilder {
	b.writeSpec("-m conntrack --ctstate ESTABLISHED,RELATED")
	return b
}

func (b *iptablesRuleBuilder) MatchInputInterface(interfaceName string) IPTablesRuleBuilder {
	if interfaceName == "" {
		return b
	}
	specStr := fmt.Sprintf("-i %s", interfaceName)
	b.writeSpec(specStr)
	return b
}

func (b *iptablesRuleBuilder) MatchOutputInterface(interfaceName string) IPTablesRuleBuilder {
	if interfaceName == "" {
		return b
	}
	specStr := fmt.Sprintf("-o %s", interfaceName)
	b.writeSpec(specStr)
	return b
}

func (b *iptablesRuleBuilder) SetTarget(target string) IPTablesRuleBuilder {
	if target == "" {
		return b
	}
	targetStr := fmt.Sprintf("-j %s", target)
	b.writeSpec(targetStr)
	return b
}

func (b *iptablesRuleBuilder) SetComment(comment string) IPTablesRuleBuilder {
	if comment == "" {
		return b
	}

	commentStr := fmt.Sprintf("-m comment --comment \"%s\"", comment)
	b.writeSpec(commentStr)
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

func (e *iptablesRule) GetRule() string {
	ruleStr := fmt.Sprintf("-A %s %s", e.chain, e.specs.String())
	return ruleStr[:len(ruleStr)-1]
}
