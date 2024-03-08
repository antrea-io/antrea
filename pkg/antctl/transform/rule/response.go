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

package rule

import (
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/util/ip"
)

type service struct {
	Protocol string `json:"protocol,omitempty"`
	Port     string `json:"port,omitempty"`
	EndPort  string `json:"endPort,omitempty"`
}

type ipBlock struct {
	CIDR   string   `json:"cidr" yaml:"cidr"`
	Except []string `json:"except,omitempty"`
}

type peer struct {
	AddressGroups []string  `json:"addressGroups,omitempty"`
	IPBlocks      []ipBlock `json:"ipBlocks,omitempty"`
}

type Response struct {
	Direction string    `json:"direction,omitempty"`
	From      peer      `json:"from,omitempty"`
	To        peer      `json:"to,omitempty"`
	Services  []service `json:"services,omitempty"`
}

func serviceTransform(services ...cpv1beta.Service) []service {
	var ret []service
	for _, s := range services {
		port := "nil"
		endPort := "nil"
		if s.Port != nil {
			port = s.Port.String()
		}
		if s.EndPort != nil {
			endPort = string(*s.EndPort)
		}
		ret = append(ret, service{
			Protocol: string(*s.Protocol),
			Port:     port,
			EndPort:  endPort,
		})
	}
	return ret
}

func ipBlockTransform(block cpv1beta.IPBlock) ipBlock {
	var ib ipBlock
	except := []string{}
	for i := range block.Except {
		except = append(except, ip.IPNetToNetIPNet(&block.Except[i]).String())
	}
	ib.Except = except
	if len(block.CIDR.IP) >= 4 {
		ib.CIDR = ip.IPNetToNetIPNet(&block.CIDR).String()
	}
	return ib
}

func peerTransform(p cpv1beta.NetworkPolicyPeer) peer {
	blocks := []ipBlock{}
	for _, originBlock := range p.IPBlocks {
		blocks = append(blocks, ipBlockTransform(originBlock))
	}
	return peer{AddressGroups: p.AddressGroups, IPBlocks: blocks}
}

func ObjectTransform(o interface{}) (interface{}, error) {
	originRules := o.(*[]cpv1beta.NetworkPolicyRule)
	var rules []Response
	for _, rule := range *originRules {
		rules = append(rules, Response{
			Direction: string(rule.Direction),
			From:      peerTransform(rule.From),
			To:        peerTransform(rule.To),
			Services:  serviceTransform(rule.Services...),
		})
	}
	return rules, nil
}
