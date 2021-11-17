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

package flexible

import (
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/runtime"
)

func (c *featurePodConnectivity) getTemplate(protocol ofProtocol) *pipelineTemplate {
	var template *pipelineTemplate
	if protocol == ofProtocolIP {
		template = &pipelineTemplate{
			stageTables: map[binding.StageID][]tableRequest{
				binding.ClassifierStage: {
					tableRequest{ClassifierTable, 0x7f},
				},
				binding.ValidationStage: {
					tableRequest{SpoofGuardTable, 0x7f},
					tableRequest{ConntrackTable, 0x6f},
					tableRequest{ConntrackStateTable, 0x5f},
				},
				binding.RoutingStage: {
					tableRequest{L3ForwardingTable, 0x7f},
					tableRequest{L3DecTTLTable, 0x7d},
				},
				binding.SwitchingStage: {
					tableRequest{L2ForwardingCalcTable, 0x7f},
				},
				binding.ConntrackStage: {
					tableRequest{ConntrackCommitTable, 0x7f},
				},
				binding.OutputStage: {
					tableRequest{L2ForwardingOutTable, 0x7f},
				},
			},
		}
		if runtime.IsWindowsPlatform() || c.connectUplinkToBridge {
			template.stageTables[binding.ValidationStage] = append(template.stageTables[binding.ValidationStage], tableRequest{UplinkTable, 0x8f})
		}
		for _, ipProtocol := range c.ipProtocols {
			if ipProtocol == binding.ProtocolIPv6 {
				template.stageTables[binding.ValidationStage] = append(template.stageTables[binding.ValidationStage], tableRequest{IPv6Table, 0x7e})
				break
			}
		}
	} else if protocol == ofProtocolARP {
		template = &pipelineTemplate{
			stageTables: map[binding.StageID][]tableRequest{
				binding.ValidationStage: {
					tableRequest{ARPSpoofGuardTable, 0x7f},
				},
				binding.OutputStage: {
					tableRequest{ARPResponderTable, 0x7f},
				},
			},
		}
	}

	return template
}

func (c *featureNetworkPolicy) getTemplate(protocol ofProtocol) *pipelineTemplate {
	var template *pipelineTemplate
	if protocol != ofProtocolIP {
		return template
	}
	template = &pipelineTemplate{
		stageTables: map[binding.StageID][]tableRequest{
			binding.EgressSecurityStage: {
				tableRequest{EgressRuleTable, 0x7f},
				tableRequest{EgressDefaultTable, 0x7e},
				tableRequest{EgressMetricTable, 0x7d},
			},
			binding.IngressSecurityStage: {
				tableRequest{IngressRuleTable, 0x7f},
				tableRequest{IngressDefaultTable, 0x7e},
				tableRequest{IngressMetricTable, 0x7d},
			},
		},
	}
	if c.enableAntreaPolicy {
		template.stageTables[binding.EgressSecurityStage] = append(template.stageTables[binding.EgressSecurityStage],
			tableRequest{AntreaPolicyEgressRuleTable, 0x8f},
		)
		template.stageTables[binding.IngressSecurityStage] = append(template.stageTables[binding.IngressSecurityStage],
			tableRequest{AntreaPolicyIngressRuleTable, 0x8f},
		)
	}
	return template
}

func (c *featureService) getTemplate(protocol ofProtocol) *pipelineTemplate {
	var template *pipelineTemplate
	if protocol != ofProtocolIP {
		return template
	}
	if c.enableProxy {
		template = &pipelineTemplate{
			stageTables: map[binding.StageID][]tableRequest{
				binding.ValidationStage: {
					tableRequest{ServiceHairpinReplyTable, 0x71},
					tableRequest{SNATConntrackTable, 0x70},
				},
				binding.PreRoutingStage: {
					tableRequest{SessionAffinityTable, 0x7f},
					tableRequest{ServiceLBTable, 0x7e},
					tableRequest{EndpointDNATTable, 0x7d},
				},
				binding.RoutingStage: {
					tableRequest{L3ForwardingTable, 0x7f},
					tableRequest{ServiceHairpinRequestTable, 0x7e},
				},
				binding.PostRoutingStage: {
					tableRequest{SNATConntrackCommitTable, 0x7e},
				},
				binding.ConntrackStage: {
					tableRequest{ConntrackCommitTable, 0x7f},
				},
				binding.OutputStage: {
					tableRequest{L2ForwardingOutTable, 0x7f},
				},
			},
		}
		if c.proxyAll {
			template.stageTables[binding.PreRoutingStage] = append(template.stageTables[binding.PreRoutingStage], tableRequest{NodePortProbeTable, 0x8f})
		}
	} else {
		template = &pipelineTemplate{
			stageTables: map[binding.StageID][]tableRequest{
				binding.PreRoutingStage: {
					tableRequest{DNATTable, 0x7f},
				},
			},
		}
	}
	return template
}

func (c *featureEgress) getTemplate(protocol ofProtocol) *pipelineTemplate {
	var template *pipelineTemplate
	if protocol != ofProtocolIP {
		return template
	}
	template = &pipelineTemplate{
		stageTables: map[binding.StageID][]tableRequest{
			binding.RoutingStage: {
				tableRequest{L3ForwardingTable, 0x7f},
			},
			binding.PostRoutingStage: {
				tableRequest{SNATTable, 0x8f},
			},
		},
	}
	return template
}

func (c *featureTraceflow) getTemplate(protocol ofProtocol) *pipelineTemplate {
	var template *pipelineTemplate
	if protocol != ofProtocolIP {
		return template
	}
	template = &pipelineTemplate{}
	return template
}

func (c *featureVMConnectivity) getTemplate(protocol ofProtocol) *pipelineTemplate {
	var template *pipelineTemplate
	if protocol != ofProtocolIP {
		return template
	}
	template = &pipelineTemplate{
		stageTables: map[binding.StageID][]tableRequest{
			binding.ClassifierStage: {
				tableRequest{ClassifierTable, 0x7f},
			},
			binding.ValidationStage: {
				tableRequest{ConntrackStateTable, 0x5f},
			},
			binding.OutputStage: {
				tableRequest{L2ForwardingOutTable, 0x7f},
			},
		},
	}
	return template
}
