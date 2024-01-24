// Copyright 2022 Antrea Authors
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

package openflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/util/runtime"
)

func podConnectivityInitFlows(
	trafficEncapMode config.TrafficEncapModeType,
	trafficEncryptionMode config.TrafficEncryptionModeType,
	connectUplinkToBridge, isIPv4, trafficControlEnabled, multicastEnabled bool,
) []string {
	var flows []string
	switch trafficEncapMode {
	case config.TrafficEncapModeEncap:
		if !isIPv4 {
			return []string{
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=1 actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=Classifier, priority=210,ipv6,in_port=2,ipv6_src=fec0:10:10::1 actions=set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=2 actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,ipv6_src=fe80::/10 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=2 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=IPv6, priority=200,icmp6,icmp_type=135,icmp_code=0 actions=NORMAL",
				"cookie=0x1010000000000, table=IPv6, priority=200,icmp6,icmp_type=136,icmp_code=0 actions=NORMAL",
				"cookie=0x1010000000000, table=IPv6, priority=200,ipv6,ipv6_dst=ff00::/8 actions=NORMAL",
				"cookie=0x1010000000000, table=ConntrackZone, priority=200,ipv6 actions=ct(table=ConntrackState,zone=65510,nat)",
				"cookie=0x1010000000000, table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x0/0x10,ipv6 actions=goto_table:AntreaPolicyEgressRule",
				"cookie=0x1010000000000, table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier",
				"cookie=0x1010000000000, table=ConntrackState, priority=200,ct_state=+inv+trk,ipv6 actions=drop",
				"cookie=0x1010000000000, table=L3Forwarding, priority=210,ipv6,ipv6_dst=fec0:10:10::1 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ipv6 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x0/0x200,ipv6_dst=fec0:10:10::/80 actions=goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=L3DecTTL, priority=210,ipv6,reg0=0x2/0xf actions=goto_table:SNATMark",
				"cookie=0x1010000000000, table=L3DecTTL, priority=200,ipv6 actions=dec_ttl,goto_table:SNATMark",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=aa:bb:cc:dd:ee:ff actions=set_field:0x1->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ipv6 actions=goto_table:ConntrackCommit",
				"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ipv6 actions=ct(commit,table=Output,zone=65510,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1010000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
			}
		}
		flows = []string{
			"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=2,arp_spa=10.10.0.1,arp_sha=0a:00:00:00:00:01 actions=goto_table:ARPResponder",
			"cookie=0x1010000000000, table=ARPResponder, priority=190,arp actions=NORMAL",
			"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=2,nw_src=10.10.0.1 actions=set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
			"cookie=0x1010000000000, table=Classifier, priority=200,in_port=2 actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
			"cookie=0x1010000000000, table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=65520,nat)",
			"cookie=0x1010000000000, table=ConntrackState, priority=200,ct_state=+inv+trk,ip actions=drop",
			"cookie=0x1010000000000, table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x0/0x10,ip actions=goto_table:AntreaPolicyEgressRule",
			"cookie=0x1010000000000, table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier",
			"cookie=0x1010000000000, table=L3Forwarding, priority=210,ip,nw_dst=10.10.0.1 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ip actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x0/0x200,nw_dst=10.10.0.0/24 actions=goto_table:L2ForwardingCalc",
			"cookie=0x1010000000000, table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			"cookie=0x1010000000000, table=L3DecTTL, priority=210,ip,reg0=0x2/0xf actions=goto_table:SNATMark",
			"cookie=0x1010000000000, table=L3DecTTL, priority=200,ip actions=dec_ttl,goto_table:SNATMark",
			"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ip actions=ct(commit,table=Output,zone=65520,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
			"cookie=0x1010000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
		}
		if trafficEncryptionMode != config.TrafficEncryptionModeWireGuard {
			flows = append(flows,
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=1 actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
			)
		}
		if !multicastEnabled {
			flows = append(flows, "cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=goto_table:UnSNAT")
		} else {
			flows = append(flows, "cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=goto_table:PipelineIPClassifier")
		}
		if runtime.IsWindowsPlatform() {
			flows = append(flows,
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,in_port=4 actions=output:4294967294",
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,in_port=4294967294 actions=output:4",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=4 actions=output:4294967294",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=4294967294 actions=output:4",
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,ct_state=-rpl+trk,ip,nw_src=10.10.0.1 actions=goto_table:ConntrackCommit",
			)
		} else {
			flows = append(flows,
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ip actions=goto_table:ConntrackCommit",
			)
		}
		if trafficControlEnabled {
			flows = append(flows,
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl",
				"cookie=0x1010000000000, table=TrafficControl, priority=210,reg0=0x200006/0x60000f actions=goto_table:Output",
				"cookie=0x1010000000000, table=Output, priority=211,reg0=0x200000/0x600000,reg4=0x400000/0xc00000 actions=output:NXM_NX_REG1[],output:NXM_NX_REG9[]",
				"cookie=0x1010000000000, table=Output, priority=211,reg0=0x200000/0x600000,reg4=0x800000/0xc00000 actions=output:NXM_NX_REG9[]",
			)
			if trafficEncryptionMode != config.TrafficEncryptionModeWireGuard {
				flows = append(flows, "cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=aa:bb:cc:dd:ee:ff actions=set_field:0x1->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl")
			}
		} else {
			flows = append(flows, "cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier")
			if trafficEncryptionMode != config.TrafficEncryptionModeWireGuard {
				flows = append(flows, "cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=aa:bb:cc:dd:ee:ff actions=set_field:0x1->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier")
			}
		}
	case config.TrafficEncapModeNoEncap:
		if !isIPv4 {
			return []string{
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,ipv6_src=fe80::/10 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=2 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=IPv6, priority=200,icmp6,icmp_type=135,icmp_code=0 actions=NORMAL",
				"cookie=0x1010000000000, table=IPv6, priority=200,icmp6,icmp_type=136,icmp_code=0 actions=NORMAL",
				"cookie=0x1010000000000, table=IPv6, priority=200,ipv6,ipv6_dst=ff00::/8 actions=NORMAL",
				"cookie=0x1010000000000, table=Classifier, priority=210,ipv6,in_port=2,ipv6_src=fec0:10:10::1 actions=set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=2 actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=ConntrackZone, priority=200,ipv6 actions=ct(table=ConntrackState,zone=65510,nat)",
				"cookie=0x1010000000000, table=ConntrackState, priority=200,ct_state=+inv+trk,ipv6 actions=drop",
				"cookie=0x1010000000000, table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x0/0x10,ipv6 actions=goto_table:AntreaPolicyEgressRule",
				"cookie=0x1010000000000, table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier",
				"cookie=0x1010000000000, table=L3Forwarding, priority=210,ipv6,ipv6_dst=fec0:10:10::1 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ipv6 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ipv6,reg0=0x0/0x200,ipv6_dst=fec0:10:10::/80 actions=goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=L3DecTTL, priority=210,ipv6,reg0=0x2/0xf actions=goto_table:SNATMark",
				"cookie=0x1010000000000, table=L3DecTTL, priority=200,ipv6 actions=dec_ttl,goto_table:SNATMark",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ipv6 actions=goto_table:ConntrackCommit",
				"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ipv6 actions=ct(commit,table=Output,zone=65510,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1010000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
			}
		}
		flows = []string{
			"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=2,arp_spa=10.10.0.1,arp_sha=0a:00:00:00:00:01 actions=goto_table:ARPResponder",
			"cookie=0x1010000000000, table=ARPResponder, priority=190,arp actions=NORMAL",
			"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=2,nw_src=10.10.0.1 actions=set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
			"cookie=0x1010000000000, table=Classifier, priority=200,in_port=2 actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
			"cookie=0x1010000000000, table=ConntrackState, priority=200,ct_state=+inv+trk,ip actions=drop",
			"cookie=0x1010000000000, table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x0/0x10,ip actions=goto_table:AntreaPolicyEgressRule",
			"cookie=0x1010000000000, table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier",
			"cookie=0x1010000000000, table=L3Forwarding, priority=210,ip,nw_dst=10.10.0.1 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ip actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			"cookie=0x1010000000000, table=L3DecTTL, priority=210,ip,reg0=0x2/0xf actions=goto_table:SNATMark",
			"cookie=0x1010000000000, table=L3DecTTL, priority=200,ip actions=dec_ttl,goto_table:SNATMark",
			"cookie=0x1010000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
		}
		if runtime.IsWindowsPlatform() {
			flows = append(flows,
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,in_port=4 actions=output:4294967294",
				"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,in_port=4294967294 actions=output:4",
				"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=4,nw_dst=10.10.0.0/24 actions=set_field:0x4/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=4 actions=output:4294967294",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=4294967294 actions=output:4",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=goto_table:UnSNAT",
				"cookie=0x1010000000000, table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=65520,nat)",
				"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x0/0x200,nw_dst=10.10.0.0/24 actions=goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,ct_state=-rpl+trk,ip,nw_src=10.10.0.1 actions=goto_table:ConntrackCommit",
				"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ip actions=ct(commit,table=Output,zone=65520,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
			)
		} else {
			flows = append(flows,
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ip actions=goto_table:ConntrackCommit",
			)
			if connectUplinkToBridge {
				flows = append(flows,
					"cookie=0x1010000000000, table=ARPSpoofGuard, priority=210,arp,in_port=4 actions=NORMAL",
					"cookie=0x1010000000000, table=ARPSpoofGuard, priority=210,arp,in_port=4294967294 actions=NORMAL",
					"cookie=0x1010000000000, table=ARPResponder, priority=200,arp,arp_tpa=10.10.0.1,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:0a:00:00:00:00:01->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:0a:00:00:00:00:01->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:10.10.0.1->arp_spa,IN_PORT",
					"cookie=0x1010000000000, table=Classifier, priority=200,in_port=4 actions=output:4294967294",
					"cookie=0x1010000000000, table=Classifier, priority=200,in_port=4294967294 actions=output:4",
					"cookie=0x1010000000000, table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=NXM_NX_REG8[0..15],nat)",
					"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x5/0xf,ip,reg8=0x0/0xfff actions=set_field:0a:00:00:00:00:02->eth_dst,goto_table:L2ForwardingCalc",
					"cookie=0x1010000000000, table=L3Forwarding, priority=210,ip,reg4=0x100000/0x100000,reg8=0x0/0xfff,nw_dst=192.168.77.100 actions=set_field:0a:00:00:00:00:02->eth_dst,goto_table:L2ForwardingCalc",
					"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x0/0x200,reg8=0x0/0xfff,nw_dst=10.10.0.0/24 actions=goto_table:L2ForwardingCalc", "cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:02 actions=set_field:0xfffffffe->reg1,set_field:0x200000/0x600000->reg0,goto_table:ConntrackCommit",
					"cookie=0x1010000000000, table=L2ForwardingCalc, priority=190,reg4=0x100000/0x100000 actions=set_field:0x4->reg1,set_field:0x200000/0x600000->reg0,goto_table:ConntrackCommit",
					"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ip actions=ct(commit,table=VLAN,zone=NXM_NX_REG8[0..15],exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
					"cookie=0x1010000000000, table=VLAN, priority=190,in_port=4,vlan_tci=0x1000/0x1000 actions=pop_vlan,goto_table:Output",
					"cookie=0x1010000000000, table=Output, priority=210,ip,reg0=0x200000/0x600000,reg1=0xfffffffe actions=output:4294967294",
				)
				if !multicastEnabled {
					flows = append(flows,
						"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=set_field:0x1000/0xf000->reg8,goto_table:UnSNAT",
					)
				} else {
					flows = append(flows,
						"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=set_field:0x1000/0xf000->reg8,goto_table:PipelineIPClassifier",
					)
				}
			} else {
				flows = append(flows,
					"cookie=0x1010000000000, table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=65520,nat)",
					"cookie=0x1010000000000, table=L3Forwarding, priority=200,ip,reg0=0x0/0x200,nw_dst=10.10.0.0/24 actions=goto_table:L2ForwardingCalc",
					"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ip actions=ct(commit,table=Output,zone=65520,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				)
				if !multicastEnabled {
					flows = append(flows,
						"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=goto_table:UnSNAT",
					)
				} else {
					flows = append(flows,
						"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=goto_table:PipelineIPClassifier",
					)
				}
			}
		}
		if trafficControlEnabled {
			flows = append(flows,
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl",
				"cookie=0x1010000000000, table=TrafficControl, priority=210,reg0=0x200006/0x60000f actions=goto_table:Output",
				"cookie=0x1010000000000, table=Output, priority=211,reg0=0x200000/0x600000,reg4=0x400000/0xc00000 actions=output:NXM_NX_REG1[],output:NXM_NX_REG9[]",
				"cookie=0x1010000000000, table=Output, priority=211,reg0=0x200000/0x600000,reg4=0x800000/0xc00000 actions=output:NXM_NX_REG9[]",
			)
		} else {
			flows = append(flows,
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			)
		}
	case config.TrafficEncapModeNetworkPolicyOnly:
		if !isIPv4 {
			return []string{
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,ipv6_src=fe80::/10 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=SpoofGuard, priority=200,ipv6,in_port=2 actions=goto_table:IPv6",
				"cookie=0x1010000000000, table=IPv6, priority=200,icmp6,icmp_type=135,icmp_code=0 actions=NORMAL",
				"cookie=0x1010000000000, table=IPv6, priority=200,icmp6,icmp_type=136,icmp_code=0 actions=NORMAL",
				"cookie=0x1010000000000, table=IPv6, priority=200,ipv6,ipv6_dst=ff00::/8 actions=NORMAL",
				"cookie=0x1010000000000, table=Classifier, priority=210,ipv6,in_port=2,ipv6_src=fec0:10:10::1 actions=set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=Classifier, priority=200,in_port=2 actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
				"cookie=0x1010000000000, table=ConntrackZone, priority=200,ipv6 actions=ct(table=ConntrackState,zone=65510,nat)",
				"cookie=0x1010000000000, table=ConntrackState, priority=200,ct_state=+inv+trk,ipv6 actions=drop",
				"cookie=0x1010000000000, table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x0/0x10,ipv6 actions=goto_table:AntreaPolicyEgressRule",
				"cookie=0x1010000000000, table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier",
				"cookie=0x1010000000000, table=L3Forwarding, priority=210,ipv6,ipv6_dst=fec0:10:10::1 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ipv6 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=190,ipv6 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
				"cookie=0x1010000000000, table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
				"cookie=0x1010000000000, table=L3DecTTL, priority=210,ipv6,reg0=0x2/0xf actions=goto_table:SNATMark",
				"cookie=0x1010000000000, table=L3DecTTL, priority=200,ipv6 actions=dec_ttl,goto_table:SNATMark",
				"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
				"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ipv6 actions=goto_table:ConntrackCommit",
				"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ipv6 actions=ct(commit,table=Output,zone=65510,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
				"cookie=0x1010000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
			}
		}
		return []string{
			"cookie=0x1010000000000, table=ARPSpoofGuard, priority=200,arp,in_port=2,arp_spa=10.10.0.1,arp_sha=0a:00:00:00:00:01 actions=goto_table:ARPResponder",
			"cookie=0x1010000000000, table=ARPResponder, priority=200,arp,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_TPA[]->NXM_NX_REG2[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],move:NXM_NX_REG2[]->NXM_OF_ARP_SPA[],IN_PORT",
			"cookie=0x1010000000000, table=ARPResponder, priority=190,arp actions=NORMAL",
			"cookie=0x1010000000000, table=Classifier, priority=210,ip,in_port=2,nw_src=10.10.0.1 actions=set_field:0x2/0xf->reg0,goto_table:SpoofGuard",
			"cookie=0x1010000000000, table=Classifier, priority=200,in_port=2 actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard",
			"cookie=0x1010000000000, table=SpoofGuard, priority=200,ip,in_port=2 actions=goto_table:UnSNAT",
			"cookie=0x1010000000000, table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=65520,nat)",
			"cookie=0x1010000000000, table=ConntrackState, priority=200,ct_state=+inv+trk,ip actions=drop",
			"cookie=0x1010000000000, table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x0/0x10,ip actions=goto_table:AntreaPolicyEgressRule",
			"cookie=0x1010000000000, table=L3Forwarding, priority=210,ip,nw_dst=10.10.0.1 actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ip actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=190,ip actions=set_field:0a:00:00:00:00:01->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL",
			"cookie=0x1010000000000, table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc",
			"cookie=0x1010000000000, table=L3DecTTL, priority=210,ip,reg0=0x2/0xf actions=goto_table:SNATMark",
			"cookie=0x1010000000000, table=L3DecTTL, priority=200,ip actions=dec_ttl,goto_table:SNATMark",
			"cookie=0x1010000000000, table=L2ForwardingCalc, priority=200,dl_dst=0a:00:00:00:00:01 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:IngressSecurityClassifier",
			"cookie=0x1010000000000, table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ip actions=goto_table:ConntrackCommit",
			"cookie=0x1010000000000, table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0x0/0x10,ip actions=ct(commit,table=Output,zone=65520,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))",
			"cookie=0x1010000000000, table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier",
			"cookie=0x1010000000000, table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]",
		}
	}
	return flows
}

func Test_featurePodConnectivity_initFlows(t *testing.T) {
	testCases := []struct {
		name             string
		enableIPv4       bool
		enableIPv6       bool
		skipWindows      bool
		skipLinux        bool
		trafficEncapMode config.TrafficEncapModeType
		clientOptions    []clientOptionsFn
		expectedFlows    []string
	}{
		{
			name:             "IPv4 Encap",
			enableIPv4:       true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeEncap, config.TrafficEncryptionModeNone, false, true, false, false),
		},
		{
			name:             "IPv4 NoEncap",
			enableIPv4:       true,
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeNoEncap, config.TrafficEncryptionModeNone, false, true, false, false),
		},
		{
			name:             "IPv4 NoEncap with Antrea IPAM",
			enableIPv4:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			clientOptions:    []clientOptionsFn{enableConnectUplinkToBridge},
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeNoEncap, config.TrafficEncryptionModeNone, true, true, false, false),
		},
		{
			name:             "IPv4 NetworkPolicyOnly Linux",
			enableIPv4:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly,
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeNetworkPolicyOnly, config.TrafficEncryptionModeNone, false, true, false, false),
		},
		{
			name:             "IPv6 Encap",
			enableIPv6:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeEncap, config.TrafficEncryptionModeNone, false, false, false, false),
		},
		{
			name:             "IPv6 NoEncap",
			enableIPv6:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeNoEncap, config.TrafficEncryptionModeNone, false, false, false, false),
		},
		{
			name:             "IPv6 NetworkPolicyOnly",
			enableIPv6:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeNetworkPolicyOnly,
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeNetworkPolicyOnly, config.TrafficEncryptionModeNone, false, false, false, false),
		},
		{
			name:             "IPv4 Encap with TrafficControl",
			enableIPv4:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			clientOptions:    []clientOptionsFn{enableTrafficControl},
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeEncap, config.TrafficEncryptionModeNone, false, true, true, false),
		},
		{
			name:             "IPv4 Encap with WireGuard",
			enableIPv4:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			clientOptions:    []clientOptionsFn{setTrafficEncryptionMode(config.TrafficEncryptionModeWireGuard)},
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeEncap, config.TrafficEncryptionModeWireGuard, false, true, false, false),
		},
		{
			name:             "IPv4 Encap with IPsec",
			enableIPv4:       true,
			skipWindows:      true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			clientOptions:    []clientOptionsFn{setTrafficEncryptionMode(config.TrafficEncryptionModeIPSec)},
			expectedFlows:    podConnectivityInitFlows(config.TrafficEncapModeEncap, config.TrafficEncryptionModeIPSec, false, true, false, false),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			skipTest(t, tc.skipLinux, tc.skipWindows)

			fc := newFakeClient(nil, tc.enableIPv4, tc.enableIPv6, config.K8sNode, tc.trafficEncapMode, tc.clientOptions...)
			defer resetPipelines()

			flows := getFlowStrings(fc.featurePodConnectivity.initFlows())
			assert.ElementsMatch(t, tc.expectedFlows, flows)
		})
	}
}
