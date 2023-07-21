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

package openflow

import (
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// Fields using reg.
var (
	tunnelVal   = uint32(1)
	gatewayVal  = uint32(2)
	localVal    = uint32(3)
	uplinkVal   = uint32(4)
	bridgeVal   = uint32(5)
	tcReturnVal = uint32(6)

	outputToPortVal       = uint32(1)
	outputToControllerVal = uint32(2)

	// reg0 (NXM_NX_REG0)
	// reg0[0..3]: Field to store the packet source. Marks in this field include:
	//   - 1: from tunnel port.
	//   - 2: from Antrea gateway port.
	//   - 3: from local Pods.
	//   - 4: from uplink port.
	//   - 5: from bridge local port.
	//   - 6: from traffic control return port.
	PktSourceField      = binding.NewRegField(0, 0, 3)
	FromTunnelRegMark   = binding.NewRegMark(PktSourceField, tunnelVal)
	FromGatewayRegMark  = binding.NewRegMark(PktSourceField, gatewayVal)
	FromLocalRegMark    = binding.NewRegMark(PktSourceField, localVal)
	FromUplinkRegMark   = binding.NewRegMark(PktSourceField, uplinkVal)
	FromBridgeRegMark   = binding.NewRegMark(PktSourceField, bridgeVal)
	FromTCReturnRegMark = binding.NewRegMark(PktSourceField, tcReturnVal)
	// reg0[4..7]: Field to store the packet destination. Marks in this field include:
	//   - 1: to tunnel port.
	//   - 2: to Antrea gateway port.
	//   - 3: to local Pods.
	//   - 4: to uplink port.
	//   - 5: to bridge local port.
	PktDestinationField = binding.NewRegField(0, 4, 7)
	ToTunnelRegMark     = binding.NewRegMark(PktDestinationField, tunnelVal)
	ToGatewayRegMark    = binding.NewRegMark(PktDestinationField, gatewayVal)
	ToUplinkRegMark     = binding.NewRegMark(PktDestinationField, uplinkVal)
	// reg0[9]: Field to indicate whether the packet's source / destination MAC address needs to be rewritten.
	RewriteMACRegMark    = binding.NewOneBitRegMark(0, 9)
	NotRewriteMACRegMark = binding.NewOneBitZeroRegMark(0, 9)
	// reg0[10]: Mark to indicate the packet is denied(Drop/Reject) for Antrea Policy.
	// K8s default drop will not be recorded in this reg.
	APDenyRegMark = binding.NewOneBitRegMark(0, 10)
	// reg0[11..12]: Field to indicate disposition of Antrea Policy. It could have more bits to support more dispositions
	// that Antrea Policy support in the future. Marks in this field include:
	//   - 0b00: allow
	//   - 0b01: drop
	//   - 0b11: pass
	APDispositionField      = binding.NewRegField(0, 11, 12)
	DispositionAllowRegMark = binding.NewRegMark(APDispositionField, DispositionAllow)
	DispositionDropRegMark  = binding.NewRegMark(APDispositionField, DispositionDrop)
	DispositionPassRegMark  = binding.NewRegMark(APDispositionField, DispositionPass)
	// reg0[13]: Mark to indicate the packet is a generated reject response packet-out.
	GeneratedRejectPacketOutRegMark = binding.NewOneBitRegMark(0, 13)
	// reg0[14]: Mark to indicate a Service without any Endpoints (used by Proxy)
	SvcNoEpRegMark = binding.NewOneBitRegMark(0, 14)
	// reg0[19]: Mark to indicate remote SNAT for Egress.
	RemoteSNATRegMark = binding.NewOneBitRegMark(0, 19)
	// reg0[20]: Field to indicate redirect action of layer 7 NetworkPolicy.
	L7NPRegField        = binding.NewRegField(0, 20, 20)
	L7NPRedirectRegMark = binding.NewRegMark(L7NPRegField, DispositionL7NPRedirect)
	// reg0[21..22]: Field to indicate how the packet leaves OVS pipeline. Marks in this field include:
	//   - 1: Output to an OVS port.
	//   - 2: Send packet to Antrea Agent.
	OutputRegField            = binding.NewRegField(0, 21, 22)
	OutputToOFPortRegMark     = binding.NewRegMark(OutputRegField, outputToPortVal)
	OutputToControllerRegMark = binding.NewRegMark(OutputRegField, outputToControllerVal)
	// reg0[25..32]: Field to indicate Antrea-native policy packetIn operations
	PacketInOperationField = binding.NewRegField(0, 25, 32)

	// reg1(NXM_NX_REG1)
	// Field to cache the ofPort of the OVS interface where to output packet.
	TargetOFPortField = binding.NewRegField(1, 0, 31)

	// reg2(NXM_NX_REG2)
	// Field to help swap values in two different flow fields in the OpenFlow actions. This field is only used in func
	// `arpResponderStaticFlow`.
	SwapField = binding.NewRegField(2, 0, 31)
	// Field to store the OVS table where the packet is decided to be sent to controller. This may be different from
	// packetIn.TableId where the flow with "SendToController" action is located as we may install the packetIn flows
	// in a single table, e.g., Antrea-native policy logging flows.
	PacketInTableField = binding.NewRegField(2, 0, 7)

	// reg3(NXM_NX_REG3)
	// Field to store the selected Service Endpoint IP
	EndpointIPField = binding.NewRegField(3, 0, 31)
	// Field to store the conjunction ID which is for rule in Antrea Policy. It shares the same register with EndpointIPField,
	// since the service selection will finish when a packet hitting NetworkPolicy related rules.
	APConjIDField = binding.NewRegField(3, 0, 31)

	// reg4(NXM_NX_REG4)
	// reg4[0..15]: Field to store the selected Service Endpoint port.
	EndpointPortField = binding.NewRegField(4, 0, 15)
	// reg4[16..18]: Field to store the state of a packet accessing a Service. Marks in this field include:
	//	- 0b001: packet need to do service selection.
	//	- 0b010: packet has done service selection.
	//	- 0b011: packet has done service selection and the selection result needs to be cached.
	ServiceEPStateField = binding.NewRegField(4, 16, 18)
	EpToSelectRegMark   = binding.NewRegMark(ServiceEPStateField, 0b001)
	EpSelectedRegMark   = binding.NewRegMark(ServiceEPStateField, 0b010)
	EpToLearnRegMark    = binding.NewRegMark(ServiceEPStateField, 0b011)
	// reg4[0..18]: Field to store the union value of Endpoint port and Endpoint status. It is used as a single match
	// when needed.
	EpUnionField = binding.NewRegField(4, 0, 18)
	// reg4[19]: Mark to indicate the Service type is NodePort.
	ToNodePortAddressRegMark = binding.NewOneBitRegMark(4, 19)
	// reg4[20]: Field to indicate whether the packet is from local Antrea IPAM Pod. NotAntreaFlexibleIPAMRegMark will
	// be used with RewriteMACRegMark, thus the reg id must not be same due to the limitation of ofnet library.
	AntreaFlexibleIPAMRegMark    = binding.NewOneBitRegMark(4, 20)
	NotAntreaFlexibleIPAMRegMark = binding.NewOneBitZeroRegMark(4, 20)
	// reg4[21]: Mark to indicate whether the packet is to a Service's external IP, like NodePort, LoadBalancerIP or ExternalIP.
	ToExternalAddressRegMark = binding.NewOneBitRegMark(4, 21)
	// reg4[22..23]: Field to store the action of a traffic control rule. Marks in this field include:
	TrafficControlActionField     = binding.NewRegField(4, 22, 23)
	TrafficControlMirrorRegMark   = binding.NewRegMark(TrafficControlActionField, 0b01)
	TrafficControlRedirectRegMark = binding.NewRegMark(TrafficControlActionField, 0b10)
	// reg4[24]: Mark to indicate that whether the Service is backed by Service IPs of other Services.
	NestedServiceRegMark = binding.NewOneBitRegMark(4, 24)
	// reg4[25]: Mark to indicate that whether the Service traffic works in DSR mode.
	DSRServiceRegMark    = binding.NewOneBitRegMark(4, 25)
	NotDSRServiceRegMark = binding.NewOneBitZeroRegMark(4, 25)
	// reg4[26]: Mark to indicate that whether a remote non-hostNetwork Endpoint is selected.
	RemoteEndpointRegMark = binding.NewOneBitRegMark(4, 26)
	// reg4[27]: Mark to indicate that whether the traffic's source is an external IP.
	// If a packet is from gateway but its source IP is not the gateway IP, it's considered external sourced traffic.
	// The masquerade rule in iptables nat table guarantees the other IPs of the Node won't be used as source IP when
	// the Node's traffic is forwarded to OVS. And even if there is no masquerade rule, there should be no problem to
	// consider the packet external sourced as the other IPs are routable externally anyway.
	FromExternalRegMark = binding.NewOneBitRegMark(4, 27)

	// reg5(NXM_NX_REG5)
	// Field to cache the Egress conjunction ID hit by TraceFlow packet.
	TFEgressConjIDField = binding.NewRegField(5, 0, 31)

	// reg6(NXM_NX_REG6)
	// Field to store the Ingress conjunction ID hit by TraceFlow packet.
	TFIngressConjIDField = binding.NewRegField(6, 0, 31)

	// reg7(NXM_NX_REG7)
	// Field to store the GroupID corresponding to the Service.
	ServiceGroupIDField = binding.NewRegField(7, 0, 31)

	// reg8(NXM_NX_REG8)
	// Field to store the VLAN ID. Valid value is 0~4094. value=0 indicates packet without 802.1q header.
	// VLANIDField for all incoming IP/IPv6 traffic with VLAN must be set explicitly at ClassifierTable or SpoofGuardTable.
	VLANIDField = binding.NewRegField(8, 0, 11)
	// Field to store the CtZone type.
	// CtZoneTypeField for all incoming IP/IPv6 traffic must be set explicitly at ClassifierTable or SpoofGuardTable.
	CtZoneTypeField       = binding.NewRegField(8, 12, 15)
	IPCtZoneTypeRegMark   = binding.NewRegMark(CtZoneTypeField, 0b0001)
	IPv6CtZoneTypeRegMark = binding.NewRegMark(CtZoneTypeField, 0b0011)
	// Field to store the CtZone ID, which is a combination of VLANIDField and CtZoneTypeField to indicate CtZone for DstNAT.
	CtZoneField = binding.NewRegField(8, 0, 15)

	// reg9(NXM_NX_REG9)
	// Field to cache the ofPort of the OVS interface to output traffic control packets.
	TrafficControlTargetOFPortField = binding.NewRegField(9, 0, 31)
)

// Fields using xxreg.
var (
	// xxreg3(NXM_NX_XXREG3)
	// xxreg3: Field to cache Endpoint IPv6 address. It occupies reg12-reg15 in the meanwhile.
	EndpointIP6Field = binding.NewXXRegField(3, 0, 127)
)

// Marks using CT.
var (
	// TODO: There is a bug in libOpenflow when CT_MARK range is from 0 to 0, and a wrong mask will be got. As a result,
	// don't just use bit 0 of CT_MARK.

	// CTMark (NXM_NX_CT_MARK)
	// CTMark[0..3]: Field to mark the source of the connection. This field has the same bits and positions as PktSourceField
	// for persisting the value from reg0 to CTMark when committing the first packet of the connection with CT action.
	// This CT mark is only used in CtZone / CtZoneV6.
	ConnSourceCTMarkField = binding.NewCTMarkField(0, 3)
	FromGatewayCTMark     = binding.NewCTMark(ConnSourceCTMarkField, gatewayVal)
	FromBridgeCTMark      = binding.NewCTMark(ConnSourceCTMarkField, bridgeVal)

	// CTMark[4]: Marks to indicate whether DNAT is performed on the connection for Service.
	// These CT marks are used in CtZone / CtZoneV6 and SNATCtZone / SNATCtZoneV6.
	ServiceCTMark    = binding.NewOneBitCTMark(4)
	NotServiceCTMark = binding.NewOneBitZeroCTMark(4)

	// CTMark[5]: Mark to indicate SNAT is performed on the connection for Service.
	// This CT mark is only used in CtZone / CtZoneV6.
	ConnSNATCTMark = binding.NewOneBitCTMark(5)

	// CTMark[6]: Mark to indicate the connection is hairpin.
	// This CT mark is used in CtZone / CtZoneV6 and SNATCtZone / SNATCtZoneV6.
	HairpinCTMark = binding.NewOneBitCTMark(6)

	// CTMark[7]: Mark to indicate the connection should be redirected to an application-aware engine. This mark is only
	// for L7 NetworkPolicy.
	// This CT mark is used in CtZone / CtZoneV6.
	L7NPRedirectCTMark = binding.NewOneBitCTMark(7)
)

// Fields using CT label.
var (
	// Field to store the ingress rule ID.
	IngressRuleCTLabel = binding.NewCTLabel(0, 31)

	// Field to store the egress rule ID.
	EgressRuleCTLabel = binding.NewCTLabel(32, 63)

	// Field to store the VLAN ID allocated for a L7 NetworkPolicy rule.
	L7NPRuleVlanIDCTLabel = binding.NewCTLabel(64, 75)
)
