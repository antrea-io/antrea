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
	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// Fields using reg.
var (
	// reg0 (NXM_NX_REG0)
	// reg0[0..3]: Field to mark the packet source. Marks in this field include,
	//   - 0: from the tunnel port
	//   - 1: from antrea-gw0
	//   - 2: from the local Pods
	//   - 4: from the Bridge interface
	//   - 5: from the uplink interface
	PktSourceField     = binding.NewRegField(0, 0, 3, "PacketSource")
	FromTunnelRegMark  = binding.NewRegMark(PktSourceField, 0)
	FromGatewayRegMark = binding.NewRegMark(PktSourceField, 1)
	FromLocalRegMark   = binding.NewRegMark(PktSourceField, 2)
	FromUplinkRegMark  = binding.NewRegMark(PktSourceField, 4)
	FromBridgeRegMark  = binding.NewRegMark(PktSourceField, 5)
	// reg0[4..7]: Field to mark the packet destination. Marks in this field include,
	//   - 0: to local Pod
	//   - 1: to remote Node
	//   - 2: to external
	PktDestinationField   = binding.NewRegField(0, 4, 7, "PacketDestination")
	ToTunnelRegMark       = binding.NewRegMark(PktDestinationField, 0)
	ToGatewayRegMark      = binding.NewRegMark(PktDestinationField, 1)
	ToLocalRegMark        = binding.NewRegMark(PktDestinationField, 2)
	ToUplinkRegMark       = binding.NewRegMark(PktDestinationField, 4)
	PacketUnionField      = binding.NewRegField(0, 0, 7, "PacketUnion")
	GatewayHairpinRegMark = binding.NewRegMark(PacketUnionField, (1<<4)|1)
	// reg0[8]: Mark to indicate the ofPort number of an interface is found.
	OFPortFoundRegMark = binding.NewOneBitRegMark(0, 8, "OFPortFound")
	// reg0[9]: Mark to indicate the packet needs DNAT to virtual IP.
	// If a packet uses HairpinRegMark, it will be output to the port where it enters OVS pipeline in L2ForwardingOutTable.
	HairpinRegMark = binding.NewOneBitRegMark(0, 9, "Hairpin")
	// reg0[10]: Field to indicate that which IP should be used for hairpin connections.
	SNATWithGatewayIP        = binding.NewOneBitRegMark(0, 10, "SNATWithGatewayIP")
	SNATWithVirtualIP        = binding.NewOneBitZeroRegMark(0, 10, "SNATWithVirtualIP")
	HairpinSNATUnionField    = binding.NewRegField(0, 9, 10, "HairpinSNATUnion")
	HairpinSNATWithVirtualIP = binding.NewRegMark(HairpinSNATUnionField, 1)
	HairpinSNATWithGatewayIP = binding.NewRegMark(HairpinSNATUnionField, 3)
	// reg0[11]: Mark to indicate the packet's MAC address needs to be rewritten.
	RewriteMACRegMark = binding.NewOneBitRegMark(0, 11, "RewriteMAC")
	// reg0[12]: Mark to indicate the packet is denied(Drop/Reject).
	CnpDenyRegMark = binding.NewOneBitRegMark(0, 12, "CNPDeny")
	// reg0[13..14]: Field to indicate disposition of Antrea Policy. It could have more bits to support more disposition
	// that Antrea policy support in the future.
	// Marks in this field include,
	//   - 0b00: allow
	//   - 0b01: drop
	//   - 0b10: reject
	APDispositionField      = binding.NewRegField(0, 13, 14, "APDisposition")
	DispositionAllowRegMark = binding.NewRegMark(APDispositionField, DispositionAllow)
	DispositionDropRegMark  = binding.NewRegMark(APDispositionField, DispositionDrop)
	DispositionRejRegMark   = binding.NewRegMark(APDispositionField, DispositionRej)
	// reg0[15..18]: Field to indicate the reasons of sending packet to the controller.
	// Marks in this field include,
	//   - 0b0001: logging
	//   - 0b0010: reject
	//   - 0b0100: deny (used by Flow Exporter)
	//   - 0b1000: DNS packet (used by FQDN)
	CustomReasonField          = binding.NewRegField(0, 15, 18, "PacketInReason")
	CustomReasonLoggingRegMark = binding.NewRegMark(CustomReasonField, CustomReasonLogging)
	CustomReasonRejectRegMark  = binding.NewRegMark(CustomReasonField, CustomReasonReject)
	CustomReasonDenyRegMark    = binding.NewRegMark(CustomReasonField, CustomReasonDeny)
	CustomReasonDNSRegMark     = binding.NewRegMark(CustomReasonField, CustomReasonDNS)

	// reg1(NXM_NX_REG1)
	// Field to cache the ofPort of the OVS interface where to output packet.
	TargetOFPortField = binding.NewRegField(1, 0, 31, "TargetOFPort")
	// ToBridgeRegMark marks that the output interface is OVS bridge.
	ToBridgeRegMark = binding.NewRegMark(TargetOFPortField, config.BridgeOFPort)

	// reg2(NXM_NX_REG2)
	// Field to help swap values in two different flow fields in the OpenFlow actions. This field is only used in func
	// `arpResponderStaticFlow`.
	SwapField = binding.NewRegField(2, 0, 31, "SwapValue")

	// reg3(NXM_NX_REG3)
	// Field to store the selected Service Endpoint IP
	EndpointIPField = binding.NewRegField(3, 0, 31, "EndpointIP")
	// Field to store the conjunction ID which is for "deny" rule in CNP. It shares the same register with EndpointIPField,
	// since the service selection will finish when a packet hitting NetworkPolicy related rules.
	CNPDenyConjIDField = binding.NewRegField(3, 0, 31, "CNPDenyConjunctionID")

	// reg4(NXM_NX_REG4)
	// reg4[0..15]: Field to store the selected Service Endpoint port.
	EndpointPortField = binding.NewRegField(4, 0, 15, "EndpointPort")
	// reg4[16..18]: Field to store the state of a packet accessing a Service. Marks in this field include,
	//	- 0b001: packet need to do service selection.
	//	- 0b010: packet has done service selection.
	//	- 0b011: packet has done service selection and the selection result needs to be cached.
	ServiceEPStateField = binding.NewRegField(4, 16, 18, "EndpointState")
	EpToSelectRegMark   = binding.NewRegMark(ServiceEPStateField, 0b001)
	EpSelectedRegMark   = binding.NewRegMark(ServiceEPStateField, 0b010)
	EpToLearnRegMark    = binding.NewRegMark(ServiceEPStateField, 0b011)
	// reg4[0..18]: Field to store the union value of Endpoint port and Endpoint status. It is used as a single match
	// when needed.
	EpUnionField = binding.NewRegField(4, 0, 18, "EndpointUnion")
	// reg4[19]: Field to mark that whether Service type is NodePort.
	NodePortAddressField = binding.NewRegField(4, 19, 19, "NodePortAddress")
	// ToNodePortAddressRegMark marks that the Service type as NodePort.
	ToNodePortAddressRegMark = binding.NewRegMark(NodePortAddressField, 0b1)
	// reg4[16..19]: Field to store the union value of Endpoint state and the mark of whether Service type is NodePort.
	NodePortUnionField = binding.NewRegField(4, 16, 19, "NodePortUnion")
	// reg4[21]: Mark to indicate the packet is from local AntreaFlexibleIPAM Pod.
	// NotAntreaFlexibleIPAMRegMark will be used with RewriteMACRegMark, thus the reg id must not be same due to the limitation of ofnet library.
	AntreaFlexibleIPAMRegMark    = binding.NewOneBitRegMark(4, 21, "AntreaFlexibleIPAM")
	NotAntreaFlexibleIPAMRegMark = binding.NewOneBitZeroRegMark(4, 21, "AntreaFlexibleIPAM")
	// reg4[22..23]: Field to store the state of a connection of Service NodePort/LoadBalancer from gateway which
	// requires SNAT or not.
	//	- 0b01: connection requires SNAT and is not marked with a ct mark.
	//	- 0b11: connection requires SNAT and is marked with a ct mark.
	ServiceSNATStateField = binding.NewRegField(4, 22, 23, "ServiceSNAT")
	NotRequireSNATRegMark = binding.NewRegMark(ServiceSNATStateField, 0b00)
	RequireSNATRegMark    = binding.NewRegMark(ServiceSNATStateField, 0b01)
	CTMarkedSNATRegMark   = binding.NewRegMark(ServiceSNATStateField, 0b11)

	// reg5(NXM_NX_REG5)
	// Field to cache the Egress conjunction ID hit by TraceFlow packet.
	TFEgressConjIDField = binding.NewRegField(5, 0, 31, "TFEgressConjunctionID")

	// reg6(NXM_NX_REG6)
	// Field to store the Ingress conjunction ID hit by TraceFlow packet.
	TFIngressConjIDField = binding.NewRegField(6, 0, 31, "TFIngressConjunctionID")

	// reg7(NXM_NX_REG7)
	// Field to store the GroupID corresponding to the Service
	ServiceGroupIDField = binding.NewRegField(7, 0, 31, "ServiceGroupID")
)

// Fields using xxreg.
var (
	// xxreg3(NXM_NX_XXREG3)
	// xxreg3: Field to cache Endpoint IPv6 address. It occupies reg12-reg15 in the meanwhile.
	EndpointIP6Field = binding.NewXXRegField(3, 0, 127)
)

// Marks using CT.
var (
	//TODO: There is a bug in libOpenflow when CT_MARK range is from 0 to 0, and a wrong mask will be got,
	// so bit 0 of CT_MARK is not used for now.

	// Mark to indicate the connection is initiated through the host gateway interface
	// (i.e. for which the first packet of the connection was received through the gateway).
	// This CT mark is only used in CtZone / CtZoneV6.
	FromGatewayCTMark = binding.NewCTMark(0b1, 1, 1)
	// Mark to indicate DNAT is performed on the connection for Service.
	// This CT mark is both used in CtZone / CtZoneV6 and SNATCtZone / SNATCtZoneV6.
	ServiceCTMark = binding.NewCTMark(0b1, 2, 2)
	// Mark to indicate the connection is initiated through the host bridge interface
	// (i.e. for which the first packet of the connection was received through the bridge).
	// This CT mark is only used in CtZone / CtZoneV6.
	FromBridgeCTMark = binding.NewCTMark(0xb1, 3, 3)
	// Mark to indicate SNAT should be performed on the connection for Service.
	// This CT mark is only used in CtZone / CtZoneV6.
	ServiceSNATCTMark = binding.NewCTMark(0b1, 4, 4)
	// Mark to indicate the connection is hairpin.
	// This CT mark is only used in SNATCtZone / SNATCtZoneV6.
	HairpinCTMark = binding.NewCTMark(0b1, 5, 5)
	// Mark to indicate the connection is hairpin and Service.
	// This CT mark is only used in SNATCtZone / SNATCtZoneV6.
	UnionHairpinServiceCTMark = binding.NewCTMark(0b11, 4, 5)
)

// Fields using CT label.
var (
	// Field to store the ingress rule ID.
	IngressRuleCTLabel = binding.NewCTLabel(0, 31, "ingressRuleCTLabel")

	// Field to store the egress rule ID.
	EgressRuleCTLabel = binding.NewCTLabel(32, 63, "egressRuleCTLabel")
)
