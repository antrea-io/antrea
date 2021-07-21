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
	// reg0[16]: Mark to indicate the ofPort number of an interface is found.
	OFPortFoundRegMark = binding.NewOneBitRegMark(0, 16, "OFPortFound")
	// reg0[17]: Mark to indicate the packet needs to be SNATed with Node's IP.
	SNATNodeIPRegMark = binding.NewOneBitRegMark(0, 17, "SNATWithNodeIP")
	// reg0[18]: Mark to indicate the packet needs DNAT to virtual IP.
	// If a packet uses HairpinRegMark, it will be output to the port where it enters OVS pipeline in L2ForwardingOutTable.
	HairpinRegMark = binding.NewOneBitRegMark(0, 18, "Hairpin")
	// reg0[19]: Mark to indicate the packet's MAC address needs to be rewritten.
	RewriteMACRegMark = binding.NewOneBitRegMark(0, 19, "RewriteMAC")
	// reg0[20]: Mark to indicate the packet is denied(Drop/Reject).
	CnpDenyRegMark = binding.NewOneBitRegMark(0, 20, "CNPDeny")
	// reg0[21..22]: Field to indicate disposition of Antrea Policy. It could have more bits to support more disposition
	// that Antrea policy support in the future.
	// Marks in this field include,
	//   - 0b00: allow
	//   - 0b01: drop
	//   - 0b10: reject
	APDispositionField      = binding.NewRegField(0, 21, 22, "APDisposition")
	DispositionAllowRegMark = binding.NewRegMark(APDispositionField, DispositionAllow)
	DispositionDropRegMark  = binding.NewRegMark(APDispositionField, DispositionDrop)
	DispositionRejRegMark   = binding.NewRegMark(APDispositionField, DispositionRej)
	// reg0[24..27]: Field to indicate the reasons of sending packet to the controller.
	// Marks in this field include,
	//   - 0b0001: logging
	//   - 0b0010: reject
	//   - 0b0100: deny (used by Flow Exporter)
	//   - 0b1000: DNS packet (used by FQDN)
	CustomReasonField          = binding.NewRegField(0, 24, 27, "PacketInReason")
	CustomReasonLoggingRegMark = binding.NewRegMark(CustomReasonField, CustomReasonLogging)
	CustomReasonRejectRegMark  = binding.NewRegMark(CustomReasonField, CustomReasonReject)
	CustomReasonDenyRegMark    = binding.NewRegMark(CustomReasonField, CustomReasonDeny)
	CustomReasonDNSRegMark     = binding.NewRegMark(CustomReasonField, CustomReasonDNS)

	// reg1(NXM_NX_REG1)
	// Field to cache the ofPort of the OVS interface where to output packet.
	TargetOFPortField = binding.NewRegField(1, 0, 31, "TargetOFPort")
	// ToGatewayRegMark marks that the output interface is Antrea gateway.
	ToGatewayRegMark = binding.NewRegMark(TargetOFPortField, config.HostGatewayOFPort)
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
	// reg4[20]: Field to mark that whether the packet of Service NodePort/LoadBalancer from gateway requires SNAT.
	ServiceSNATField = binding.NewRegField(4, 20, 20, "ServiceSNAT")
	// ServiceNeedSNATRegMark marks that the packet of Service NodePort/LoadBalancer requires SNAT.
	ServiceNeedSNATRegMark = binding.NewRegMark(ServiceSNATField, 0b1)
	// reg4[16..19]: Field to store the union value of Endpoint state and the mark of whether Service type is NodePort.
	NodePortUnionField = binding.NewRegField(4, 16, 19, "NodePortUnion")
	// reg4[21]: Mark to indicate the packet is from local AntreaFlexibleIPAM Pod.
	// NotAntreaFlexibleIPAMRegMark will be used with RewriteMACRegMark, thus the reg id must not be same due to the limitation of ofnet library.
	AntreaFlexibleIPAMRegMark    = binding.NewOneBitRegMark(4, 21, "AntreaFlexibleIPAM")
	NotAntreaFlexibleIPAMRegMark = binding.NewOneBitZeroRegMark(4, 21, "AntreaFlexibleIPAM")

	// reg5(NXM_NX_REG5)
	// Field to cache the Egress conjunction ID hit by TraceFlow packet.
	TFEgressConjIDField = binding.NewRegField(5, 0, 31, "TFEgressConjunctionID")

	// reg(N6XM_NX_REG6)
	// Field to store the Ingress conjunction ID hit by TraceFlow packet.
	TFIngressConjIDField = binding.NewRegField(6, 0, 31, "TFIngressConjunctionID")
)

// Fields using xxreg.
var (
	// xxreg3(NXM_NX_XXREG3)
	// xxreg3: Field to cache Endpoint IPv6 address. It occupies reg12-reg15 in the meanwhile.
	EndpointIP6Field = binding.NewXXRegField(3, 0, 127)
)

// Marks using CT.
var (
	// Mark to indicate the connection is initiated through the host gateway interface
	// (i.e. for which the first packet of the connection was received through the gateway).
	FromGatewayCTMark = binding.NewCTMark(0x20, 0, 31)
	// Mark to indicate DNAT is performed on the connection for Service.
	ServiceCTMark = binding.NewCTMark(0x21, 0, 31)
	// Mark to indicate the connection is initiated through the host bridge interface
	// (i.e. for which the first packet of the connection was received through the bridge).
	FromBridgeCTMark = binding.NewCTMark(0x22, 0, 31)
)

// Fields using CT label.
var (
	// Field to store the ingress rule ID.
	IngressRuleCTLabel = binding.NewCTLabel(0, 31, "ingressRuleCTLabel")

	// Field to store the egress rule ID.
	EgressRuleCTLabel = binding.NewCTLabel(32, 63, "egressRuleCTLabel")
)
