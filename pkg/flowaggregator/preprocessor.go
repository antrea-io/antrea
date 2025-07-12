// Copyright 2025 Antrea Authors
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

package flowaggregator

import (
	"net"
	"net/netip"

	"github.com/vmware/go-ipfix/pkg/entities"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"

<<<<<<< HEAD
	flowpb "antrea.io/antrea/apis/pkg/apis/flow/v1alpha1"
=======
	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
>>>>>>> origin/main
)

// preprocessor is in charge of converting data records in IPFIX messages received from the IPFIX
// collector to individual Protobuf messages (one per record). If an IPFIX record has extra fields
// (no corresponding field in Protobuf), these will be discarded. If some fields are missing, the
// default Protobuf field value will be used.
type preprocessor struct {
	inCh  <-chan *entities.Message
	outCh chan<- *flowpb.Flow
}

func newPreprocessor(inCh <-chan *entities.Message, outCh chan<- *flowpb.Flow) (*preprocessor, error) {
	return &preprocessor{
		inCh:  inCh,
		outCh: outCh,
	}, nil
}

func (p *preprocessor) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case msg, ok := <-p.inCh:
			if !ok {
				return
			}
			p.processMsg(msg)
		}
	}
}

func (p *preprocessor) processMsg(msg *entities.Message) {
	set := msg.GetSet()
	if set.GetSetType() != entities.Data {
		return
	}
	records := set.GetRecords()
	if len(records) == 0 {
		return
	}
	exportTime := msg.GetExportTime()
	sequenceNum := msg.GetSequenceNum()
	obsDomainID := msg.GetObsDomainID()
	exportAddr := msg.GetExportAddress()
	for _, record := range records {
		elementList := record.GetOrderedElementList()
		flow := &flowpb.Flow{
			Ipfix: &flowpb.IPFIX{
				ExportTime: &timestamppb.Timestamp{
					Seconds: int64(exportTime),
				},
				SequenceNumber:      sequenceNum,
				ObservationDomainId: obsDomainID,
				ExporterIp:          exportAddr,
			},
			StartTs:      &timestamppb.Timestamp{},
			EndTs:        &timestamppb.Timestamp{},
			Ip:           &flowpb.IP{},
			Transport:    &flowpb.Transport{},
			K8S:          &flowpb.Kubernetes{},
			Stats:        &flowpb.Stats{},
			ReverseStats: &flowpb.Stats{},
			App:          &flowpb.App{},
		}
		sequenceNum++
		for _, ie := range elementList {
			name := ie.GetName()
			switch name {
			case "flowStartSeconds":
				flow.StartTs.Seconds = int64(ie.GetUnsigned32Value())
			case "flowEndSeconds":
				flow.EndTs.Seconds = int64(ie.GetUnsigned32Value())
			case "flowEndReason":
				flow.EndReason = flowpb.FlowEndReason(ie.GetUnsigned8Value())
			case "sourceIPv4Address":
				flow.Ip.Version = flowpb.IPVersion_IP_VERSION_4
				// This is guaranteed to be a slice of length 4, as the Information
				// Element has length 4.
				flow.Ip.Source = ie.GetIPAddressValue()
			case "destinationIPv4Address":
				flow.Ip.Destination = ie.GetIPAddressValue()
			case "sourceIPv6Address":
				flow.Ip.Version = flowpb.IPVersion_IP_VERSION_6
				flow.Ip.Source = ie.GetIPAddressValue()
			case "destinationIPv6Address":
				flow.Ip.Destination = ie.GetIPAddressValue()
			case "sourceTransportPort":
				flow.Transport.SourcePort = uint32(ie.GetUnsigned16Value())
			case "destinationTransportPort":
				flow.Transport.DestinationPort = uint32(ie.GetUnsigned16Value())
			case "protocolIdentifier":
				flow.Transport.ProtocolNumber = uint32(ie.GetUnsigned8Value())
			case "packetTotalCount":
				flow.Stats.PacketTotalCount = ie.GetUnsigned64Value()
			case "octetTotalCount":
				flow.Stats.OctetTotalCount = ie.GetUnsigned64Value()
			case "packetDeltaCount":
				flow.Stats.PacketDeltaCount = ie.GetUnsigned64Value()
			case "octetDeltaCount":
				flow.Stats.OctetDeltaCount = ie.GetUnsigned64Value()
			case "reversePacketTotalCount":
				flow.ReverseStats.PacketTotalCount = ie.GetUnsigned64Value()
			case "reverseOctetTotalCount":
				flow.ReverseStats.OctetTotalCount = ie.GetUnsigned64Value()
			case "reversePacketDeltaCount":
				flow.ReverseStats.PacketDeltaCount = ie.GetUnsigned64Value()
			case "reverseOctetDeltaCount":
				flow.ReverseStats.OctetDeltaCount = ie.GetUnsigned64Value()
			case "sourcePodNamespace":
				flow.K8S.SourcePodNamespace = ie.GetStringValue()
			case "sourcePodName":
				flow.K8S.SourcePodName = ie.GetStringValue()
			case "sourceNodeName":
				flow.K8S.SourceNodeName = ie.GetStringValue()
			case "destinationPodNamespace":
				flow.K8S.DestinationPodNamespace = ie.GetStringValue()
			case "destinationPodName":
				flow.K8S.DestinationPodName = ie.GetStringValue()
			case "destinationNodeName":
				flow.K8S.DestinationNodeName = ie.GetStringValue()
			case "destinationClusterIPv4":
				// The IE will be a slice of zeros when this IP is not available,
				// but for the protobuf message we prefer using the default value (nil).
				ip := ie.GetIPAddressValue()
				if !ip.Equal(net.IPv4zero) {
					flow.K8S.DestinationClusterIp = ie.GetIPAddressValue()
				}
			case "destinationClusterIPv6":
				ip := ie.GetIPAddressValue()
				if !ip.Equal(net.IPv6zero) {
					flow.K8S.DestinationClusterIp = ie.GetIPAddressValue()
				}
			case "destinationServicePort":
				flow.K8S.DestinationServicePort = uint32(ie.GetUnsigned16Value())
			case "destinationServicePortName":
				flow.K8S.DestinationServicePortName = ie.GetStringValue()
			case "ingressNetworkPolicyName":
				flow.K8S.IngressNetworkPolicyName = ie.GetStringValue()
			case "ingressNetworkPolicyNamespace":
				flow.K8S.IngressNetworkPolicyNamespace = ie.GetStringValue()
			case "ingressNetworkPolicyType":
				flow.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType(ie.GetUnsigned8Value())
			case "ingressNetworkPolicyRuleName":
				flow.K8S.IngressNetworkPolicyRuleName = ie.GetStringValue()
			case "ingressNetworkPolicyRuleAction":
				flow.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction(ie.GetUnsigned8Value())
			case "egressNetworkPolicyName":
				flow.K8S.EgressNetworkPolicyName = ie.GetStringValue()
			case "egressNetworkPolicyNamespace":
				flow.K8S.EgressNetworkPolicyNamespace = ie.GetStringValue()
			case "egressNetworkPolicyType":
				flow.K8S.EgressNetworkPolicyType = flowpb.NetworkPolicyType(ie.GetUnsigned8Value())
			case "egressNetworkPolicyRuleName":
				flow.K8S.EgressNetworkPolicyRuleName = ie.GetStringValue()
			case "egressNetworkPolicyRuleAction":
				flow.K8S.EgressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction(ie.GetUnsigned8Value())
			case "tcpState":
				state := ie.GetStringValue()
				if state != "" {
					flow.Transport.Protocol = &flowpb.Transport_TCP{
						TCP: &flowpb.TCP{
							StateName: state,
						},
					}
				}
			case "flowType":
				flow.K8S.FlowType = flowpb.FlowType(ie.GetUnsigned8Value())
			case "egressName":
				flow.K8S.EgressName = ie.GetStringValue()
			case "egressIP":
				ipStr := ie.GetStringValue()
				if ipStr != "" {
					addr, err := netip.ParseAddr(ipStr)
					if err != nil {
						klog.ErrorS(err, "Invalid egressIP in flow record", "egressIP", ipStr)
					} else {
						flow.K8S.EgressIp = addr.AsSlice()
					}
				}
			case "appProtocolName":
				flow.App.ProtocolName = ie.GetStringValue()
			case "httpVals":
				flow.App.HttpVals = []byte(ie.GetStringValue())
			case "egressNodeName":
				flow.K8S.EgressNodeName = ie.GetStringValue()
			}
		}

		p.outCh <- flow
	}
}
