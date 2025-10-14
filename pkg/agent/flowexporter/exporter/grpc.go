// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"context"
	"fmt"
	"net/netip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
)

type grpcExporter struct {
	nodeName    string
	nodeUID     string
	obsDomainID uint32
	grpcClient  *grpc.ClientConn
	client      flowpb.FlowExportServiceClient
	stream      flowpb.FlowExportService_ExportClient
}

func NewGRPCExporter(nodeName string, nodeUID string, obsDomainID uint32) *grpcExporter {
	return &grpcExporter{
		nodeName:    nodeName,
		nodeUID:     nodeUID,
		obsDomainID: obsDomainID,
	}
}

func (e *grpcExporter) ConnectToCollector(addr string, tlsConfig *TLSConfig) error {
	klog.InfoS("Connecting to gRPC collector", "addr", addr)
	tls, err := tlsConfig.AsStdConfig()
	if err != nil {
		return err
	}
	grpcClient, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	e.grpcClient = grpcClient
	client := flowpb.NewFlowExportServiceClient(grpcClient)
	e.client = client
	stream, err := client.Export(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to create gRPC stream to export connections: %w", err)
	}
	e.stream = stream
	return nil
}

func (e *grpcExporter) Export(conn *connection.Connection) error {
	// It is not safe to modify the message after calling SendMsg, so we need to allocate a
	// brand new message every time.
	// We could investigate using grpc.PreparedMsg to see if it helps reduce the number of
	// allocations, but that is an experimental API:
	// https://github.com/grpc/grpc-go/issues/8186
	flow := e.createMessage(conn)
	return e.stream.Send(&flowpb.ExportRequest{
		// At the moment, we send a single flow per stream message because it's simpler.
		// Note that there should still be some batching at the transport layer.
		// In the future, we should try to do explicit batching.
		Flows: []*flowpb.Flow{flow},
	})
}

func (e *grpcExporter) CloseConnToCollector() {
	if e.grpcClient != nil {
		e.grpcClient.Close()
		e.grpcClient = nil
		e.client = nil
		e.stream = nil
	}
}

func (e *grpcExporter) createMessage(conn *connection.Connection) *flowpb.Flow {
	ipVersion := flowpb.IPVersion_IP_VERSION_4
	if conn.FlowKey.SourceAddress.Is6() {
		ipVersion = flowpb.IPVersion_IP_VERSION_6
	}
	flow := &flowpb.Flow{
		Id: "", // not used currently
		Ipfix: &flowpb.IPFIX{
			ExportTime:          timestamppb.Now(),
			ObservationDomainId: e.obsDomainID,
		},
		StartTs: timestamppb.New(conn.StartTime),
		EndTs:   timestamppb.New(conn.StopTime),
		Ip: &flowpb.IP{
			Version:     ipVersion,
			Source:      conn.FlowKey.SourceAddress.AsSlice(),
			Destination: conn.FlowKey.DestinationAddress.AsSlice(),
		},
		Transport: &flowpb.Transport{
			SourcePort:      uint32(conn.FlowKey.SourcePort),
			DestinationPort: uint32(conn.FlowKey.DestinationPort),
			ProtocolNumber:  uint32(conn.FlowKey.Protocol),
		},
		K8S: &flowpb.Kubernetes{
			FlowType:                       flowpb.FlowType(conn.FlowType),
			SourcePodNamespace:             conn.SourcePodNamespace,
			SourcePodName:                  conn.SourcePodName,
			SourcePodUid:                   conn.SourcePodUID,
			DestinationPodNamespace:        conn.DestinationPodNamespace,
			DestinationPodName:             conn.DestinationPodName,
			DestinationPodUid:              conn.DestinationPodUID,
			IngressNetworkPolicyNamespace:  conn.IngressNetworkPolicyNamespace,
			IngressNetworkPolicyName:       conn.IngressNetworkPolicyName,
			IngressNetworkPolicyUid:        conn.IngressNetworkPolicyUID,
			IngressNetworkPolicyType:       flowpb.NetworkPolicyType(conn.IngressNetworkPolicyType),
			IngressNetworkPolicyRuleName:   conn.IngressNetworkPolicyRuleName,
			IngressNetworkPolicyRuleAction: flowpb.NetworkPolicyRuleAction(conn.IngressNetworkPolicyRuleAction),
			EgressNetworkPolicyNamespace:   conn.EgressNetworkPolicyNamespace,
			EgressNetworkPolicyName:        conn.EgressNetworkPolicyName,
			EgressNetworkPolicyUid:         conn.EgressNetworkPolicyUID,
			EgressNetworkPolicyType:        flowpb.NetworkPolicyType(conn.EgressNetworkPolicyType),
			EgressNetworkPolicyRuleName:    conn.EgressNetworkPolicyRuleName,
			EgressNetworkPolicyRuleAction:  flowpb.NetworkPolicyRuleAction(conn.EgressNetworkPolicyRuleAction),
			EgressName:                     conn.EgressName,
			EgressNodeName:                 conn.EgressNodeName,
			EgressUid:                      conn.EgressUID,
		},
		Stats: &flowpb.Stats{
			PacketTotalCount: conn.OriginalStats.Packets,
			OctetTotalCount:  conn.OriginalStats.Bytes,
		},
		ReverseStats: &flowpb.Stats{
			PacketTotalCount: conn.OriginalStats.ReversePackets,
			OctetTotalCount:  conn.OriginalStats.ReverseBytes,
		},
		App: &flowpb.App{
			ProtocolName: conn.AppProtocolName,
			HttpVals:     []byte(conn.HttpVals),
		},
	}
	if utils.IsConnectionDying(conn) {
		flow.EndReason = flowpb.FlowEndReason_FLOW_END_REASON_END_OF_FLOW
	} else if conn.IsActive {
		flow.EndReason = flowpb.FlowEndReason_FLOW_END_REASON_ACTIVE_TIMEOUT
	} else {
		flow.EndReason = flowpb.FlowEndReason_FLOW_END_REASON_IDLE_TIMEOUT
	}
	// Add nodeName / nodeUID only for local Pods whose Pod names are resolved.
	if conn.SourcePodName != "" {
		flow.K8S.SourceNodeName = e.nodeName
		flow.K8S.SourceNodeUid = e.nodeUID
	}
	if conn.DestinationPodName != "" {
		flow.K8S.DestinationNodeName = e.nodeName
		flow.K8S.DestinationNodeUid = e.nodeUID
	}
	if conn.DestinationServicePortName != "" {
		flow.K8S.DestinationClusterIp = conn.OriginalDestinationAddress.AsSlice()
		flow.K8S.DestinationServicePort = uint32(conn.OriginalDestinationPort)
		flow.K8S.DestinationServicePortName = conn.DestinationServicePortName
	}
	if conn.OriginalStats.Packets < conn.PreviousStats.Packets {
		klog.InfoS("Packet delta count for connection should not be negative")
	} else {
		flow.Stats.PacketDeltaCount = conn.OriginalStats.Packets - conn.PreviousStats.Packets
	}
	if conn.OriginalStats.Bytes < conn.PreviousStats.Bytes {
		klog.InfoS("Byte delta count for connection should not be negative")
	} else {
		flow.Stats.OctetDeltaCount = conn.OriginalStats.Bytes - conn.PreviousStats.Bytes
	}
	if conn.OriginalStats.ReversePackets < conn.PreviousStats.ReversePackets {
		klog.InfoS("Reverse packet delta count for connection should not be negative")
	} else {
		flow.ReverseStats.PacketDeltaCount = conn.OriginalStats.ReversePackets - conn.PreviousStats.ReversePackets
	}
	if conn.OriginalStats.ReverseBytes < conn.PreviousStats.ReverseBytes {
		klog.InfoS("Reverse byte delta count for connection should not be negative")
	} else {
		flow.ReverseStats.OctetDeltaCount = conn.OriginalStats.ReverseBytes - conn.PreviousStats.ReverseBytes
	}
	if conn.TCPState != "" {
		flow.Transport.Protocol = &flowpb.Transport_TCP{
			TCP: &flowpb.TCP{
				StateName: conn.TCPState,
			},
		}
	}
	if conn.EgressIP != "" {
		ip, err := netip.ParseAddr(conn.EgressIP)
		if err != nil {
			klog.ErrorS(err, "Invalid Egress IP", "ip", conn.EgressIP)
		}
		flow.K8S.EgressIp = ip.AsSlice()
	}

	return flow
}
