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
	"fmt"
	"net"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/ipfix"
)

var (
	IANAInfoElementsCommon = []string{
		"flowStartSeconds",
		"flowEndSeconds",
		"flowEndReason",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
		"packetDeltaCount",
		"octetDeltaCount",
	}
	IANAInfoElementsIPv4 = append(IANAInfoElementsCommon, []string{"sourceIPv4Address", "destinationIPv4Address"}...)
	IANAInfoElementsIPv6 = append(IANAInfoElementsCommon, []string{"sourceIPv6Address", "destinationIPv6Address"}...)
	// IANAReverseInfoElements contain substring "reverse" which is an indication to get reverse element of go-ipfix library.
	IANAReverseInfoElements = []string{
		"reversePacketTotalCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetDeltaCount",
	}
	antreaInfoElementsCommon = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationServicePort",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
		"egressNetworkPolicyRuleAction",
		"tcpState",
		"flowType",
		"egressName",
		"egressIP",
		"appProtocolName",
		"httpVals",
		"egressNodeName",
	}
	AntreaInfoElementsIPv4 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	AntreaInfoElementsIPv6 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)
)

type ipfixExporter struct {
	process        ipfix.IPFIXExportingProcess
	collectorProto string
	v4Enabled      bool
	v6Enabled      bool
	elementsListv4 []ipfixentities.InfoElementWithValue
	elementsListv6 []ipfixentities.InfoElementWithValue
	ipfixSet       ipfixentities.Set
	templateIDv4   uint16
	templateIDv6   uint16
	registry       ipfix.IPFIXRegistry
	nodeName       string
	obsDomainID    uint32
}

func NewIPFIXExporter(collectorProto string, nodeName string, obsDomainID uint32, v4Enabled, v6Enabled bool) *ipfixExporter {
	// Initialize IPFIX registry
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()

	return &ipfixExporter{
		collectorProto: collectorProto,
		v4Enabled:      v4Enabled,
		v6Enabled:      v6Enabled,
		ipfixSet:       ipfixentities.NewSet(false),
		registry:       registry,
		nodeName:       nodeName,
		obsDomainID:    obsDomainID,
	}
}

func (e *ipfixExporter) ConnectToCollector(addr string, tlsConfig *TLSConfig) error {
	expInput := exporter.ExporterInput{
		CollectorAddress:    addr,
		ObservationDomainID: e.obsDomainID,
		// TempRefTimeout specifies how often the exporting process should send the template
		// again. It is only relevant when using the UDP protocol. We use 0 to tell the go-ipfix
		// library to use the default value, which should be 600s as per the IPFIX standards.
		TempRefTimeout: 0,
	}
	if e.collectorProto == "tls" {
		expInput.CollectorProtocol = "tcp"
	} else {
		expInput.CollectorProtocol = e.collectorProto
	}
	if tlsConfig != nil {
		expInput.TLSClientConfig = &exporter.ExporterTLSClientConfig{
			ServerName: tlsConfig.ServerName,
			CAData:     tlsConfig.CAData,
			CertData:   tlsConfig.CertData,
			KeyData:    tlsConfig.KeyData,
		}
	}
	expProcess, err := exporter.InitExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("error when starting exporter: %w", err)
	}
	e.process = expProcess
	if e.v4Enabled {
		templateID := e.process.NewTemplateID()
		e.templateIDv4 = templateID
		sentBytes, err := e.sendTemplateSet(false)
		if err != nil {
			return err
		}
		klog.V(2).InfoS("Initialized flow exporter for IPv4 flow records and sent template record", "size", sentBytes)
	}
	if e.v6Enabled {
		templateID := e.process.NewTemplateID()
		e.templateIDv6 = templateID
		sentBytes, err := e.sendTemplateSet(true)
		if err != nil {
			return err
		}
		klog.V(2).InfoS("Initialized flow exporter for IPv6 flow records and sent template record", "size", sentBytes)
	}
	return nil
}

func (e *ipfixExporter) Export(conn *connection.Connection) error {
	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	if err := e.addConnToSet(conn); err != nil {
		return err
	}
	if _, err := e.sendDataSet(); err != nil {
		return err
	}
	return nil
}

func (e *ipfixExporter) CloseConnToCollector() {
	if e.process != nil {
		e.process.CloseConnToCollector()
		e.process = nil
	}
}

func (e *ipfixExporter) sendTemplateSet(isIPv6 bool) (int, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)

	IANAInfoElements := IANAInfoElementsIPv4
	AntreaInfoElements := AntreaInfoElementsIPv4
	templateID := e.templateIDv4
	if isIPv6 {
		IANAInfoElements = IANAInfoElementsIPv6
		AntreaInfoElements = AntreaInfoElementsIPv6
		templateID = e.templateIDv6
	}
	for _, ie := range IANAInfoElements {
		element, err := e.registry.GetInfoElement(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
		if err != nil {
			return 0, fmt.Errorf("error when creating information element: %v", err)
		}
		elements = append(elements, ieWithValue)
	}
	for _, ie := range IANAReverseInfoElements {
		element, err := e.registry.GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
		if err != nil {
			return 0, fmt.Errorf("error when creating information element: %v", err)
		}
		elements = append(elements, ieWithValue)
	}
	for _, ie := range AntreaInfoElements {
		element, err := e.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("information element %s is not present in Antrea registry", ie)
		}
		ieWithValue, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
		if err != nil {
			return 0, fmt.Errorf("error when creating information element: %v", err)
		}
		elements = append(elements, ieWithValue)
	}
	e.ipfixSet.ResetSet()
	if err := e.ipfixSet.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := e.ipfixSet.AddRecordV2(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error in adding record to template set: %v", err)
	}
	sentBytes, err := e.process.SendSet(e.ipfixSet)
	if err != nil {
		return 0, fmt.Errorf("error in IPFIX exporting process when sending template record: %v", err)
	}

	// Get all elements from template record.
	if !isIPv6 {
		e.elementsListv4 = elements
	} else {
		e.elementsListv6 = elements
	}

	return sentBytes, nil
}

func (e *ipfixExporter) addConnToSet(conn *connection.Connection) error {
	e.ipfixSet.ResetSet()

	eL := e.elementsListv4
	templateID := e.templateIDv4
	if conn.FlowKey.SourceAddress.Is6() {
		templateID = e.templateIDv6
		eL = e.elementsListv6
	}
	if err := e.ipfixSet.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	// Iterate over all infoElements in the list
	for i := range eL {
		ie := eL[i]
		switch ieName := ie.GetInfoElement().Name; ieName {
		case "flowStartSeconds":
			ie.SetUnsigned32Value(uint32(conn.StartTime.Unix()))
		case "flowEndSeconds":
			ie.SetUnsigned32Value(uint32(conn.StopTime.Unix()))
		case "flowEndReason":
			if utils.IsConnectionDying(conn) {
				ie.SetUnsigned8Value(ipfixregistry.EndOfFlowReason)
			} else if conn.IsActive {
				ie.SetUnsigned8Value(ipfixregistry.ActiveTimeoutReason)
			} else {
				ie.SetUnsigned8Value(ipfixregistry.IdleTimeoutReason)
			}
		case "sourceIPv4Address":
			ie.SetIPAddressValue(conn.FlowKey.SourceAddress.AsSlice())
		case "destinationIPv4Address":
			ie.SetIPAddressValue(conn.FlowKey.DestinationAddress.AsSlice())
		case "sourceIPv6Address":
			ie.SetIPAddressValue(conn.FlowKey.SourceAddress.AsSlice())
		case "destinationIPv6Address":
			ie.SetIPAddressValue(conn.FlowKey.DestinationAddress.AsSlice())
		case "sourceTransportPort":
			ie.SetUnsigned16Value(conn.FlowKey.SourcePort)
		case "destinationTransportPort":
			ie.SetUnsigned16Value(conn.FlowKey.DestinationPort)
		case "protocolIdentifier":
			ie.SetUnsigned8Value(conn.FlowKey.Protocol)
		case "packetTotalCount":
			ie.SetUnsigned64Value(conn.OriginalStats.Packets)
		case "octetTotalCount":
			ie.SetUnsigned64Value(conn.OriginalStats.Bytes)
		case "packetDeltaCount":
			deltaPkts := int64(conn.OriginalStats.Packets) - int64(conn.PreviousStats.Packets)
			if deltaPkts < 0 {
				klog.InfoS("Packet delta count for connection should not be negative", "packet delta count", deltaPkts)
			}
			ie.SetUnsigned64Value(uint64(deltaPkts))
		case "octetDeltaCount":
			deltaBytes := int64(conn.OriginalStats.Bytes) - int64(conn.PreviousStats.Bytes)
			if deltaBytes < 0 {
				klog.InfoS("Byte delta count for connection should not be negative", "byte delta count", deltaBytes)
			}
			ie.SetUnsigned64Value(uint64(deltaBytes))
		case "reversePacketTotalCount":
			ie.SetUnsigned64Value(conn.OriginalStats.ReversePackets)
		case "reverseOctetTotalCount":
			ie.SetUnsigned64Value(conn.OriginalStats.ReverseBytes)
		case "reversePacketDeltaCount":
			deltaPkts := int64(conn.OriginalStats.ReversePackets) - int64(conn.PreviousStats.ReversePackets)
			if deltaPkts < 0 {
				klog.InfoS("Reverse packet delta count for connection should not be negative", "packet delta count", deltaPkts)
			}
			ie.SetUnsigned64Value(uint64(deltaPkts))
		case "reverseOctetDeltaCount":
			deltaBytes := int64(conn.OriginalStats.ReverseBytes) - int64(conn.PreviousStats.ReverseBytes)
			if deltaBytes < 0 {
				klog.InfoS("Reverse byte delta count for connection should not be negative", "byte delta count", deltaBytes)
			}
			ie.SetUnsigned64Value(uint64(deltaBytes))
		case "sourcePodNamespace":
			ie.SetStringValue(conn.SourcePodNamespace)
		case "sourcePodName":
			ie.SetStringValue(conn.SourcePodName)
		case "sourceNodeName":
			// Add nodeName only for local Pods whose Pod names are resolved.
			if conn.SourcePodName != "" {
				ie.SetStringValue(e.nodeName)
			} else {
				ie.SetStringValue("")
			}
		case "destinationPodNamespace":
			ie.SetStringValue(conn.DestinationPodNamespace)
		case "destinationPodName":
			ie.SetStringValue(conn.DestinationPodName)
		case "destinationNodeName":
			// Add nodeName only for local Pods whose Pod names are resolved.
			if conn.DestinationPodName != "" {
				ie.SetStringValue(e.nodeName)
			} else {
				ie.SetStringValue("")
			}
		case "destinationClusterIPv4":
			if conn.DestinationServicePortName != "" {
				ie.SetIPAddressValue(conn.OriginalDestinationAddress.AsSlice())
			} else {
				// Sending dummy IP as IPFIX collector expects constant length of data for IP field.
				// We should probably think of better approach as this involves customization of IPFIX collector to ignore
				// this dummy IP address.
				ie.SetIPAddressValue(net.IP{0, 0, 0, 0})
			}
		case "destinationClusterIPv6":
			if conn.DestinationServicePortName != "" {
				ie.SetIPAddressValue(conn.OriginalDestinationAddress.AsSlice())
			} else {
				// Same as destinationClusterIPv4.
				ie.SetIPAddressValue(net.ParseIP("::"))
			}
		case "destinationServicePort":
			if conn.DestinationServicePortName != "" {
				ie.SetUnsigned16Value(conn.OriginalDestinationPort)
			} else {
				ie.SetUnsigned16Value(uint16(0))
			}
		case "destinationServicePortName":
			ie.SetStringValue(conn.DestinationServicePortName)
		case "ingressNetworkPolicyName":
			ie.SetStringValue(conn.IngressNetworkPolicyName)
		case "ingressNetworkPolicyNamespace":
			ie.SetStringValue(conn.IngressNetworkPolicyNamespace)
		case "ingressNetworkPolicyType":
			ie.SetUnsigned8Value(conn.IngressNetworkPolicyType)
		case "ingressNetworkPolicyRuleName":
			ie.SetStringValue(conn.IngressNetworkPolicyRuleName)
		case "ingressNetworkPolicyRuleAction":
			ie.SetUnsigned8Value(conn.IngressNetworkPolicyRuleAction)
		case "egressNetworkPolicyName":
			ie.SetStringValue(conn.EgressNetworkPolicyName)
		case "egressNetworkPolicyNamespace":
			ie.SetStringValue(conn.EgressNetworkPolicyNamespace)
		case "egressNetworkPolicyType":
			ie.SetUnsigned8Value(conn.EgressNetworkPolicyType)
		case "egressNetworkPolicyRuleName":
			ie.SetStringValue(conn.EgressNetworkPolicyRuleName)
		case "egressNetworkPolicyRuleAction":
			ie.SetUnsigned8Value(conn.EgressNetworkPolicyRuleAction)
		case "tcpState":
			ie.SetStringValue(conn.TCPState)
		case "flowType":
			ie.SetUnsigned8Value(conn.FlowType)
		case "egressName":
			ie.SetStringValue(conn.EgressName)
		case "egressIP":
			ie.SetStringValue(conn.EgressIP)
		case "appProtocolName":
			ie.SetStringValue(conn.AppProtocolName)
		case "httpVals":
			ie.SetStringValue(conn.HttpVals)
		case "egressNodeName":
			ie.SetStringValue(conn.EgressNodeName)
		}
	}
	err := e.ipfixSet.AddRecordV2(eL, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}
	return nil
}

func (e *ipfixExporter) sendDataSet() (int, error) {
	sentBytes, err := e.process.SendSet(e.ipfixSet)
	if err != nil {
		return 0, fmt.Errorf("error when sending data set: %v", err)
	}
	if klog.V(5).Enabled() {
		klog.InfoS("Data set sent successfully", "Bytes sent", sentBytes)
	}
	return sentBytes, nil
}
