// Copyright 2020 Antrea Authors
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
	"hash/fnv"
	"net"
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/flowrecords"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/ipfix"
	"antrea.io/antrea/pkg/util/env"
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
	// Substring "reverse" is an indication to get reverse element of go-ipfix library.
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
	}
	AntreaInfoElementsIPv4 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	AntreaInfoElementsIPv6 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)
)

type flowExporter struct {
	conntrackConnStore  *connections.ConntrackConnectionStore
	flowRecords         *flowrecords.FlowRecords
	denyConnStore       *connections.DenyConnectionStore
	process             ipfix.IPFIXExportingProcess
	elementsListv4      []*ipfixentities.InfoElementWithValue
	elementsListv6      []*ipfixentities.InfoElementWithValue
	ipfixSet            ipfixentities.Set
	numDataSetsSent     uint64 // used for unit tests.
	templateIDv4        uint16
	templateIDv6        uint16
	registry            ipfix.IPFIXRegistry
	v4Enabled           bool
	v6Enabled           bool
	exporterInput       exporter.ExporterInput
	activeFlowTimeout   time.Duration
	idleFlowTimeout     time.Duration
	k8sClient           kubernetes.Interface
	nodeRouteController *noderoute.Controller
	isNetworkPolicyOnly bool
}

func genObservationID() (uint32, error) {
	name, err := env.GetNodeName()
	if err != nil {
		return 0, err
	}
	h := fnv.New32()
	h.Write([]byte(name))
	return h.Sum32(), nil
}

func prepareExporterInputArgs(collectorAddr, collectorProto string) (exporter.ExporterInput, error) {
	expInput := exporter.ExporterInput{}
	var err error
	// Exporting process requires domain observation ID.
	expInput.ObservationDomainID, err = genObservationID()
	if err != nil {
		return expInput, err
	}
	expInput.CollectorAddress = collectorAddr
	if collectorProto == "tls" {
		expInput.IsEncrypted = true
		expInput.CollectorProtocol = "tcp"
	} else {
		expInput.IsEncrypted = false
		expInput.CollectorProtocol = collectorProto
	}
	expInput.PathMTU = 0

	return expInput, nil
}

func NewFlowExporter(connStore *connections.ConntrackConnectionStore, records *flowrecords.FlowRecords, denyConnStore *connections.DenyConnectionStore,
	collectorAddr string, collectorProto string, activeFlowTimeout time.Duration, idleFlowTimeout time.Duration,
	v4Enabled bool, v6Enabled bool, k8sClient kubernetes.Interface,
	nodeRouteController *noderoute.Controller, isNetworkPolicyOnly bool) (*flowExporter, error) {
	// Initialize IPFIX registry
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()

	// Prepare input args for IPFIX exporting process.
	expInput, err := prepareExporterInputArgs(collectorAddr, collectorProto)
	if err != nil {
		return nil, err
	}

	return &flowExporter{
		conntrackConnStore:  connStore,
		flowRecords:         records,
		denyConnStore:       denyConnStore,
		registry:            registry,
		v4Enabled:           v4Enabled,
		v6Enabled:           v6Enabled,
		exporterInput:       expInput,
		activeFlowTimeout:   activeFlowTimeout,
		idleFlowTimeout:     idleFlowTimeout,
		ipfixSet:            ipfixentities.NewSet(false),
		k8sClient:           k8sClient,
		nodeRouteController: nodeRouteController,
		isNetworkPolicyOnly: isNetworkPolicyOnly,
	}, nil
}

// Run calls Export function periodically to check if flow records need to be exported
// based on active flow and idle flow timeouts.
func (exp *flowExporter) Run(stopCh <-chan struct{}) {
	go wait.Until(exp.Export, time.Second, stopCh)

	<-stopCh
}

func (exp *flowExporter) Export() {
	// Retry to connect to IPFIX collector if the exporting process gets reset
	if exp.process == nil {
		err := exp.initFlowExporter()
		if err != nil {
			klog.Errorf("Error when initializing flow exporter: %v", err)
			// There could be other errors while initializing flow exporter other than connecting to IPFIX collector,
			// therefore closing the connection and resetting the process.
			if exp.process != nil {
				exp.process.CloseConnToCollector()
				exp.process = nil
			}
			return
		}
	}
	// Send flow records to IPFIX collector.
	err := exp.sendFlowRecords()
	if err != nil {
		klog.Errorf("Error when sending flow records: %v", err)
		// If there is an error when sending flow records because of intermittent connectivity, we reset the connection
		// to IPFIX collector and retry in the next export cycle to reinitialize the connection and send flow records.
		exp.process.CloseConnToCollector()
		exp.process = nil
		return
	}
	klog.V(2).Infof("Successfully exported IPFIX flow records")
}

func (exp *flowExporter) initFlowExporter() error {
	var err error
	if exp.exporterInput.IsEncrypted {
		// if CA certificate, client certificate and key do not exist during initialization,
		// it will retry to obtain the credentials in next export cycle
		exp.exporterInput.CACert, err = getCACert(exp.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve CA cert: %v", err)
		}
		exp.exporterInput.ClientCert, exp.exporterInput.ClientKey, err = getClientCertKey(exp.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve client cert and key: %v", err)
		}
		// TLS transport does not need any tempRefTimeout, so sending 0.
		exp.exporterInput.TempRefTimeout = 0
	} else if exp.exporterInput.CollectorProtocol == "tcp" {
		// TCP transport does not need any tempRefTimeout, so sending 0.
		// tempRefTimeout is the template refresh timeout, which specifies how often
		// the exporting process should send the template again.
		exp.exporterInput.TempRefTimeout = 0
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s.
		exp.exporterInput.TempRefTimeout = 1800
	}
	expProcess, err := ipfix.NewIPFIXExportingProcess(exp.exporterInput)
	if err != nil {
		return fmt.Errorf("error when starting exporter: %v", err)
	}
	exp.process = expProcess
	if exp.v4Enabled {
		templateID := exp.process.NewTemplateID()
		exp.templateIDv4 = templateID
		sentBytes, err := exp.sendTemplateSet(false)
		if err != nil {
			return err
		}

		klog.V(2).Infof("Initialized flow exporter for IPv4 flow records and sent %d bytes size of template record", sentBytes)
	}
	if exp.v6Enabled {
		templateID := exp.process.NewTemplateID()
		exp.templateIDv6 = templateID
		sentBytes, err := exp.sendTemplateSet(true)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Initialized flow exporter for IPv6 flow records and sent %d bytes size of template record", sentBytes)
	}
	return nil
}

func (exp *flowExporter) sendFlowRecords() error {
	updateOrSendFlowRecord := func(key flowexporter.ConnectionKey, record flowexporter.FlowRecord) error {
		recordNeedsSending := false
		// We do not check for any timeout as the connection is still idle since
		// the idleFlowTimeout was triggered.
		if !record.IsActive {
			return nil
		}
		// Send a flow record if the conditions for either timeout
		// (activeFlowTimeout or idleFlowTimeout) are met. A flow is considered
		// to be idle if its packet counts haven't changed since the last export.
		if time.Since(record.LastExportTime) >= exp.idleFlowTimeout {
			if ((record.Conn.OriginalPackets <= record.PrevPackets) && (record.Conn.ReversePackets <= record.PrevReversePackets)) || flowexporter.IsConnectionDying(&record.Conn) {
				// Idle flow timeout
				record.IsActive = false
				recordNeedsSending = true
			}
		}
		if time.Since(record.LastExportTime) >= exp.activeFlowTimeout {
			// Active flow timeout
			recordNeedsSending = true
		}
		if recordNeedsSending {
			exp.ipfixSet.ResetSet()
			if record.IsIPv6 {
				if err := exp.ipfixSet.PrepareSet(ipfixentities.Data, exp.templateIDv6); err != nil {
					return err
				}
				// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
				if err := exp.addRecordToSet(record); err != nil {
					return err
				}
				if _, err := exp.sendDataSet(); err != nil {
					return err
				}
			} else {
				if err := exp.ipfixSet.PrepareSet(ipfixentities.Data, exp.templateIDv4); err != nil {
					return err
				}
				// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
				if err := exp.addRecordToSet(record); err != nil {
					return err
				}
				if _, err := exp.sendDataSet(); err != nil {
					return err
				}
			}
			exp.numDataSetsSent = exp.numDataSetsSent + 1

			if flowexporter.IsConnectionDying(&record.Conn) {
				// If the connection is in dying state or connection is not in conntrack table,
				// we will delete the flow records from records map.
				klog.V(2).Infof("Deleting the inactive flow records with key: %v from record map", key)
				if err := exp.flowRecords.DeleteFlowRecordWithoutLock(key); err != nil {
					return err
				}
				if err := exp.conntrackConnStore.SetExportDone(key); err != nil {
					return err
				}
			} else {
				exp.flowRecords.ValidateAndUpdateStats(key, record)
			}
		}
		return nil
	}
	err := exp.flowRecords.ForAllFlowRecordsDo(updateOrSendFlowRecord)
	if err != nil {
		return fmt.Errorf("error when iterating flow records: %v", err)
	}

	exportDenyConn := func(connKey flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		if conn.DeltaPackets > 0 && time.Since(conn.LastExportTime) >= exp.activeFlowTimeout {
			if err := exp.addDenyConnToSet(conn, ipfixregistry.ActiveTimeoutReason); err != nil {
				return err
			}
			if _, err := exp.sendDataSet(); err != nil {
				return err
			}
			exp.numDataSetsSent = exp.numDataSetsSent + 1
			exp.denyConnStore.ResetConnStatsWithoutLock(conn)
		}
		if time.Since(conn.LastExportTime) >= exp.idleFlowTimeout {
			if err := exp.addDenyConnToSet(conn, ipfixregistry.IdleTimeoutReason); err != nil {
				return err
			}
			if _, err := exp.sendDataSet(); err != nil {
				return err
			}
			exp.numDataSetsSent = exp.numDataSetsSent + 1
			exp.denyConnStore.DeleteConnWithoutLock(connKey)
		}
		return nil
	}
	err = exp.denyConnStore.ForAllConnectionsDo(exportDenyConn)
	if err != nil {
		return fmt.Errorf("error when iterating deny connections: %v", err)
	}
	return nil
}

func (exp *flowExporter) sendTemplateSet(isIPv6 bool) (int, error) {
	elements := make([]*ipfixentities.InfoElementWithValue, 0)

	IANAInfoElements := IANAInfoElementsIPv4
	AntreaInfoElements := AntreaInfoElementsIPv4
	templateID := exp.templateIDv4
	if isIPv6 {
		IANAInfoElements = IANAInfoElementsIPv6
		AntreaInfoElements = AntreaInfoElementsIPv6
		templateID = exp.templateIDv6
	}
	for _, ie := range IANAInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ieWithValue)
	}
	for _, ie := range IANAReverseInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ieWithValue)
	}
	for _, ie := range AntreaInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("information element %s is not present in Antrea registry", ie)
		}
		ieWithValue := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ieWithValue)
	}
	exp.ipfixSet.ResetSet()
	if err := exp.ipfixSet.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := exp.ipfixSet.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error in adding record to template set: %v", err)
	}
	sentBytes, err := exp.process.SendSet(exp.ipfixSet)
	if err != nil {
		return 0, fmt.Errorf("error in IPFIX exporting process when sending template record: %v", err)
	}

	// Get all elements from template record.
	if !isIPv6 {
		exp.elementsListv4 = elements
	} else {
		exp.elementsListv6 = elements
	}

	return sentBytes, nil
}

func (exp *flowExporter) addRecordToSet(record flowexporter.FlowRecord) error {
	nodeName, _ := env.GetNodeName()

	// Iterate over all infoElements in the list
	eL := exp.elementsListv4
	if record.IsIPv6 {
		eL = exp.elementsListv6
	}
	for _, ie := range eL {
		switch ieName := ie.Element.Name; ieName {
		case "flowStartSeconds":
			ie.Value = uint32(record.Conn.StartTime.Unix())
		case "flowEndSeconds":
			ie.Value = uint32(record.Conn.StopTime.Unix())
		case "flowEndReason":
			if flowexporter.IsConnectionDying(&record.Conn) {
				ie.Value = ipfixregistry.EndOfFlowReason
			} else if record.IsActive {
				ie.Value = ipfixregistry.ActiveTimeoutReason
			} else {
				ie.Value = ipfixregistry.IdleTimeoutReason
			}
		case "sourceIPv4Address":
			ie.Value = record.Conn.FlowKey.SourceAddress
		case "destinationIPv4Address":
			ie.Value = record.Conn.FlowKey.DestinationAddress
		case "sourceIPv6Address":
			ie.Value = record.Conn.FlowKey.SourceAddress
		case "destinationIPv6Address":
			ie.Value = record.Conn.FlowKey.DestinationAddress
		case "sourceTransportPort":
			ie.Value = record.Conn.FlowKey.SourcePort
		case "destinationTransportPort":
			ie.Value = record.Conn.FlowKey.DestinationPort
		case "protocolIdentifier":
			ie.Value = record.Conn.FlowKey.Protocol
		case "packetTotalCount":
			ie.Value = record.Conn.OriginalPackets
		case "octetTotalCount":
			ie.Value = record.Conn.OriginalBytes
		case "packetDeltaCount":
			deltaPkts := int64(record.Conn.OriginalPackets) - int64(record.PrevPackets)
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			ie.Value = uint64(deltaPkts)
		case "octetDeltaCount":
			deltaBytes := int64(record.Conn.OriginalBytes) - int64(record.PrevBytes)
			if deltaBytes < 0 {
				klog.Warningf("Byte delta count for connection should not be negative: %d", deltaBytes)
			}
			ie.Value = uint64(deltaBytes)
		case "reversePacketTotalCount":
			ie.Value = record.Conn.ReversePackets
		case "reverseOctetTotalCount":
			ie.Value = record.Conn.ReverseBytes
		case "reversePacketDeltaCount":
			deltaPkts := int64(record.Conn.ReversePackets) - int64(record.PrevReversePackets)
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			ie.Value = uint64(deltaPkts)
		case "reverseOctetDeltaCount":
			deltaBytes := int64(record.Conn.ReverseBytes) - int64(record.PrevReverseBytes)
			if deltaBytes < 0 {
				klog.Warningf("Byte delta count for connection should not be negative: %d", deltaBytes)
			}
			ie.Value = uint64(deltaBytes)
		case "sourcePodNamespace":
			ie.Value = record.Conn.SourcePodNamespace
		case "sourcePodName":
			ie.Value = record.Conn.SourcePodName
		case "sourceNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if record.Conn.SourcePodName != "" {
				ie.Value = nodeName
			} else {
				ie.Value = ""
			}
		case "destinationPodNamespace":
			ie.Value = record.Conn.DestinationPodNamespace
		case "destinationPodName":
			ie.Value = record.Conn.DestinationPodName
		case "destinationNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if record.Conn.DestinationPodName != "" {
				ie.Value = nodeName
			} else {
				ie.Value = ""
			}
		case "destinationClusterIPv4":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.DestinationServiceAddress
			} else {
				// Sending dummy IP as IPFIX collector expects constant length of data for IP field.
				// We should probably think of better approach as this involves customization of IPFIX collector to ignore
				// this dummy IP address.
				ie.Value = net.IP{0, 0, 0, 0}
			}
		case "destinationClusterIPv6":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.DestinationServiceAddress
			} else {
				// Same as destinationClusterIPv4.
				ie.Value = net.ParseIP("::")
			}
		case "destinationServicePort":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.DestinationServicePort
			} else {
				ie.Value = uint16(0)
			}
		case "destinationServicePortName":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.DestinationServicePortName
			} else {
				ie.Value = ""
			}
		case "ingressNetworkPolicyName":
			ie.Value = record.Conn.IngressNetworkPolicyName
		case "ingressNetworkPolicyNamespace":
			ie.Value = record.Conn.IngressNetworkPolicyNamespace
		case "ingressNetworkPolicyType":
			ie.Value = record.Conn.IngressNetworkPolicyType
		case "ingressNetworkPolicyRuleName":
			ie.Value = record.Conn.IngressNetworkPolicyRuleName
		case "ingressNetworkPolicyRuleAction":
			ie.Value = record.Conn.IngressNetworkPolicyRuleAction
		case "egressNetworkPolicyName":
			ie.Value = record.Conn.EgressNetworkPolicyName
		case "egressNetworkPolicyNamespace":
			ie.Value = record.Conn.EgressNetworkPolicyNamespace
		case "egressNetworkPolicyType":
			ie.Value = record.Conn.EgressNetworkPolicyType
		case "egressNetworkPolicyRuleName":
			ie.Value = record.Conn.EgressNetworkPolicyRuleName
		case "egressNetworkPolicyRuleAction":
			ie.Value = record.Conn.EgressNetworkPolicyRuleAction
		case "tcpState":
			ie.Value = record.Conn.TCPState
		case "flowType":
			ie.Value = exp.findFlowType(record.Conn)
		}
	}

	templateID := exp.templateIDv4
	if record.IsIPv6 {
		templateID = exp.templateIDv6
	}
	err := exp.ipfixSet.AddRecord(eL, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}
	return nil
}

func (exp *flowExporter) addDenyConnToSet(conn *flowexporter.Connection, flowEndReason uint8) error {
	nodeName, _ := env.GetNodeName()
	exp.ipfixSet.ResetSet()

	eL := exp.elementsListv4
	templateID := exp.templateIDv4
	if conn.FlowKey.SourceAddress.To4() == nil {
		templateID = exp.templateIDv6
		eL = exp.elementsListv6
	}
	if err := exp.ipfixSet.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	// Iterate over all infoElements in the list
	for _, ie := range eL {
		switch ieName := ie.Element.Name; ieName {
		case "flowStartSeconds":
			ie.Value = uint32(conn.StartTime.Unix())
		case "flowEndSeconds":
			ie.Value = uint32(conn.StopTime.Unix())
		case "flowEndReason":
			ie.Value = flowEndReason
		case "sourceIPv4Address":
			ie.Value = conn.FlowKey.SourceAddress
		case "destinationIPv4Address":
			ie.Value = conn.FlowKey.DestinationAddress
		case "sourceIPv6Address":
			ie.Value = conn.FlowKey.SourceAddress
		case "destinationIPv6Address":
			ie.Value = conn.FlowKey.DestinationAddress
		case "sourceTransportPort":
			ie.Value = conn.FlowKey.SourcePort
		case "destinationTransportPort":
			ie.Value = conn.FlowKey.DestinationPort
		case "protocolIdentifier":
			ie.Value = conn.FlowKey.Protocol
		case "packetTotalCount":
			ie.Value = conn.OriginalPackets
		case "octetTotalCount":
			ie.Value = conn.OriginalBytes
		case "packetDeltaCount":
			ie.Value = conn.DeltaPackets
		case "octetDeltaCount":
			ie.Value = conn.DeltaBytes
		case "reversePacketTotalCount", "reverseOctetTotalCount", "reversePacketDeltaCount", "reverseOctetDeltaCount":
			ie.Value = uint64(0)
		case "sourcePodNamespace":
			ie.Value = conn.SourcePodNamespace
		case "sourcePodName":
			ie.Value = conn.SourcePodName
		case "sourceNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if conn.SourcePodName != "" {
				ie.Value = nodeName
			} else {
				ie.Value = ""
			}
		case "destinationPodNamespace":
			ie.Value = conn.DestinationPodNamespace
		case "destinationPodName":
			ie.Value = conn.DestinationPodName
		case "destinationNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if conn.DestinationPodName != "" {
				ie.Value = nodeName
			} else {
				ie.Value = ""
			}
		case "destinationClusterIPv4":
			if conn.DestinationServicePortName != "" {
				ie.Value = conn.DestinationServiceAddress
			} else {
				ie.Value = net.IP{0, 0, 0, 0}
			}
		case "destinationClusterIPv6":
			if conn.DestinationServicePortName != "" {
				ie.Value = conn.DestinationServiceAddress
			} else {
				ie.Value = net.ParseIP("::")
			}
		case "destinationServicePort":
			if conn.DestinationServicePortName != "" {
				ie.Value = conn.DestinationServicePort
			} else {
				ie.Value = uint16(0)
			}
		case "destinationServicePortName":
			ie.Value = conn.DestinationServicePortName
		case "ingressNetworkPolicyName":
			ie.Value = conn.IngressNetworkPolicyName
		case "ingressNetworkPolicyNamespace":
			ie.Value = conn.IngressNetworkPolicyNamespace
		case "ingressNetworkPolicyType":
			ie.Value = conn.IngressNetworkPolicyType
		case "ingressNetworkPolicyRuleName":
			ie.Value = conn.IngressNetworkPolicyRuleName
		case "ingressNetworkPolicyRuleAction":
			ie.Value = conn.IngressNetworkPolicyRuleAction
		case "egressNetworkPolicyName":
			ie.Value = conn.EgressNetworkPolicyName
		case "egressNetworkPolicyNamespace":
			ie.Value = conn.EgressNetworkPolicyNamespace
		case "egressNetworkPolicyType":
			ie.Value = conn.EgressNetworkPolicyType
		case "egressNetworkPolicyRuleName":
			ie.Value = conn.EgressNetworkPolicyRuleName
		case "egressNetworkPolicyRuleAction":
			ie.Value = conn.EgressNetworkPolicyRuleAction
		case "tcpState":
			ie.Value = ""
		case "flowType":
			ie.Value = exp.findFlowType(*conn)
		}
	}

	err := exp.ipfixSet.AddRecord(eL, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}
	return nil
}

func (exp *flowExporter) sendDataSet() (int, error) {
	sentBytes, err := exp.process.SendSet(exp.ipfixSet)
	if err != nil {
		return 0, fmt.Errorf("error when sending data set: %v", err)
	}
	klog.V(4).Infof("Data set sent successfully. Bytes sent: %d", sentBytes)
	return sentBytes, nil
}

func (exp *flowExporter) findFlowType(conn flowexporter.Connection) uint8 {
	// TODO: support Pod-To-External flows in network policy only mode.
	if exp.isNetworkPolicyOnly {
		if conn.SourcePodName == "" || conn.DestinationPodName == "" {
			return ipfixregistry.FlowTypeInterNode
		}
		return ipfixregistry.FlowTypeIntraNode
	}

	if exp.nodeRouteController == nil {
		klog.Warningf("Can't find flowType without nodeRouteController")
		return 0
	}
	if exp.nodeRouteController.IPInPodSubnets(conn.FlowKey.SourceAddress) {
		if conn.Mark == openflow.ServiceCTMark || exp.nodeRouteController.IPInPodSubnets(conn.FlowKey.DestinationAddress) {
			if conn.SourcePodName == "" || conn.DestinationPodName == "" {
				return ipfixregistry.FlowTypeInterNode
			}
			return ipfixregistry.FlowTypeIntraNode
		} else {
			return ipfixregistry.FlowTypeToExternal
		}
	} else {
		// We do not support External-To-Pod flows for now.
		klog.Warningf("Source IP: %s doesn't exist in PodCIDRs", conn.FlowKey.SourceAddress.String())
		return 0
	}
}
