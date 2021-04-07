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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	"github.com/vmware-tanzu/antrea/pkg/ipfix"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
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
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"tcpState",
		"flowType",
	}
	AntreaInfoElementsIPv4 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	AntreaInfoElementsIPv6 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)
)

type flowExporter struct {
	connStore                 connections.ConnectionStore
	flowRecords               *flowrecords.FlowRecords
	process                   ipfix.IPFIXExportingProcess
	elementsListv4            []*ipfixentities.InfoElementWithValue
	elementsListv6            []*ipfixentities.InfoElementWithValue
	ipfixSet                  ipfix.IPFIXSet
	numDataSetsSent           uint64 // used for unit tests.
	templateIDv4              uint16
	templateIDv6              uint16
	registry                  ipfix.IPFIXRegistry
	v4Enabled                 bool
	v6Enabled                 bool
	exporterInput             exporter.ExporterInput
	activeFlowTimeout         time.Duration
	idleFlowTimeout           time.Duration
	enableTLSToFlowAggregator bool
	k8sClient                 kubernetes.Interface
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
	expInput.CollectorProtocol = collectorProto
	expInput.PathMTU = 0

	return expInput, nil
}

func NewFlowExporter(connStore connections.ConnectionStore, records *flowrecords.FlowRecords,
	collectorAddr string, collectorProto string, activeFlowTimeout time.Duration, idleFlowTimeout time.Duration,
	enableTLSToFlowAggregator bool, v4Enabled bool, v6Enabled bool, k8sClient kubernetes.Interface) (*flowExporter, error) {
	// Initialize IPFIX registry
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()

	// Prepare input args for IPFIX exporting process.
	expInput, err := prepareExporterInputArgs(collectorAddr, collectorProto)
	if err != nil {
		return nil, err
	}
	return &flowExporter{
		connStore:                 connStore,
		flowRecords:               records,
		registry:                  registry,
		v4Enabled:                 v4Enabled,
		v6Enabled:                 v6Enabled,
		exporterInput:             expInput,
		activeFlowTimeout:         activeFlowTimeout,
		idleFlowTimeout:           idleFlowTimeout,
		ipfixSet:                  ipfix.NewSet(false),
		enableTLSToFlowAggregator: enableTLSToFlowAggregator,
		k8sClient:                 k8sClient,
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
	if exp.enableTLSToFlowAggregator {
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
		exp.exporterInput.IsEncrypted = true
	} else if exp.exporterInput.CollectorProtocol == "tcp" {
		// TCP transport does not need any tempRefTimeout, so sending 0.
		// tempRefTimeout is the template refresh timeout, which specifies how often
		// the exporting process should send the template again.
		exp.exporterInput.TempRefTimeout = 0
		exp.exporterInput.IsEncrypted = false
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s.
		exp.exporterInput.TempRefTimeout = 1800
		exp.exporterInput.IsEncrypted = false
	}
	expProcess, err := ipfix.NewIPFIXExportingProcess(exp.exporterInput)
	if err != nil {
		return fmt.Errorf("error when starting exporter: %v", err)
	}
	exp.process = expProcess
	if exp.v4Enabled {
		templateID := exp.process.NewTemplateID()
		exp.templateIDv4 = templateID
		if err = exp.ipfixSet.PrepareSet(ipfixentities.Template, exp.templateIDv4); err != nil {
			return err
		}
		sentBytes, err := exp.sendTemplateSet(exp.ipfixSet, false)
		exp.ipfixSet.ResetSet()
		if err != nil {
			return err
		}

		klog.V(2).Infof("Initialized flow exporter for IPv4 flow records and sent %d bytes size of template record", sentBytes)
	}
	if exp.v6Enabled {
		templateID := exp.process.NewTemplateID()
		exp.templateIDv6 = templateID
		if err = exp.ipfixSet.PrepareSet(ipfixentities.Template, exp.templateIDv6); err != nil {
			return err
		}
		sentBytes, err := exp.sendTemplateSet(exp.ipfixSet, true)
		exp.ipfixSet.ResetSet()
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
				if err := exp.connStore.SetExportDone(key); err != nil {
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
	return nil
}

func (exp *flowExporter) sendTemplateSet(templateSet ipfix.IPFIXSet, isIPv6 bool) (int, error) {
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

	err := templateSet.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error in adding record to template set: %v", err)
	}

	sentBytes, err := exp.process.SendSet(templateSet)
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
			ie.Value = record.Conn.TupleOrig.SourceAddress
		case "destinationIPv4Address":
			ie.Value = record.Conn.TupleReply.SourceAddress
		case "sourceIPv6Address":
			ie.Value = record.Conn.TupleOrig.SourceAddress
		case "destinationIPv6Address":
			ie.Value = record.Conn.TupleReply.SourceAddress
		case "sourceTransportPort":
			ie.Value = record.Conn.TupleOrig.SourcePort
		case "destinationTransportPort":
			ie.Value = record.Conn.TupleReply.SourcePort
		case "protocolIdentifier":
			ie.Value = record.Conn.TupleOrig.Protocol
		case "packetTotalCount":
			ie.Value = record.Conn.OriginalPackets
		case "octetTotalCount":
			ie.Value = record.Conn.OriginalBytes
		case "packetDeltaCount":
			deltaPkts := int64(0)
			if record.PrevPackets != 0 {
				deltaPkts = int64(record.Conn.OriginalPackets) - int64(record.PrevPackets)
			}
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			ie.Value = uint64(deltaPkts)
		case "octetDeltaCount":
			deltaBytes := int64(0)
			if record.PrevBytes != 0 {
				deltaBytes = int64(record.Conn.OriginalBytes) - int64(record.PrevBytes)
			}
			if deltaBytes < 0 {
				klog.Warningf("Byte delta count for connection should not be negative: %d", deltaBytes)
			}
			ie.Value = uint64(deltaBytes)
		case "reversePacketTotalCount":
			ie.Value = record.Conn.ReversePackets
		case "reverseOctetTotalCount":
			ie.Value = record.Conn.ReverseBytes
		case "reversePacketDeltaCount":
			deltaPkts := int64(0)
			if record.PrevReversePackets != 0 {
				deltaPkts = int64(record.Conn.ReversePackets) - int64(record.PrevReversePackets)
			}
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			ie.Value = uint64(deltaPkts)
		case "reverseOctetDeltaCount":
			deltaBytes := int64(0)
			if record.PrevReverseBytes != 0 {
				deltaBytes = int64(record.Conn.ReverseBytes) - int64(record.PrevReverseBytes)
			}
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
				ie.Value = record.Conn.TupleOrig.DestinationAddress
			} else {
				// Sending dummy IP as IPFIX collector expects constant length of data for IP field.
				// We should probably think of better approach as this involves customization of IPFIX collector to ignore
				// this dummy IP address.
				ie.Value = net.IP{0, 0, 0, 0}
			}
		case "destinationClusterIPv6":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.TupleOrig.DestinationAddress
			} else {
				// Same as destinationClusterIPv4.
				ie.Value = net.ParseIP("::")
			}
		case "destinationServicePort":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.TupleOrig.DestinationPort
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
		case "egressNetworkPolicyName":
			ie.Value = record.Conn.EgressNetworkPolicyName
		case "egressNetworkPolicyNamespace":
			ie.Value = record.Conn.EgressNetworkPolicyNamespace
		case "tcpState":
			ie.Value = record.Conn.TCPState
		case "flowType":
			// TODO: assign flow type to support Pod-to-External flows
			if record.Conn.SourcePodName == "" || record.Conn.DestinationPodName == "" {
				ie.Value = ipfixregistry.InterNode
			} else {
				ie.Value = ipfixregistry.IntraNode
			}
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

func (exp *flowExporter) sendDataSet() (int, error) {
	sentBytes, err := exp.process.SendSet(exp.ipfixSet)
	if err != nil {
		return 0, fmt.Errorf("error when sending data set: %v", err)
	}
	klog.V(4).Infof("Data set sent successfully. Bytes sent: %d", sentBytes)
	return sentBytes, nil
}
