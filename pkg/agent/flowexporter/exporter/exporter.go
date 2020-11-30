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
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/ipfix"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

var (
	IANAInfoElements = []string{
		"flowStartSeconds",
		"flowEndSeconds",
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
		"packetDeltaCount",
		"octetDeltaCount",
	}
	IANAReverseInfoElements = []string{
		"reversePacketTotalCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetDeltaCount",
	}
	AntreaInfoElements = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationClusterIPv4",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
	}
)

type flowExporter struct {
	flowRecords     *flowrecords.FlowRecords
	process         ipfix.IPFIXExportingProcess
	elementsList    []*ipfixentities.InfoElementWithValue
	exportFrequency uint
	pollCycle       uint
	templateID      uint16
	registry        ipfix.IPFIXRegistry
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

func NewFlowExporter(records *flowrecords.FlowRecords, exportFrequency uint) *flowExporter {
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()
	return &flowExporter{
		records,
		nil,
		nil,
		exportFrequency,
		0,
		0,
		registry,
	}
}

// DoExport enables us to export flow records periodically at a given flow export frequency.
func (exp *flowExporter) Export(collector net.Addr, stopCh <-chan struct{}, pollDone <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case <-pollDone:
			// Number of pollDone signals received or poll cycles should be equal to export frequency before starting
			// the export cycle. This is necessary because IPFIX collector computes throughput based on flow records received interval.
			exp.pollCycle++
			if exp.pollCycle%exp.exportFrequency == 0 {
				// Retry to connect to IPFIX collector if the exporting process gets reset
				if exp.process == nil {
					err := exp.initFlowExporter(collector)
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
				// Build and send flow records to IPFIX collector.
				exp.flowRecords.BuildFlowRecords()
				err := exp.sendFlowRecords()
				if err != nil {
					klog.Errorf("Error when sending flow records: %v", err)
					// If there is an error when sending flow records because of intermittent connectivity, we reset the connection
					// to IPFIX collector and retry in the next export cycle to reinitialize the connection and send flow records.
					exp.process.CloseConnToCollector()
					exp.process = nil
					return
				}

				exp.pollCycle = 0
				klog.V(2).Infof("Successfully exported IPFIX flow records")
			}
		}
	}

}

func (exp *flowExporter) initFlowExporter(collector net.Addr) error {
	// Create IPFIX exporting expProcess, initialize registries and other related entities
	obsID, err := genObservationID()
	if err != nil {
		return fmt.Errorf("cannot generate obsID for IPFIX ipfixexport: %v", err)
	}

	var expProcess ipfix.IPFIXExportingProcess
	if collector.Network() == "tcp" {
		// TCP transport do not need any tempRefTimeout, so sending 0.
		expProcess, err = ipfix.NewIPFIXExportingProcess(collector, obsID, 0)
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s.
		expProcess, err = ipfix.NewIPFIXExportingProcess(collector, obsID, 1800)
	}
	if err != nil {
		return err
	}
	exp.process = expProcess
	exp.templateID = expProcess.NewTemplateID()

	templateSet := ipfix.NewSet(ipfixentities.Template, exp.templateID, false)

	sentBytes, err := exp.sendTemplateSet(templateSet, exp.templateID)
	if err != nil {
		return err
	}
	klog.V(2).Infof("Initialized flow exporter and sent %d bytes size of template record", sentBytes)

	return nil
}

func (exp *flowExporter) sendFlowRecords() error {
	sendAndUpdateFlowRecord := func(key flowexporter.ConnectionKey, record flowexporter.FlowRecord) error {
		dataSet := ipfix.NewSet(ipfixentities.Data, exp.templateID, false)
		if err := exp.sendDataSet(dataSet, record, exp.templateID); err != nil {
			return err
		}
		if err := exp.flowRecords.ValidateAndUpdateStats(key, record); err != nil {
			return err
		}
		return nil
	}
	err := exp.flowRecords.ForAllFlowRecordsDo(sendAndUpdateFlowRecord)
	if err != nil {
		return fmt.Errorf("error when iterating flow records: %v", err)
	}
	return nil
}

func (exp *flowExporter) sendTemplateSet(templateSet ipfix.IPFIXSet, templateID uint16) (int, error) {
	elements := make([]*ipfixentities.InfoElementWithValue, 0)

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

	sentBytes, err := exp.process.AddSetAndSendMsg(ipfixentities.Template, templateSet.GetSet())
	if err != nil {
		return 0, fmt.Errorf("error in IPFIX exporting process when sending template record: %v", err)
	}

	// Get all elements from template record.
	exp.elementsList = elements

	return sentBytes, nil
}

func (exp *flowExporter) sendDataSet(dataSet ipfix.IPFIXSet, record flowexporter.FlowRecord, templateID uint16) error {
	nodeName, _ := env.GetNodeName()

	// Iterate over all infoElements in the list
	for _, ie := range exp.elementsList {
		switch ieName := ie.Element.Name; ieName {
		case "flowStartSeconds":
			ie.Value = uint32(record.Conn.StartTime.Unix())
		case "flowEndSeconds":
			ie.Value = uint32(time.Now().Unix())
		case "sourceIPv4Address":
			ie.Value = record.Conn.TupleOrig.SourceAddress
		case "destinationIPv4Address":
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
		}
	}

	err := dataSet.AddRecord(exp.elementsList, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}

	sentBytes, err := exp.process.AddSetAndSendMsg(ipfixentities.Data, dataSet.GetSet())
	if err != nil {
		return fmt.Errorf("error in IPFIX exporting process when sending data record: %v", err)
	}
	klog.V(4).Infof("Flow record created and sent. Bytes sent: %d", sentBytes)
	return nil
}
