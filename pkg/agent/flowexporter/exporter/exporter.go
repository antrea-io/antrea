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
		"destinationServicePort",
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
	elementsList    []*ipfixentities.InfoElement
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

	templateRec := ipfix.NewIPFIXTemplateRecord(uint16(len(IANAInfoElements)+len(IANAReverseInfoElements)+len(AntreaInfoElements)), exp.templateID)

	sentBytes, err := exp.sendTemplateRecord(templateRec)
	if err != nil {
		return err
	}
	klog.V(2).Infof("Initialized flow exporter and sent %d bytes size of template record", sentBytes)

	return nil
}

func (exp *flowExporter) sendFlowRecords() error {
	sendAndUpdateFlowRecord := func(key flowexporter.ConnectionKey, record flowexporter.FlowRecord) error {
		dataRec := ipfix.NewIPFIXDataRecord(exp.templateID)
		if err := exp.sendDataRecord(dataRec, record); err != nil {
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

func (exp *flowExporter) sendTemplateRecord(templateRec ipfix.IPFIXRecord) (int, error) {
	// Add template header
	_, err := templateRec.PrepareRecord()
	if err != nil {
		return 0, fmt.Errorf("error when writing template header: %v", err)
	}

	for _, ie := range IANAInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		if _, err = templateRec.AddInfoElement(element, nil); err != nil {
			return 0, fmt.Errorf("error when adding %s to template: %v", element.Name, err)
		}
	}
	for _, ie := range IANAReverseInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		if _, err = templateRec.AddInfoElement(element, nil); err != nil {
			return 0, fmt.Errorf("error when adding %s to template: %v", element.Name, err)
		}
	}
	for _, ie := range AntreaInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("information element %s is not present in Antrea registry", ie)
		}
		if _, err := templateRec.AddInfoElement(element, nil); err != nil {
			return 0, fmt.Errorf("error when adding %s to template: %v", element.Name, err)
		}
	}

	sentBytes, err := exp.process.AddRecordAndSendMsg(ipfixentities.Template, templateRec.GetRecord())
	if err != nil {
		return 0, fmt.Errorf("error in IPFIX exporting process when sending template record: %v", err)
	}

	// Get all elements from template record.
	exp.elementsList = templateRec.GetTemplateElements()

	return sentBytes, nil
}

func (exp *flowExporter) sendDataRecord(dataRec ipfix.IPFIXRecord, record flowexporter.FlowRecord) error {
	nodeName, _ := env.GetNodeName()
	// Iterate over all infoElements in the list
	for _, ie := range exp.elementsList {
		var err error
		switch ieName := ie.Name; ieName {
		case "flowStartSeconds":
			_, err = dataRec.AddInfoElement(ie, uint32(record.Conn.StartTime.Unix()))
		case "flowEndSeconds":
			_, err = dataRec.AddInfoElement(ie, uint32(record.Conn.StopTime.Unix()))
		case "sourceIPv4Address":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.SourceAddress)
		case "destinationIPv4Address":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleReply.SourceAddress)
		case "sourceTransportPort":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.SourcePort)
		case "destinationTransportPort":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleReply.SourcePort)
		case "protocolIdentifier":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.Protocol)
		case "packetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.OriginalPackets)
		case "octetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.OriginalBytes)
		case "packetDeltaCount":
			deltaPkts := int64(0)
			if record.PrevPackets != 0 {
				deltaPkts = int64(record.Conn.OriginalPackets) - int64(record.PrevPackets)
			}
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaPkts))
		case "octetDeltaCount":
			deltaBytes := int64(0)
			if record.PrevBytes != 0 {
				deltaBytes = int64(record.Conn.OriginalBytes) - int64(record.PrevBytes)
			}
			if deltaBytes < 0 {
				klog.Warningf("Byte delta count for connection should not be negative: %d", deltaBytes)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaBytes))
		case "reversePacketTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.ReversePackets)
		case "reverseOctetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.ReverseBytes)
		case "reversePacketDeltaCount":
			deltaPkts := int64(0)
			if record.PrevReversePackets != 0 {
				deltaPkts = int64(record.Conn.ReversePackets) - int64(record.PrevReversePackets)
			}
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaPkts))
		case "reverseOctetDeltaCount":
			deltaBytes := int64(0)
			if record.PrevReverseBytes != 0 {
				deltaBytes = int64(record.Conn.ReverseBytes) - int64(record.PrevReverseBytes)
			}
			if deltaBytes < 0 {
				klog.Warningf("Byte delta count for connection should not be negative: %d", deltaBytes)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaBytes))
		case "sourcePodNamespace":
			_, err = dataRec.AddInfoElement(ie, record.Conn.SourcePodNamespace)
		case "sourcePodName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.SourcePodName)
		case "sourceNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if record.Conn.SourcePodName != "" {
				_, err = dataRec.AddInfoElement(ie, nodeName)
			} else {
				_, err = dataRec.AddInfoElement(ie, "")
			}
		case "destinationPodNamespace":
			_, err = dataRec.AddInfoElement(ie, record.Conn.DestinationPodNamespace)
		case "destinationPodName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.DestinationPodName)
		case "destinationNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if record.Conn.DestinationPodName != "" {
				_, err = dataRec.AddInfoElement(ie, nodeName)
			} else {
				_, err = dataRec.AddInfoElement(ie, "")
			}
		case "destinationClusterIPv4":
			if record.Conn.DestinationServicePortName != "" {
				_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.DestinationAddress)
			} else {
				// Sending dummy IP as IPFIX collector expects constant length of data for IP field.
				// We should probably think of better approach as this involves customization of IPFIX collector to ignore
				// this dummy IP address.
				_, err = dataRec.AddInfoElement(ie, net.IP{0, 0, 0, 0})
			}
		case "destinationServicePort":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.DestinationPort)
		case "destinationServicePortName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.DestinationServicePortName)
		case "ingressNetworkPolicyName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.IngressNetworkPolicyName)
		case "ingressNetworkPolicyNamespace":
			_, err = dataRec.AddInfoElement(ie, record.Conn.IngressNetworkPolicyNamespace)
		case "egressNetworkPolicyName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.EgressNetworkPolicyName)
		case "egressNetworkPolicyNamespace":
			_, err = dataRec.AddInfoElement(ie, record.Conn.EgressNetworkPolicyNamespace)
		}
		if err != nil {
			return fmt.Errorf("error while adding info element: %s to data record: %v", ie.Name, err)
		}
	}

	sentBytes, err := exp.process.AddRecordAndSendMsg(ipfixentities.Data, dataRec.GetRecord())
	if err != nil {
		return fmt.Errorf("error in IPFIX exporting process when sending data record: %v", err)
	}
	klog.V(4).Infof("Flow record created and sent. Bytes sent: %d", sentBytes)

	return nil
}
