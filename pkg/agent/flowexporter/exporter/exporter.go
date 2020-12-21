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
	"strings"
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	"github.com/vmware-tanzu/antrea/pkg/ipfix"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
)

var (
	IANAInfoElementsCommon = []string{
		"flowStartSeconds",
		"flowEndSeconds",
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
	}
	AntreaInfoElementsIPv4 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	AntreaInfoElementsIPv6 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)
)

const (
	// flowAggregatorDNSName is a static DNS name for the deployed Flow Aggregator
	// Service in the K8s cluster. By default, both the Name and Namespace of the
	// Service are set to "flow-aggregator".
	flowAggregatorDNSName = "flow-aggregator.flow-aggregator.svc"
	defaultIPFIXPort      = "4739"
)

type flowExporter struct {
	flowRecords     *flowrecords.FlowRecords
	process         ipfix.IPFIXExportingProcess
	elementsListv4  []*ipfixentities.InfoElementWithValue
	elementsListv6  []*ipfixentities.InfoElementWithValue
	exportFrequency uint
	pollCycle       uint
	templateIDv4    uint16
	templateIDv6    uint16
	registry        ipfix.IPFIXRegistry
	v4Enabled       bool
	v6Enabled       bool
	collectorAddr   net.Addr
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

func NewFlowExporter(records *flowrecords.FlowRecords, exportFrequency uint, v4Enabled bool, v6Enabled bool) *flowExporter {
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()
	return &flowExporter{
		records,
		nil,
		nil,
		nil,
		exportFrequency,
		0,
		0,
		0,
		registry,
		v4Enabled,
		v6Enabled,
		nil,
	}
}

// DoExport enables us to export flow records periodically at a given flow export frequency.
func (exp *flowExporter) Export(collectorAddr string, collectorProto string, stopCh <-chan struct{}, pollDone <-chan struct{}) {
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
					err := exp.initFlowExporter(collectorAddr, collectorProto)
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

func (exp *flowExporter) initFlowExporter(collectorAddr string, collectorProto string) error {
	// Create IPFIX exporting expProcess, initialize registries and other related entities
	obsID, err := genObservationID()
	if err != nil {
		return fmt.Errorf("cannot generate obsID for IPFIX ipfixexport: %v", err)
	}

	if strings.Contains(collectorAddr, flowAggregatorDNSName) {
		hostIPs, err := net.LookupIP(flowAggregatorDNSName)
		if err != nil {
			return err
		}
		// Currently, supporting only IPv4 for Flow Aggregator.
		ip := hostIPs[0].To4()
		if ip != nil {
			// Update the collector address with resolved IP of flow aggregator
			collectorAddr = net.JoinHostPort(ip.String(), defaultIPFIXPort)
		} else {
			return fmt.Errorf("resolved Flow Aggregator address %v is not supported", hostIPs[0])
		}
	}

	// TODO: This code can be further simplified by changing the go-ipfix API to accept
	// collectorAddr and collectorProto instead of net.Addr input.
	var expInput exporter.ExporterInput
	if collectorProto == "tcp" {
		collector, err := net.ResolveTCPAddr("tcp", collectorAddr)
		if err != nil {
			return err
		}
		// TCP transport does not need any tempRefTimeout, so sending 0.
		// tempRefTimeout is the template refresh timeout, which specifies how often
		// the exporting process should send the template again.
		expInput = exporter.ExporterInput{
			CollectorAddr:       collector,
			ObservationDomainID: obsID,
			TempRefTimeout:      0,
			PathMTU:             0,
			IsEncrypted:         false,
		}
	} else {
		collector, err := net.ResolveUDPAddr("udp", collectorAddr)
		if err != nil {
			return err
		}
		// For UDP transport, hardcoding tempRefTimeout value as 1800s.
		expInput = exporter.ExporterInput{
			CollectorAddr:       collector,
			ObservationDomainID: obsID,
			TempRefTimeout:      1800,
			PathMTU:             0,
			IsEncrypted:         false,
		}
	}
	expProcess, err := ipfix.NewIPFIXExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("error when starting exporter: %v", err)
	}

	exp.process = expProcess
	if exp.v4Enabled {
		templateID := expProcess.NewTemplateID()
		exp.templateIDv4 = templateID
		templateSet := ipfix.NewSet(ipfixentities.Template, exp.templateIDv4, false)
		sentBytes, err := exp.sendTemplateSet(templateSet, false)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Initialized flow exporter for IPv4 flow records and sent %d bytes size of template record", sentBytes)
	}
	if exp.v6Enabled {
		templateID := expProcess.NewTemplateID()
		exp.templateIDv6 = templateID
		templateSet := ipfix.NewSet(ipfixentities.Template, exp.templateIDv6, false)
		sentBytes, err := exp.sendTemplateSet(templateSet, true)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Initialized flow exporter for IPv6 flow records and sent %d bytes size of template record", sentBytes)
	}

	return nil
}

func (exp *flowExporter) sendFlowRecords() error {
	addAndSendFlowRecord := func(key flowexporter.ConnectionKey, record flowexporter.FlowRecord) error {
		if record.IsIPv6 {
			dataSetIPv6 := ipfix.NewSet(ipfixentities.Data, exp.templateIDv6, false)
			// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
			if err := exp.addRecordToSet(dataSetIPv6, record); err != nil {
				return err
			}
			if _, err := exp.sendDataSet(dataSetIPv6); err != nil {
				return err
			}
		} else {
			dataSetIPv4 := ipfix.NewSet(ipfixentities.Data, exp.templateIDv4, false)
			// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
			if err := exp.addRecordToSet(dataSetIPv4, record); err != nil {
				return err
			}
			if _, err := exp.sendDataSet(dataSetIPv4); err != nil {
				return err
			}
		}
		if err := exp.flowRecords.ValidateAndUpdateStats(key, record); err != nil {
			return err
		}
		return nil
	}
	err := exp.flowRecords.ForAllFlowRecordsDo(addAndSendFlowRecord)
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

	sentBytes, err := exp.process.SendSet(templateSet.GetSet())
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

func (exp *flowExporter) addRecordToSet(dataSet ipfix.IPFIXSet, record flowexporter.FlowRecord) error {
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
			ie.Value = uint32(time.Now().Unix())
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
			ie.Value = record.Conn.TupleOrig.DestinationPort
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

	templateID := exp.templateIDv4
	if record.IsIPv6 {
		templateID = exp.templateIDv6
	}
	err := dataSet.AddRecord(eL, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}
	return nil
}

func (exp *flowExporter) sendDataSet(dataSet ipfix.IPFIXSet) (int, error) {
	sentBytes, err := exp.process.SendSet(dataSet.GetSet())
	if err != nil {
		return 0, fmt.Errorf("error when sending data set: %v", err)
	}
	klog.V(4).Infof("Data set sent successfully. Bytes sent: %d", sentBytes)
	return sentBytes, nil
}
