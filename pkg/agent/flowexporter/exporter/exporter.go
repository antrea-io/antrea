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
	"unicode"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
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
	// Substring "reverse" is an indication to get reverse element of go-ipfix library.
	IANAReverseInfoElements = []string{
		"reverse_PacketTotalCount",
		"reverse_OctetTotalCount",
		"reverse_PacketDeltaCount",
		"reverse_OctetDeltaCount",
	}
	AntreaInfoElements = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
	}
)

type flowExporter struct {
	flowRecords     *flowrecords.FlowRecords
	process         ipfix.IPFIXExportingProcess
	elementsList    []*ipfixentities.InfoElement
	exportFrequency uint
	pollInterval    time.Duration
	templateID      uint16
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

func NewFlowExporter(records *flowrecords.FlowRecords, expProcess ipfix.IPFIXExportingProcess, elemList []*ipfixentities.InfoElement, exportFrequency uint, pollInterval time.Duration, tempID uint16) *flowExporter {
	return &flowExporter{
		records,
		expProcess,
		elemList,
		exportFrequency,
		pollInterval,
		tempID,
	}
}

func InitFlowExporter(collector net.Addr, records *flowrecords.FlowRecords, exportFrequency uint, pollInterval time.Duration) (*flowExporter, error) {
	// Create IPFIX exporting expProcess and initialize registries and other related entities
	obsID, err := genObservationID()
	if err != nil {
		return nil, fmt.Errorf("cannot generate obsID for IPFIX ipfixexport: %v", err)
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
		return nil, fmt.Errorf("error while initializing IPFIX exporting expProcess: %v", err)
	}
	expProcess.LoadRegistries()

	flowExp := NewFlowExporter(records, expProcess, nil, exportFrequency, pollInterval, expProcess.NewTemplateID())

	templateRec := ipfix.NewIPFIXTemplateRecord(uint16(len(IANAInfoElements)+len(IANAReverseInfoElements)+len(AntreaInfoElements)), flowExp.templateID)

	sentBytes, err := flowExp.sendTemplateRecord(templateRec)
	if err != nil {
		return nil, fmt.Errorf("error while creating and sending template record through IPFIX process: %v", err)
	}
	klog.V(2).Infof("Initialized flow exporter and sent %d bytes size of template record", sentBytes)

	return flowExp, nil
}

// Run enables to export flow records periodically at a given flow export frequency
func (exp *flowExporter) Run(stopCh <-chan struct{}, pollDone <-chan struct{}) {
	klog.Infof("Start exporting IPFIX flow records")
	ticker := time.NewTicker(time.Duration(exp.exportFrequency) * exp.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			exp.process.CloseConnToCollector()
			break
		case <-ticker.C:
			// Waiting for expected number of pollDone signals from go routine(ConnectionStore.Run) is necessary because
			// IPFIX collector computes throughput based on flow records received interval. Number of pollDone
			// signals should be equal to export frequency before starting the export cycle.
			for i := uint(0); i < exp.exportFrequency; i++ {
				<-pollDone
			}
			err := exp.flowRecords.BuildFlowRecords()
			if err != nil {
				klog.Errorf("Error when building flow records: %v", err)
				exp.process.CloseConnToCollector()
				break
			}
			err = exp.sendFlowRecords()
			if err != nil {
				klog.Errorf("Error when sending flow records: %v", err)
				exp.process.CloseConnToCollector()
				break
			}
		}
	}
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
		element, err := exp.process.GetIANARegistryInfoElement(ie, false)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		if _, err = templateRec.AddInfoElement(element, nil); err != nil {
			return 0, fmt.Errorf("error when adding %s to template: %v", element.Name, err)
		}
	}
	for _, ie := range IANAReverseInfoElements {
		split := strings.Split(ie, "_")
		runeStr := []rune(split[1])
		runeStr[0] = unicode.ToLower(runeStr[0])
		element, err := exp.process.GetIANARegistryInfoElement(string(runeStr), true)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		if _, err = templateRec.AddInfoElement(element, nil); err != nil {
			return 0, fmt.Errorf("error when adding %s to template: %v", element.Name, err)
		}
	}
	for _, ie := range AntreaInfoElements {
		element, err := exp.process.GetAntreaRegistryInfoElement(ie, false)
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
			_, err = dataRec.AddInfoElement(ie, record.Conn.StartTime.Unix())
		case "flowEndSeconds":
			_, err = dataRec.AddInfoElement(ie, record.Conn.StopTime.Unix())
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
			deltaPkts := 0
			if record.PrevPackets != 0 {
				deltaPkts = int(record.Conn.OriginalPackets) - int(record.PrevPackets)
			}
			if deltaPkts < 0 {
				klog.Warningf("Delta packets is not expected to be negative: %d", deltaPkts)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaPkts))
		case "octetDeltaCount":
			deltaBytes := 0
			if record.PrevBytes != 0 {
				deltaBytes = int(record.Conn.OriginalBytes) - int(record.PrevBytes)
			}
			if deltaBytes < 0 {
				klog.Warningf("Delta bytes is not expected to be negative: %d", deltaBytes)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaBytes))
		case "reverse_PacketTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.ReversePackets)
		case "reverse_OctetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.ReverseBytes)
		case "reverse_PacketDeltaCount":
			deltaPkts := 0
			if record.PrevReversePackets != 0 {
				deltaPkts = int(record.Conn.ReversePackets) - int(record.PrevReversePackets)
			}
			if deltaPkts < 0 {
				klog.Warningf("Delta packets is not expected to be negative: %d", deltaPkts)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaPkts))
		case "reverse_OctetDeltaCount":
			deltaBytes := 0
			if record.PrevReverseBytes != 0 {
				deltaBytes = int(record.Conn.ReverseBytes) - int(record.PrevReverseBytes)
			}
			if deltaBytes < 0 {
				klog.Warningf("Delta bytes is not expected to be negative: %d", deltaBytes)
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
