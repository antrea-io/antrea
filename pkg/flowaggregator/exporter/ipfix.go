// Copyright 2022 Antrea Authors
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

package exporter

import (
	"fmt"
	"hash/fnv"

	"github.com/google/uuid"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/ipfix"
)

// this is used for unit testing
var (
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		return exporter.initExportingProcess()
	}
)

type IPFIXExporter struct {
	externalFlowCollectorAddr  string
	externalFlowCollectorProto string
	exportingProcess           ipfix.IPFIXExportingProcess
	sendJSONRecord             bool
	includePodLabels           bool
	observationDomainID        uint32
	templateIDv4               uint16
	templateIDv6               uint16
	set                        ipfixentities.Set
	registry                   ipfix.IPFIXRegistry
}

// genObservationDomainID generates an IPFIX Observation Domain ID when one is not provided by the
// user through the flow aggregator configuration. It will first try to generate one
// deterministically based on the cluster UUID (if available, with a timeout of 10s). Otherwise, it
// will generate a random one.
func genObservationDomainID(k8sClient kubernetes.Interface) uint32 {
	clusterUUID, err := getClusterUUID(k8sClient)
	if err != nil {
		klog.ErrorS(err, "Error when retrieving cluster UUID; will generate a random observation domain ID")
		clusterUUID = uuid.New()
	}
	h := fnv.New32()
	h.Write(clusterUUID[:])
	observationDomainID := h.Sum32()
	return observationDomainID
}

func NewIPFIXExporter(
	k8sClient kubernetes.Interface,
	opt *options.Options,
	registry ipfix.IPFIXRegistry,
) *IPFIXExporter {
	var sendJSONRecord bool
	if opt.Config.FlowCollector.RecordFormat == "JSON" {
		sendJSONRecord = true
	} else {
		sendJSONRecord = false
	}

	var observationDomainID uint32
	if opt.Config.FlowCollector.ObservationDomainID != nil {
		observationDomainID = *opt.Config.FlowCollector.ObservationDomainID
	} else {
		observationDomainID = genObservationDomainID(k8sClient)
	}
	klog.InfoS("Flow aggregator Observation Domain ID", "Domain ID", observationDomainID)

	exporter := &IPFIXExporter{
		externalFlowCollectorAddr:  opt.ExternalFlowCollectorAddr,
		externalFlowCollectorProto: opt.ExternalFlowCollectorProto,
		sendJSONRecord:             sendJSONRecord,
		includePodLabels:           opt.Config.RecordContents.PodLabels,
		observationDomainID:        observationDomainID,
		registry:                   registry,
		set:                        ipfixentities.NewSet(false),
	}

	return exporter
}

func (e *IPFIXExporter) Start() {
	// no-op
}

func (e *IPFIXExporter) Stop() {
	// no-op
}

func (e *IPFIXExporter) AddRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	if err := e.sendRecord(record, isRecordIPv6); err != nil {
		if e.exportingProcess != nil {
			e.exportingProcess.CloseConnToCollector()
			e.exportingProcess = nil
		}
		// in case of error, the FlowAggregator flowExportLoop will retry after activeFlowRecordTimeout
		return fmt.Errorf("error when sending IPFIX record: %v", err)
	}
	return nil
}

func (e *IPFIXExporter) updateExternalFlowCollectorAddr(address, protocol string) {
	if address == e.externalFlowCollectorAddr && protocol == e.externalFlowCollectorProto {
		return
	}
	klog.InfoS("Updating flow-collector address")
	e.externalFlowCollectorAddr = address
	e.externalFlowCollectorProto = protocol
	klog.InfoS("Config ExternalFlowCollectorAddr is changed", "address", e.externalFlowCollectorAddr, "protocol", e.externalFlowCollectorProto)
	if e.exportingProcess != nil {
		e.exportingProcess.CloseConnToCollector()
		e.exportingProcess = nil
	}
}

func (e *IPFIXExporter) UpdateOptions(opt *options.Options) {
	e.updateExternalFlowCollectorAddr(opt.ExternalFlowCollectorAddr, opt.ExternalFlowCollectorProto)
}

func (e *IPFIXExporter) sendRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	templateID := e.templateIDv4
	if isRecordIPv6 {
		templateID = e.templateIDv6
	}

	if e.exportingProcess == nil {
		if err := initIPFIXExportingProcess(e); err != nil {
			// in case of error, the FlowAggregator flowExportLoop will retry after activeFlowRecordTimeout
			return fmt.Errorf("error when initializing IPFIX exporting process: %v", err)
		}
	}

	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	e.set.ResetSet()
	if err := e.set.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	if err := e.set.AddRecord(record.GetOrderedElementList(), templateID); err != nil {
		return err
	}
	sentBytes, err := e.exportingProcess.SendSet(e.set)
	if err != nil {
		return err
	}
	klog.V(4).InfoS("Data set sent successfully", "bytes sent", sentBytes)
	return nil
}

func (e *IPFIXExporter) initExportingProcess() error {
	// TODO: This code can be further simplified by changing the go-ipfix API to accept
	// externalFlowCollectorAddr and externalFlowCollectorProto instead of net.Addr input.
	var expInput exporter.ExporterInput
	if e.externalFlowCollectorProto == "tcp" {
		// TCP transport does not need any tempRefTimeout, so sending 0.
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			TempRefTimeout:      0,
			TLSClientConfig:     nil,
			SendJSONRecord:      e.sendJSONRecord,
		}
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s. So we will send out template every 30 minutes.
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			TempRefTimeout:      1800,
			TLSClientConfig:     nil,
			SendJSONRecord:      e.sendJSONRecord,
		}
	}
	ep, err := exporter.InitExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("got error when initializing IPFIX exporting process: %v", err)
	}
	e.exportingProcess = ep
	// Currently, we send two templates for IPv4 and IPv6 regardless of the IP families supported by cluster
	if err = e.createAndSendTemplate(false); err != nil {
		return err
	}
	if err = e.createAndSendTemplate(true); err != nil {
		return err
	}

	return nil
}

func (e *IPFIXExporter) createAndSendTemplate(isRecordIPv6 bool) error {
	templateID := e.exportingProcess.NewTemplateID()
	recordIPFamily := "IPv4"
	if isRecordIPv6 {
		recordIPFamily = "IPv6"
	}
	if isRecordIPv6 {
		e.templateIDv6 = templateID
	} else {
		e.templateIDv4 = templateID
	}
	bytesSent, err := e.sendTemplateSet(isRecordIPv6)
	if err != nil {
		e.exportingProcess.CloseConnToCollector()
		e.exportingProcess = nil
		e.set.ResetSet()
		return fmt.Errorf("sending %s template set failed, err: %v", recordIPFamily, err)
	}
	klog.V(2).InfoS("Exporting process initialized", "bytesSent", bytesSent, "templateSetIPFamily", recordIPFamily)
	return nil
}

func (e *IPFIXExporter) sendTemplateSet(isIPv6 bool) (int, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)
	ianaInfoElements := infoelements.IANAInfoElementsIPv4
	antreaInfoElements := infoelements.AntreaInfoElementsIPv4
	templateID := e.templateIDv4
	if isIPv6 {
		ianaInfoElements = infoelements.IANAInfoElementsIPv6
		antreaInfoElements = infoelements.AntreaInfoElementsIPv6
		templateID = e.templateIDv6
	}
	for _, ie := range ianaInfoElements {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range infoelements.IANAReverseInfoElements {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range antreaInfoElements {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	// The order of source and destination stats elements needs to match the order specified in
	// addFieldsForStatsAggregation method in go-ipfix aggregation process.
	for i := range infoelements.StatsElementList {
		// Add Antrea source stats fields
		ieName := infoelements.AntreaSourceStatsElementList[i]
		ie, err := e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add Antrea destination stats fields
		ieName = infoelements.AntreaDestinationStatsElementList[i]
		ie, err = e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range infoelements.AntreaFlowEndSecondsElementList {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for i := range infoelements.AntreaThroughputElementList {
		// Add common throughput fields
		ieName := infoelements.AntreaThroughputElementList[i]
		ie, err := e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add source node specific throughput fields
		ieName = infoelements.AntreaSourceThroughputElementList[i]
		ie, err = e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add destination node specific throughput fields
		ieName = infoelements.AntreaDestinationThroughputElementList[i]
		ie, err = e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	if e.includePodLabels {
		for _, ie := range infoelements.AntreaLabelsElementList {
			ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return 0, err
			}
			elements = append(elements, ie)
		}
	}
	e.set.ResetSet()
	if err := e.set.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := e.set.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error when adding record to set, error: %v", err)
	}
	bytesSent, err := e.exportingProcess.SendSet(e.set)
	return bytesSent, err
}

func (e *IPFIXExporter) createInfoElementForTemplateSet(ieName string, enterpriseID uint32) (ipfixentities.InfoElementWithValue, error) {
	element, err := e.registry.GetInfoElement(ieName, enterpriseID)
	if err != nil {
		return nil, fmt.Errorf("%s not present. returned error: %v", ieName, err)
	}
	ie, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	if err != nil {
		return nil, err
	}
	return ie, nil
}
