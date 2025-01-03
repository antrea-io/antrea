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
	"reflect"
	"time"

	"github.com/google/uuid"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
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
	config                     flowaggregatorconfig.FlowCollectorConfig
	externalFlowCollectorAddr  string
	externalFlowCollectorProto string
	exportingProcess           ipfix.IPFIXExportingProcess
	sendJSONRecord             bool
	observationDomainID        uint32
	templateRefreshTimeout     time.Duration
	templateIDv4               uint16
	templateIDv6               uint16
	registry                   ipfix.IPFIXRegistry
	set                        ipfixentities.Set
	clusterUUID                uuid.UUID
}

// genObservationDomainID generates an IPFIX Observation Domain ID when one is not provided by the
// user through the flow aggregator configuration. It is generated as a hash of the cluster UUID.
func genObservationDomainID(clusterUUID uuid.UUID) uint32 {
	h := fnv.New32()
	h.Write(clusterUUID[:])
	observationDomainID := h.Sum32()
	return observationDomainID
}

func NewIPFIXExporter(
	clusterUUID uuid.UUID,
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
		observationDomainID = genObservationDomainID(clusterUUID)
	}
	klog.InfoS("Flow aggregator Observation Domain ID", "domainID", observationDomainID)

	exporter := &IPFIXExporter{
		config:                     opt.Config.FlowCollector,
		externalFlowCollectorAddr:  opt.ExternalFlowCollectorAddr,
		externalFlowCollectorProto: opt.ExternalFlowCollectorProto,
		sendJSONRecord:             sendJSONRecord,
		observationDomainID:        observationDomainID,
		templateRefreshTimeout:     opt.TemplateRefreshTimeout,
		registry:                   registry,
		set:                        ipfixentities.NewSet(false),
		clusterUUID:                clusterUUID,
	}

	return exporter
}

func (e *IPFIXExporter) Start() {
	// no-op, initIPFIXExportingProcess will be called whenever AddRecord is
	// called as needed.
}

func (e *IPFIXExporter) Stop() {
	if e.exportingProcess != nil {
		e.exportingProcess.CloseConnToCollector()
		e.exportingProcess = nil
	}
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

func (e *IPFIXExporter) UpdateOptions(opt *options.Options) {
	config := opt.Config.FlowCollector
	if reflect.DeepEqual(config, e.config) {
		return
	}

	e.config = config
	e.externalFlowCollectorAddr = opt.ExternalFlowCollectorAddr
	e.externalFlowCollectorProto = opt.ExternalFlowCollectorProto
	if opt.Config.FlowCollector.RecordFormat == "JSON" {
		e.sendJSONRecord = true
	} else {
		e.sendJSONRecord = false
	}
	if opt.Config.FlowCollector.ObservationDomainID != nil {
		e.observationDomainID = *opt.Config.FlowCollector.ObservationDomainID
	} else {
		e.observationDomainID = genObservationDomainID(e.clusterUUID)
	}
	e.templateRefreshTimeout = opt.TemplateRefreshTimeout
	klog.InfoS("New IPFIXExporter configuration", "collectorAddress", e.externalFlowCollectorAddr, "collectorProtocol", e.externalFlowCollectorProto, "sendJSON", e.sendJSONRecord, "domainID", e.observationDomainID, "templateRefreshTimeout", e.templateRefreshTimeout)

	if e.exportingProcess != nil {
		e.exportingProcess.CloseConnToCollector()
		e.exportingProcess = nil
	}
}

func (e *IPFIXExporter) sendRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	if e.exportingProcess == nil {
		if err := initIPFIXExportingProcess(e); err != nil {
			// in case of error, the FlowAggregator flowExportLoop will retry after activeFlowRecordTimeout
			return fmt.Errorf("error when initializing IPFIX exporting process: %v", err)
		}
	}

	templateID := e.templateIDv4
	if isRecordIPv6 {
		templateID = e.templateIDv6
	}

	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	e.set.ResetSet()
	if err := e.set.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	if err := e.set.AddRecordV2(record.GetOrderedElementList(), templateID); err != nil {
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
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			// TCP transport does not need any tempRefTimeout, so sending 0.
			TempRefTimeout:  0,
			TLSClientConfig: nil,
			SendJSONRecord:  e.sendJSONRecord,
		}
	} else {
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			TempRefTimeout:      uint32(e.templateRefreshTimeout.Seconds()),
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
	for _, ie := range infoelements.AntreaLabelsElementList {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	e.set.ResetSet()
	if err := e.set.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := e.set.AddRecordV2(elements, templateID)
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
