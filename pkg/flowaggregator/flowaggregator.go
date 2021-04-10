// Copyright 2020 Antrea Authors
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

package flowaggregator

import (
	"fmt"
	"net"
	"time"

	"github.com/vmware/go-ipfix/pkg/collector"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/ipfix"
)

var (
	ianaInfoElementsCommon = []string{
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
	ianaInfoElementsIPv4    = append(ianaInfoElementsCommon, []string{"sourceIPv4Address", "destinationIPv4Address"}...)
	ianaInfoElementsIPv6    = append(ianaInfoElementsCommon, []string{"sourceIPv6Address", "destinationIPv6Address"}...)
	ianaReverseInfoElements = []string{
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
	antreaInfoElementsIPv4   = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	antreaInfoElementsIPv6   = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)
	aggregatorElementsCommon = []string{
		"originalObservationDomainId",
	}
	aggregatorElementsIPv4 = append([]string{"originalExporterIPv4Address"}, aggregatorElementsCommon...)
	aggregatorElementsIPv6 = append([]string{"originalExporterIPv6Address"}, aggregatorElementsCommon...)

	nonStatsElementList = []string{
		"flowEndSeconds",
		"flowEndReason",
		"tcpState",
	}
	statsElementList = []string{
		"octetDeltaCount",
		"octetTotalCount",
		"packetDeltaCount",
		"packetTotalCount",
		"reverseOctetDeltaCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reversePacketTotalCount",
	}
	antreaSourceStatsElementList = []string{
		"octetDeltaCountFromSourceNode",
		"octetTotalCountFromSourceNode",
		"packetDeltaCountFromSourceNode",
		"packetTotalCountFromSourceNode",
		"reverseOctetDeltaCountFromSourceNode",
		"reverseOctetTotalCountFromSourceNode",
		"reversePacketDeltaCountFromSourceNode",
		"reversePacketTotalCountFromSourceNode",
	}
	antreaDestinationStatsElementList = []string{
		"octetDeltaCountFromDestinationNode",
		"octetTotalCountFromDestinationNode",
		"packetDeltaCountFromDestinationNode",
		"packetTotalCountFromDestinationNode",
		"reverseOctetDeltaCountFromDestinationNode",
		"reverseOctetTotalCountFromDestinationNode",
		"reversePacketDeltaCountFromDestinationNode",
		"reversePacketTotalCountFromDestinationNode",
	}
	aggregationElements = &ipfixintermediate.AggregationElements{
		NonStatsElements:                   nonStatsElementList,
		StatsElements:                      statsElementList,
		AggregatedSourceStatsElements:      antreaSourceStatsElementList,
		AggregatedDestinationStatsElements: antreaDestinationStatsElementList,
	}

	correlateFields = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationClusterIPv4",
		"destinationClusterIPv6",
		"destinationServicePort",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
	}
)

const (
	aggregationWorkerNum = 2
	udpTransport         = "udp"
	tcpTransport         = "tcp"
	collectorAddress     = "0.0.0.0:4739"
)

type AggregatorTransportProtocol string

const (
	AggregatorTransportProtocolTCP AggregatorTransportProtocol = "TCP"
	AggregatorTransportProtocolTLS AggregatorTransportProtocol = "TLS"
	AggregatorTransportProtocolUDP AggregatorTransportProtocol = "UDP"
)

type flowAggregator struct {
	externalFlowCollectorAddr   string
	externalFlowCollectorProto  string
	aggregatorTransportProtocol AggregatorTransportProtocol
	collectingProcess           ipfix.IPFIXCollectingProcess
	aggregationProcess          ipfix.IPFIXAggregationProcess
	exportInterval              time.Duration
	exportingProcess            ipfix.IPFIXExportingProcess
	templateIDv4                uint16
	templateIDv6                uint16
	registry                    ipfix.IPFIXRegistry
	set                         ipfix.IPFIXSet
	flowAggregatorAddress       string
	k8sClient                   kubernetes.Interface
	observationDomainID         uint32
}

func NewFlowAggregator(
	externalFlowCollectorAddr string,
	externalFlowCollectorProto string,
	exportInterval time.Duration,
	aggregatorTransportProtocol AggregatorTransportProtocol,
	flowAggregatorAddress string,
	k8sClient kubernetes.Interface,
	observationDomainID uint32,
) *flowAggregator {
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()
	fa := &flowAggregator{
		externalFlowCollectorAddr,
		externalFlowCollectorProto,
		aggregatorTransportProtocol,
		nil,
		nil,
		exportInterval,
		nil,
		0,
		0,
		registry,
		ipfix.NewSet(false),
		flowAggregatorAddress,
		k8sClient,
		observationDomainID,
	}
	return fa
}

func (fa *flowAggregator) InitCollectingProcess() error {
	var err error
	var cpInput collector.CollectorInput
	if fa.aggregatorTransportProtocol == AggregatorTransportProtocolTLS {
		parentCert, privateKey, caCert, err := generateCACertKey()
		if err != nil {
			return fmt.Errorf("error when generating CA certificate: %v", err)
		}
		serverCert, serverKey, err := generateCertKey(parentCert, privateKey, true, fa.flowAggregatorAddress)
		if err != nil {
			return fmt.Errorf("error when creating server certificate: %v", err)
		}

		clientCert, clientKey, err := generateCertKey(parentCert, privateKey, false, "")
		if err != nil {
			return fmt.Errorf("error when creating client certificate: %v", err)
		}
		err = syncCAAndClientCert(caCert, clientCert, clientKey, fa.k8sClient)
		if err != nil {
			return fmt.Errorf("error when synchronizing client certificate: %v", err)
		}
		cpInput = collector.CollectorInput{
			Address:       collectorAddress,
			Protocol:      tcpTransport,
			MaxBufferSize: 65535,
			TemplateTTL:   0,
			IsEncrypted:   true,
			CACert:        caCert,
			ServerKey:     serverKey,
			ServerCert:    serverCert,
		}
	} else if fa.aggregatorTransportProtocol == AggregatorTransportProtocolTCP {
		cpInput = collector.CollectorInput{
			Address:       collectorAddress,
			Protocol:      tcpTransport,
			MaxBufferSize: 65535,
			TemplateTTL:   0,
			IsEncrypted:   false,
		}
	} else {
		cpInput = collector.CollectorInput{
			Address:       collectorAddress,
			Protocol:      udpTransport,
			MaxBufferSize: 1024,
			TemplateTTL:   0,
			IsEncrypted:   false,
		}
	}
	fa.collectingProcess, err = ipfix.NewIPFIXCollectingProcess(cpInput)
	return err
}

func (fa *flowAggregator) InitAggregationProcess() error {
	var err error
	apInput := ipfixintermediate.AggregationInput{
		MessageChan:       fa.collectingProcess.GetMsgChan(),
		WorkerNum:         aggregationWorkerNum,
		CorrelateFields:   correlateFields,
		AggregateElements: aggregationElements,
	}
	fa.aggregationProcess, err = ipfix.NewIPFIXAggregationProcess(apInput)
	return err
}

func (fa *flowAggregator) initExportingProcess() error {
	// TODO: This code can be further simplified by changing the go-ipfix API to accept
	// externalFlowCollectorAddr and externalFlowCollectorProto instead of net.Addr input.
	var expInput exporter.ExporterInput
	if fa.externalFlowCollectorProto == "tcp" {
		// TCP transport does not need any tempRefTimeout, so sending 0.
		expInput = exporter.ExporterInput{
			CollectorAddress:    fa.externalFlowCollectorAddr,
			CollectorProtocol:   fa.externalFlowCollectorProto,
			ObservationDomainID: fa.observationDomainID,
			TempRefTimeout:      0,
			PathMTU:             0,
			IsEncrypted:         false,
		}
	} else {
		collector, err := net.ResolveUDPAddr("udp", fa.externalFlowCollectorAddr)
		if err != nil {
			return err
		}
		// For UDP transport, hardcoding tempRefTimeout value as 1800s. So we will send out template every 30 minutes.
		expInput = exporter.ExporterInput{
			CollectorAddress:    fa.externalFlowCollectorAddr,
			CollectorProtocol:   fa.externalFlowCollectorProto,
			ObservationDomainID: fa.observationDomainID,
			TempRefTimeout:      1800,
			PathMTU:             0,
			IsEncrypted:         false,
		}
	}
	ep, err := ipfix.NewIPFIXExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("got error when initializing IPFIX exporting process: %v", err)
	}
	fa.exportingProcess = ep
	// Currently, we send two templates for IPv4 and IPv6 regardless of the IP families supported by cluster
	fa.templateIDv4 = fa.exportingProcess.NewTemplateID()
	if err := fa.set.PrepareSet(ipfixentities.Template, fa.templateIDv4); err != nil {
		return fmt.Errorf("error when preparing IPv4 template set: %v", err)
	}
	bytesSent, err := fa.sendTemplateSet(fa.set, false)
	if err != nil {
		fa.exportingProcess.CloseConnToCollector()
		fa.exportingProcess = nil
		fa.templateIDv4 = 0
		fa.set.ResetSet()
		return fmt.Errorf("sending IPv4 template set failed, err: %v", err)
	}
	klog.V(2).Infof("Initialized exporting process and sent %d bytes size of IPv4 template set", bytesSent)

	fa.set.ResetSet()
	fa.templateIDv6 = fa.exportingProcess.NewTemplateID()
	if err := fa.set.PrepareSet(ipfixentities.Template, fa.templateIDv6); err != nil {
		return fmt.Errorf("error when preparing IPv6 template set: %v", err)
	}
	bytesSent, err = fa.sendTemplateSet(fa.set, true)
	if err != nil {
		fa.exportingProcess.CloseConnToCollector()
		fa.exportingProcess = nil
		fa.templateIDv6 = 0
		fa.set.ResetSet()
		return fmt.Errorf("sending IPv6 template set failed, err: %v", err)
	}
	klog.V(2).Infof("Initialized exporting process and sent %d bytes size of IPv6 template set", bytesSent)

	return nil
}

func (fa *flowAggregator) Run(stopCh <-chan struct{}) {
	exportTicker := time.NewTicker(fa.exportInterval)
	defer exportTicker.Stop()
	go fa.collectingProcess.Start()
	defer fa.collectingProcess.Stop()
	go fa.aggregationProcess.Start()
	defer fa.aggregationProcess.Stop()
	for {
		select {
		case <-stopCh:
			if fa.exportingProcess != nil {
				fa.exportingProcess.CloseConnToCollector()
			}
			return
		case <-exportTicker.C:
			if fa.exportingProcess == nil {
				err := fa.initExportingProcess()
				if err != nil {
					klog.Errorf("Error when initializing exporting process: %v, will retry in %s", err, fa.exportInterval)
					// Initializing exporting process fails, will retry in next exportInterval
					continue
				}
			}
			err := fa.aggregationProcess.ForAllRecordsDo(fa.sendFlowKeyRecord)
			if err != nil {
				klog.Errorf("Error when sending flow records: %v", err)
				// If there is an error when sending flow records because of intermittent connectivity, we reset the connection
				// to IPFIX collector and retry in the next export cycle to reinitialize the connection and send flow records.
				fa.exportingProcess.CloseConnToCollector()
				fa.exportingProcess = nil
				continue
			}
		}
	}
}

func (fa *flowAggregator) sendFlowKeyRecord(key ipfixintermediate.FlowKey, record ipfixintermediate.AggregationFlowRecord) error {
	if !record.ReadyToSend {
		klog.V(4).Info("Skip sending record that is not correlated.")
		return nil
	}
	templateID := fa.templateIDv4
	if net.ParseIP(key.SourceAddress).To4() == nil || net.ParseIP(key.DestinationAddress).To4() == nil {
		templateID = fa.templateIDv6
	}
	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	fa.set.ResetSet()
	if err := fa.set.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return fmt.Errorf("error when preparing set: %v", err)
	}
	err := fa.set.AddRecord(record.Record.GetOrderedElementList(), templateID)
	if err != nil {
		return fmt.Errorf("error when adding the record to the set: %v", err)
	}
	_, err = fa.sendDataSet(fa.set)
	if err != nil {
		return err
	}
	fa.aggregationProcess.DeleteFlowKeyFromMapWithoutLock(key)
	return nil
}

func (fa *flowAggregator) sendTemplateSet(templateSet ipfix.IPFIXSet, isIPv6 bool) (int, error) {
	elements := make([]*ipfixentities.InfoElementWithValue, 0)
	ianaInfoElements := ianaInfoElementsIPv4
	antreaInfoElements := antreaInfoElementsIPv4
	aggregatorElements := aggregatorElementsIPv4
	templateID := fa.templateIDv4
	if isIPv6 {
		ianaInfoElements = ianaInfoElementsIPv6
		antreaInfoElements = antreaInfoElementsIPv6
		aggregatorElements = aggregatorElementsIPv6
		templateID = fa.templateIDv6
	}
	for _, ie := range ianaInfoElements {
		element, err := fa.registry.GetInfoElement(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ie := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, ie := range ianaReverseInfoElements {
		element, err := fa.registry.GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ie := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, ie := range antreaInfoElements {
		element, err := fa.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ie := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, ie := range aggregatorElements {
		element, err := fa.registry.GetInfoElement(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ie := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, ie := range antreaSourceStatsElementList {
		element, err := fa.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ie := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, ie := range antreaDestinationStatsElementList {
		element, err := fa.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ie := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	err := templateSet.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error when adding record to set, error: %v", err)
	}
	bytesSent, err := fa.exportingProcess.SendSet(templateSet)
	return bytesSent, err
}

func (fa *flowAggregator) sendDataSet(dataSet ipfix.IPFIXSet) (int, error) {
	sentBytes, err := fa.exportingProcess.SendSet(dataSet)
	if err != nil {
		return 0, fmt.Errorf("error when sending data set: %v", err)
	}
	klog.V(4).Infof("Data set sent successfully. Bytes sent: %d", sentBytes)
	return sentBytes, nil
}
