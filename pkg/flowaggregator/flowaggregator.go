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
	"hash/fnv"
	"net"
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/ipfix"
)

var (
	ianaInfoElements = []string{
		"flowStartSeconds",
		"flowEndSeconds",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
		"packetDeltaCount",
		"octetDeltaCount",
		"sourceIPv4Address",
		"destinationIPv4Address",
	}
	ianaReverseInfoElements = []string{
		"reversePacketTotalCount",
		"reverseOctetTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetDeltaCount",
	}
	antreaInfoElements = []string{
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
		"destinationClusterIPv4",
	}
	aggregatorElements = []string{
		"originalExporterIPv4Address",
		"originalObservationDomainId",
	}
	aggregationFields = []string{
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationClusterIPv4",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
	}
	aggregationWorkerNum = 2
)

type AggregatorTransportProtocol string

const (
	AggregatorTransportProtocolTCP AggregatorTransportProtocol = "TCP"
	AggregatorTransportProtocolUDP AggregatorTransportProtocol = "UDP"
	flowAggregatorDNSName          string                      = "flow-aggregator.flow-aggregator.svc"
)

type flowAggregator struct {
	externalFlowCollectorAddr   net.Addr
	aggregatorTransportProtocol AggregatorTransportProtocol
	collectingProcess           ipfix.IPFIXCollectingProcess
	aggregationProcess          ipfix.IPFIXAggregationProcess
	exportInterval              time.Duration
	exportingProcess            ipfix.IPFIXExportingProcess
	templateID                  uint16
	registry                    ipfix.IPFIXRegistry
}

func NewFlowAggregator(externalFlowCollectorAddr net.Addr, exportInterval time.Duration, aggregatorTransportProtocol AggregatorTransportProtocol) *flowAggregator {
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()
	fa := &flowAggregator{
		externalFlowCollectorAddr,
		aggregatorTransportProtocol,
		nil,
		nil,
		exportInterval,
		nil,
		0,
		registry,
	}
	return fa
}

func genObservationID() (uint32, error) {
	// TODO: Change to use cluster UUID to generate observation ID once it's available
	h := fnv.New32()
	h.Write([]byte(flowAggregatorDNSName))
	return h.Sum32(), nil
}

func (fa *flowAggregator) InitCollectingProcess() error {
	var collectAddr net.Addr
	var err error
	if fa.aggregatorTransportProtocol == AggregatorTransportProtocolTCP {
		collectAddr, _ = net.ResolveTCPAddr("tcp", "0.0.0.0:4739")
		fa.collectingProcess, err = ipfix.NewIPFIXCollectingProcess(collectAddr, 65535, 0)
	} else {
		collectAddr, _ = net.ResolveUDPAddr("udp", "0.0.0.0:4739")
		fa.collectingProcess, err = ipfix.NewIPFIXCollectingProcess(collectAddr, 1024, 0)
	}
	return err
}

func (fa *flowAggregator) InitAggregationProcess() error {
	var err error
	fa.aggregationProcess, err = ipfix.NewIPFIXAggregationProcess(fa.collectingProcess.GetMsgChan(), aggregationWorkerNum, aggregationFields)
	return err
}

func (fa *flowAggregator) initExportingProcess() error {
	obsID, err := genObservationID()
	if err != nil {
		return fmt.Errorf("cannot generate observation ID for flow aggregator: %v", err)
	}
	var ep ipfix.IPFIXExportingProcess
	if fa.externalFlowCollectorAddr.Network() == "tcp" {
		// tempRefTimeout is the template refresh timeout. TCP transport does not need send template periodically, so sending 0.
		ep, err = ipfix.NewIPFIXExportingProcess(fa.externalFlowCollectorAddr, obsID, 0)
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s. So we will send out template every 30 minutes.
		ep, err = ipfix.NewIPFIXExportingProcess(fa.externalFlowCollectorAddr, obsID, 1800)
	}
	if err != nil {
		return fmt.Errorf("got error when initializing IPFIX exporting process: %v", err)
	}
	fa.exportingProcess = ep
	fa.templateID = fa.exportingProcess.NewTemplateID()
	templateSet := ipfix.NewSet(ipfixentities.Template, fa.templateID, false)

	bytesSent, err := fa.sendTemplateSet(templateSet)
	if err != nil {
		fa.exportingProcess.CloseConnToCollector()
		fa.exportingProcess = nil
		fa.templateID = 0
		return fmt.Errorf("sending template set failed, err: %v", err)
	}
	klog.V(2).Infof("Initialized exporting process and sent %d bytes size of template set", bytesSent)
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
			err := fa.aggregationProcess.ForAllRecordsDo(fa.sendFlowKeyRecords)
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

func (fa *flowAggregator) sendFlowKeyRecords(key ipfixintermediate.FlowKey, records []ipfixentities.Record) error {
	setSent := ipfix.NewSet(ipfixentities.Data, fa.templateID, false)
	for _, record := range records {
		err := setSent.AddRecord(record.GetOrderedElementList(), fa.templateID)
		if err != nil {
			return fmt.Errorf("AddRecord failed, error: %v", err)
		}
	}
	bytesSent, err := fa.exportingProcess.AddSetAndSendMsg(ipfixentities.Data, setSent.GetSet())
	if err != nil {
		return fmt.Errorf("send data record for key %+v failed, error: %v", key, err)
	}
	// TODO: We will delete only inactive flows when intermediate process supports it in go-ipfix.
	fa.aggregationProcess.DeleteFlowKeyFromMapWithoutLock(key)
	klog.V(4).Infof("Sent key: %+v, sent bytes: %d, records num: %d\n", key, bytesSent, len(records))
	return nil
}

func (fa *flowAggregator) sendTemplateSet(templateSet ipfix.IPFIXSet) (int, error) {
	elements := make([]*ipfixentities.InfoElementWithValue, 0)
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
	err := templateSet.AddRecord(elements, fa.templateID)
	if err != nil {
		return 0, fmt.Errorf("AddRecord failed, error: %v", err)
	}
	bytesSent, err := fa.exportingProcess.AddSetAndSendMsg(ipfixentities.Template, templateSet.GetSet())
	return bytesSent, err
}
