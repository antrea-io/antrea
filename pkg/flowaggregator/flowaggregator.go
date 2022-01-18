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
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/vmware/go-ipfix/pkg/collector"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
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
	antreaInfoElementsIPv4 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	antreaInfoElementsIPv6 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)

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
	antreaLabelsElementList = []string{
		"sourcePodLabels",
		"destinationPodLabels",
	}
	antreaFlowEndSecondsElementList = []string{
		"flowEndSecondsFromSourceNode",
		"flowEndSecondsFromDestinationNode",
	}
	antreaThroughputElementList = []string{
		"throughput",
		"reverseThroughput",
	}
	antreaSourceThroughputElementList = []string{
		"throughputFromSourceNode",
		"reverseThroughputFromSourceNode",
	}
	antreaDestinationThroughputElementList = []string{
		"throughputFromDestinationNode",
		"reverseThroughputFromDestinationNode",
	}
	aggregationElements = &ipfixintermediate.AggregationElements{
		NonStatsElements:                   nonStatsElementList,
		StatsElements:                      statsElementList,
		AggregatedSourceStatsElements:      antreaSourceStatsElementList,
		AggregatedDestinationStatsElements: antreaDestinationStatsElementList,
		AntreaFlowEndSecondsElements:       antreaFlowEndSecondsElementList,
		ThroughputElements:                 antreaThroughputElementList,
		SourceThroughputElements:           antreaSourceThroughputElementList,
		DestinationThroughputElements:      antreaDestinationThroughputElementList,
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
		"ingressNetworkPolicyRuleAction",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyRuleAction",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
	}
)

const (
	aggregationWorkerNum = 2
	udpTransport         = "udp"
	tcpTransport         = "tcp"
	collectorAddress     = "0.0.0.0:4739"

	// PodInfo index name for Pod cache.
	podInfoIndex = "podInfo"
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
	activeFlowRecordTimeout     time.Duration
	inactiveFlowRecordTimeout   time.Duration
	exportingProcess            ipfix.IPFIXExportingProcess
	templateIDv4                uint16
	templateIDv6                uint16
	registry                    ipfix.IPFIXRegistry
	set                         ipfixentities.Set
	flowAggregatorAddress       string
	includePodLabels            bool
	k8sClient                   kubernetes.Interface
	observationDomainID         uint32
	podInformer                 coreinformers.PodInformer
	sendJSONRecord              bool
	numRecordsExported          int64
	numRecordsReceived          int64
}

func NewFlowAggregator(
	externalFlowCollectorAddr string,
	externalFlowCollectorProto string,
	activeFlowRecTimeout time.Duration,
	inactiveFlowRecTimeout time.Duration,
	aggregatorTransportProtocol AggregatorTransportProtocol,
	flowAggregatorAddress string,
	includePodLabels bool,
	k8sClient kubernetes.Interface,
	observationDomainID uint32,
	podInformer coreinformers.PodInformer,
	sendJSONRecord bool,
) *flowAggregator {
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()
	fa := &flowAggregator{
		externalFlowCollectorAddr:   externalFlowCollectorAddr,
		externalFlowCollectorProto:  externalFlowCollectorProto,
		aggregatorTransportProtocol: aggregatorTransportProtocol,
		activeFlowRecordTimeout:     activeFlowRecTimeout,
		inactiveFlowRecordTimeout:   inactiveFlowRecTimeout,
		registry:                    registry,
		set:                         ipfixentities.NewSet(false),
		flowAggregatorAddress:       flowAggregatorAddress,
		includePodLabels:            includePodLabels,
		k8sClient:                   k8sClient,
		observationDomainID:         observationDomainID,
		podInformer:                 podInformer,
		sendJSONRecord:              sendJSONRecord,
	}
	podInformer.Informer().AddIndexers(cache.Indexers{podInfoIndex: podInfoIndexFunc})
	return fa
}

func podInfoIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("obj is not pod: %+v", obj)
	}
	if len(pod.Status.PodIPs) > 0 && pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
		indexes := make([]string, len(pod.Status.PodIPs))
		for i := range pod.Status.PodIPs {
			indexes[i] = pod.Status.PodIPs[i].IP
		}
		return indexes, nil
	}
	return nil, nil
}

func (fa *flowAggregator) InitCollectingProcess() error {
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
	cpInput.NumExtraElements = len(antreaSourceStatsElementList) + len(antreaDestinationStatsElementList) + len(antreaLabelsElementList) +
		len(antreaFlowEndSecondsElementList) + len(antreaThroughputElementList) + len(antreaSourceThroughputElementList) + len(antreaDestinationThroughputElementList)
	var err error
	fa.collectingProcess, err = ipfix.NewIPFIXCollectingProcess(cpInput)
	return err
}

func (fa *flowAggregator) InitAggregationProcess() error {
	var err error
	apInput := ipfixintermediate.AggregationInput{
		MessageChan:           fa.collectingProcess.GetMsgChan(),
		WorkerNum:             aggregationWorkerNum,
		CorrelateFields:       correlateFields,
		ActiveExpiryTimeout:   fa.activeFlowRecordTimeout,
		InactiveExpiryTimeout: fa.inactiveFlowRecordTimeout,
		AggregateElements:     aggregationElements,
	}
	fa.aggregationProcess, err = ipfix.NewIPFIXAggregationProcess(apInput)
	return err
}

func (fa *flowAggregator) createAndSendTemplate(isRecordIPv6 bool) error {
	templateID := fa.exportingProcess.NewTemplateID()
	recordIPFamily := "IPv4"
	if isRecordIPv6 {
		recordIPFamily = "IPv6"
	}
	if isRecordIPv6 {
		fa.templateIDv6 = templateID
	} else {
		fa.templateIDv4 = templateID
	}
	bytesSent, err := fa.sendTemplateSet(isRecordIPv6)
	if err != nil {
		fa.exportingProcess.CloseConnToCollector()
		fa.exportingProcess = nil
		fa.set.ResetSet()
		return fmt.Errorf("sending %s template set failed, err: %v", recordIPFamily, err)
	}
	klog.V(2).InfoS("Exporting process initialized", "bytesSent", bytesSent, "templateSetIPFamily", recordIPFamily)
	return nil
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
			IsEncrypted:         false,
			SendJSONRecord:      fa.sendJSONRecord,
		}
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s. So we will send out template every 30 minutes.
		expInput = exporter.ExporterInput{
			CollectorAddress:    fa.externalFlowCollectorAddr,
			CollectorProtocol:   fa.externalFlowCollectorProto,
			ObservationDomainID: fa.observationDomainID,
			TempRefTimeout:      1800,
			IsEncrypted:         false,
			SendJSONRecord:      fa.sendJSONRecord,
		}
	}
	ep, err := ipfix.NewIPFIXExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("got error when initializing IPFIX exporting process: %v", err)
	}
	fa.exportingProcess = ep
	// Currently, we send two templates for IPv4 and IPv6 regardless of the IP families supported by cluster
	if err = fa.createAndSendTemplate(false); err != nil {
		return err
	}
	if err = fa.createAndSendTemplate(true); err != nil {
		return err
	}

	return nil
}

func (fa *flowAggregator) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	go fa.collectingProcess.Start()
	defer fa.collectingProcess.Stop()
	go fa.aggregationProcess.Start()
	defer fa.aggregationProcess.Stop()
	go fa.flowRecordExpiryCheck(stopCh)

	<-stopCh
}

func (fa *flowAggregator) flowRecordExpiryCheck(stopCh <-chan struct{}) {
	expireTimer := time.NewTimer(fa.activeFlowRecordTimeout)
	logTicker := time.NewTicker(time.Minute)
	for {
		select {
		case <-stopCh:
			if fa.exportingProcess != nil {
				fa.exportingProcess.CloseConnToCollector()
			}
			expireTimer.Stop()
			return
		case <-expireTimer.C:
			if fa.exportingProcess == nil {
				err := fa.initExportingProcess()
				if err != nil {
					klog.Errorf("Error when initializing exporting process: %v, will retry in %s", err, fa.activeFlowRecordTimeout)
					// Initializing exporting process fails, will retry in next cycle.
					expireTimer.Reset(fa.activeFlowRecordTimeout)
					continue
				}
			}
			// Pop the flow record item from expire priority queue in the Aggregation
			// Process and send the flow records.
			if err := fa.aggregationProcess.ForAllExpiredFlowRecordsDo(fa.sendFlowKeyRecord); err != nil {
				klog.Errorf("Error when sending expired flow records: %v", err)
				// If there is an error when sending flow records because of intermittent connectivity, we reset the connection
				// to IPFIX collector and retry in the next export cycle to reinitialize the connection and send flow records.
				fa.exportingProcess.CloseConnToCollector()
				fa.exportingProcess = nil
				expireTimer.Reset(fa.activeFlowRecordTimeout)
				continue
			}
			// Get the new expiry and reset the timer.
			expireTimer.Reset(fa.aggregationProcess.GetExpiryFromExpirePriorityQueue())
		case <-logTicker.C:
			// Add visibility of processing stats of Flow Aggregator
			klog.V(4).InfoS("Total number of records received", "count", fa.collectingProcess.GetNumRecordsReceived())
			klog.V(4).InfoS("Total number of records exported", "count", fa.numRecordsExported)
			klog.V(4).InfoS("Total number of flows stored in Flow Aggregator", "count", fa.aggregationProcess.GetNumFlows())
			klog.V(4).InfoS("Number of exporters connected with Flow Aggregator", "count", fa.collectingProcess.GetNumConnToCollector())
		}
	}
}

func (fa *flowAggregator) sendFlowKeyRecord(key ipfixintermediate.FlowKey, record *ipfixintermediate.AggregationFlowRecord) error {
	isRecordIPv4 := fa.aggregationProcess.IsAggregatedRecordIPv4(*record)
	templateID := fa.templateIDv4
	if !isRecordIPv4 {
		templateID = fa.templateIDv6
	}
	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	fa.set.ResetSet()
	if err := fa.set.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	if !fa.aggregationProcess.AreCorrelatedFieldsFilled(*record) {
		fa.fillK8sMetadata(key, record.Record)
		fa.aggregationProcess.SetCorrelatedFieldsFilled(record)
	}
	if fa.includePodLabels && !fa.aggregationProcess.AreExternalFieldsFilled(*record) {
		fa.fillPodLabels(key, record.Record)
		fa.aggregationProcess.SetExternalFieldsFilled(record)
	}
	if err := fa.set.AddRecord(record.Record.GetOrderedElementList(), templateID); err != nil {
		return err
	}

	sentBytes, err := fa.exportingProcess.SendSet(fa.set)
	if err != nil {
		return err
	}
	if err = fa.aggregationProcess.ResetStatElementsInRecord(record.Record); err != nil {
		return err
	}
	klog.V(4).Infof("Data set sent successfully: %d Bytes sent", sentBytes)
	fa.numRecordsExported = fa.numRecordsExported + 1
	return nil
}

func (fa *flowAggregator) sendTemplateSet(isIPv6 bool) (int, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)
	ianaInfoElements := ianaInfoElementsIPv4
	antreaInfoElements := antreaInfoElementsIPv4
	templateID := fa.templateIDv4
	if isIPv6 {
		ianaInfoElements = ianaInfoElementsIPv6
		antreaInfoElements = antreaInfoElementsIPv6
		templateID = fa.templateIDv6
	}
	for _, ie := range ianaInfoElements {
		ie, err := fa.createInfoElementForTemplateSet(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range ianaReverseInfoElements {
		ie, err := fa.createInfoElementForTemplateSet(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range antreaInfoElements {
		ie, err := fa.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	// The order of source and destination stats elements needs to match the order specified in
	// addFieldsForStatsAggregation method in go-ipfix aggregation process.
	for i := range statsElementList {
		// Add Antrea source stats fields
		ieName := antreaSourceStatsElementList[i]
		ie, err := fa.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add Antrea destination stats fields
		ieName = antreaDestinationStatsElementList[i]
		ie, err = fa.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range antreaFlowEndSecondsElementList {
		ie, err := fa.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for i := range antreaThroughputElementList {
		// Add common throughput fields
		ieName := antreaThroughputElementList[i]
		ie, err := fa.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add source node specific throughput fields
		ieName = antreaSourceThroughputElementList[i]
		ie, err = fa.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add destination node specific throughput fields
		ieName = antreaDestinationThroughputElementList[i]
		ie, err = fa.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	if fa.includePodLabels {
		for _, ie := range antreaLabelsElementList {
			ie, err := fa.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return 0, err
			}
			elements = append(elements, ie)
		}
	}
	fa.set.ResetSet()
	if err := fa.set.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := fa.set.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error when adding record to set, error: %v", err)
	}
	bytesSent, err := fa.exportingProcess.SendSet(fa.set)
	return bytesSent, err
}

// fillK8sMetadata fills Pod name, Pod namespace and Node name for inter-Node flows
// that have incomplete info due to deny network policy.
func (fa *flowAggregator) fillK8sMetadata(key ipfixintermediate.FlowKey, record ipfixentities.Record) {
	// fill source Pod info when sourcePodName is empty
	if sourcePodName, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		if sourcePodName.GetStringValue() == "" {
			pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, key.SourceAddress)
			if err == nil && len(pods) > 0 {
				pod, ok := pods[0].(*corev1.Pod)
				if !ok {
					klog.Warningf("Invalid Pod obj in cache")
				}
				sourcePodName.SetStringValue(pod.Name)
				if sourcePodNamespace, _, exist := record.GetInfoElementWithValue("sourcePodNamespace"); exist {
					sourcePodNamespace.SetStringValue(pod.Namespace)
				}
				if sourceNodeName, _, exist := record.GetInfoElementWithValue("sourceNodeName"); exist {
					sourceNodeName.SetStringValue(pod.Spec.NodeName)
				}
			} else {
				klog.Warning(err)
			}
		}
	}
	// fill destination Pod info when destinationPodName is empty
	if destinationPodName, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		if destinationPodName.GetStringValue() == "" {
			pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, key.DestinationAddress)
			if len(pods) > 0 && err == nil {
				pod, ok := pods[0].(*corev1.Pod)
				if !ok {
					klog.Warningf("Invalid Pod obj in cache")
				}
				destinationPodName.SetStringValue(pod.Name)
				if destinationPodNamespace, _, exist := record.GetInfoElementWithValue("destinationPodNamespace"); exist {
					destinationPodNamespace.SetStringValue(pod.Namespace)
				}
				if destinationNodeName, _, exist := record.GetInfoElementWithValue("destinationNodeName"); exist {
					destinationNodeName.SetStringValue(pod.Spec.NodeName)
				}
			} else {
				klog.Warning(err)
			}
		}
	}
}

func (fa *flowAggregator) fetchPodLabels(podAddress string) string {
	pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, podAddress)
	if err != nil {
		klog.Warning(err)
		return ""
	} else if len(pods) == 0 {
		klog.InfoS("No Pod objects found for Pod Address", "podAddress", podAddress)
		return ""
	}
	pod, ok := pods[0].(*corev1.Pod)
	if !ok {
		klog.Warningf("Invalid Pod obj in cache")
	}
	labelsJSON, err := json.Marshal(pod.GetLabels())
	if err != nil {
		klog.Warningf("JSON encoding of Pod labels failed: %v", err)
		return ""
	}
	return string(labelsJSON)
}

func (fa *flowAggregator) fillPodLabels(key ipfixintermediate.FlowKey, record ipfixentities.Record) {
	podLabelString := fa.fetchPodLabels(key.SourceAddress)
	sourcePodLabelsElement, err := fa.registry.GetInfoElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID)
	if err == nil {
		sourcePodLabelsIE, err := ipfixentities.DecodeAndCreateInfoElementWithValue(sourcePodLabelsElement, bytes.NewBufferString(podLabelString).Bytes())
		if err != nil {
			klog.Warningf("Create sourcePodLabels InfoElementWithValue failed: %v", err)
		}
		err = record.AddInfoElement(sourcePodLabelsIE)
		if err != nil {
			klog.Warningf("Add sourcePodLabels InfoElementWithValue failed: %v", err)
		}
	} else {
		klog.Warningf("Get sourcePodLabels InfoElement failed: %v", err)
	}
	podLabelString = fa.fetchPodLabels(key.DestinationAddress)
	destinationPodLabelsElement, err := fa.registry.GetInfoElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID)
	if err == nil {
		destinationPodLabelsIE, err := ipfixentities.DecodeAndCreateInfoElementWithValue(destinationPodLabelsElement, bytes.NewBufferString(podLabelString).Bytes())
		if err != nil {
			klog.Warningf("Create destinationPodLabelsIE InfoElementWithValue failed: %v", err)
		}
		err = record.AddInfoElement(destinationPodLabelsIE)
		if err != nil {
			klog.Warningf("Add destinationPodLabels InfoElementWithValue failed: %v", err)
		}
	} else {
		klog.Warningf("Get destinationPodLabels InfoElement failed: %v", err)
	}
}

func (fa *flowAggregator) GetFlowRecords(flowKey *ipfixintermediate.FlowKey) []map[string]interface{} {
	return fa.aggregationProcess.GetRecords(flowKey)
}

func (fa *flowAggregator) GetRecordMetrics() querier.Metrics {
	return querier.Metrics{
		NumRecordsExported: fa.numRecordsExported,
		NumRecordsReceived: fa.collectingProcess.GetNumRecordsReceived(),
		NumFlows:           fa.aggregationProcess.GetNumFlows(),
		NumConnToCollector: fa.collectingProcess.GetNumConnToCollector(),
	}
}

func (fa *flowAggregator) createInfoElementForTemplateSet(ieName string, enterpriseID uint32) (ipfixentities.InfoElementWithValue, error) {
	element, err := fa.registry.GetInfoElement(ieName, enterpriseID)
	if err != nil {
		return nil, fmt.Errorf("%s not present. returned error: %v", ieName, err)
	}
	ie, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	if err != nil {
		return nil, err
	}
	return ie, nil
}
