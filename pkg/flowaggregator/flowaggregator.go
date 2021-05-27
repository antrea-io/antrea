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
	corev1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

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
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyRuleAction",
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
		"ingressNetworkPolicyRuleAction",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
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
	k8sClient                   kubernetes.Interface
	observationDomainID         uint32
	podInformer                 coreinformers.PodInformer
}

func NewFlowAggregator(
	externalFlowCollectorAddr string,
	externalFlowCollectorProto string,
	activeFlowRecTimeout time.Duration,
	inactiveFlowRecTimeout time.Duration,
	aggregatorTransportProtocol AggregatorTransportProtocol,
	flowAggregatorAddress string,
	k8sClient kubernetes.Interface,
	observationDomainID uint32,
	podInformer coreinformers.PodInformer,
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
		k8sClient:                   k8sClient,
		observationDomainID:         observationDomainID,
		podInformer:                 podInformer,
	}
	podInformer.Informer().AddIndexers(cache.Indexers{podInfoIndex: podInfoIndexFunc})
	return fa
}

func podInfoIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("obj is not pod: %+v", obj)
	}
	if pod.Status.PodIP == "" {
		klog.V(4).Infof("Pod %s/%s has not been assigned IP yet. ", pod.Namespace, pod.Name)
	}
	return []string{pod.Status.PodIP}, nil
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
	go fa.collectingProcess.Start()
	defer fa.collectingProcess.Stop()
	go fa.aggregationProcess.Start()
	defer fa.aggregationProcess.Stop()
	go fa.flowRecordExpiryCheck(stopCh)

	<-stopCh
}

func (fa *flowAggregator) flowRecordExpiryCheck(stopCh <-chan struct{}) {
	expireTimer := time.NewTimer(fa.activeFlowRecordTimeout)

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
		}
	}
}

func (fa *flowAggregator) sendFlowKeyRecord(key ipfixintermediate.FlowKey, record ipfixintermediate.AggregationFlowRecord) error {
	templateID := fa.templateIDv4
	if net.ParseIP(key.SourceAddress).To4() == nil || net.ParseIP(key.DestinationAddress).To4() == nil {
		templateID = fa.templateIDv6
	}
	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	fa.set.ResetSet()
	if err := fa.set.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	if !fa.aggregationProcess.IsMetadataFilled(record) {
		fa.fillK8sMetadata(key, record.Record)
		fa.aggregationProcess.SetMetadataFilled(record)
	}
	err := fa.set.AddRecord(record.Record.GetOrderedElementList(), templateID)
	if err != nil {
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
	return nil
}

func (fa *flowAggregator) sendTemplateSet(templateSet ipfixentities.Set, isIPv6 bool) (int, error) {
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

// fillK8sMetadata fills Pod name, Pod namespace and Node name for inter-Node flows
// that have incomplete info due to deny network policy.
func (fa *flowAggregator) fillK8sMetadata(key ipfixintermediate.FlowKey, record ipfixentities.Record) {
	if fa.podInformer == nil {
		klog.Warning("No pod podInformer is provided for filling k8s metadata.")
		return
	}
	// fill source Pod info when sourcePodName is empty
	if sourcePodName, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		if sourcePodName.Value == "" {
			pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, key.SourceAddress)
			if err == nil && len(pods) > 0 {
				pod, ok := pods[0].(*corev1.Pod)
				if !ok {
					klog.Warningf("Invalid Pod obj in cache")
				}
				sourcePodName.Value = pod.Name
				if sourcePodNamespace, exist := record.GetInfoElementWithValue("sourcePodNamespace"); exist {
					sourcePodNamespace.Value = pod.Namespace
				}
				if sourceNodeName, exist := record.GetInfoElementWithValue("sourceNodeName"); exist {
					sourceNodeName.Value = pod.Spec.NodeName
				}
			} else {
				klog.Warning(err)
			}
		}
	}
	// fill destination Pod info when destinationPodName is empty
	if destinationPodName, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		if destinationPodName.Value == "" {
			pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, key.DestinationAddress)
			if len(pods) > 0 && err == nil {
				pod, ok := pods[0].(*corev1.Pod)
				if !ok {
					klog.Warningf("Invalid Pod obj in cache")
				}
				destinationPodName.Value = pod.Name
				if destinationPodNamespace, exist := record.GetInfoElementWithValue("destinationPodNamespace"); exist {
					destinationPodNamespace.Value = pod.Namespace
				}
				if destinationNodeName, exist := record.GetInfoElementWithValue("destinationNodeName"); exist {
					destinationNodeName.Value = pod.Spec.NodeName
				}
			} else {
				klog.Warning(err)
			}
		}
	}
}
