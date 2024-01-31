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
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ipfix"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/env"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/util/podstore"
)

// When initializing flowExporter, a slice is allocated with a fixed size to
// store expired connections. The advantage is every time we export, the connection
// store lock will only be held for a bounded time. The disadvantages are: 1. the
// constant is independent of actual number of expired connections 2. when the
// number of expired connections goes over the constant, the export can not be
// finished in a single round. It could be delayed by conntrack connections polling
// routine, which also acquires the connection store lock. The possible solution
// can be taking a fraction of the size of connection store to approximate the
// number of expired connections, while having a min and a max to handle edge cases,
// e.g. min(50 + 0.1 * connectionStore.size(), 200)
const maxConnsToExport = 64

var (
	IANAInfoElementsCommon = []string{
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
	IANAInfoElementsIPv4 = append(IANAInfoElementsCommon, []string{"sourceIPv4Address", "destinationIPv4Address"}...)
	IANAInfoElementsIPv6 = append(IANAInfoElementsCommon, []string{"sourceIPv6Address", "destinationIPv6Address"}...)
	// IANAReverseInfoElements contain substring "reverse" which is an indication to get reverse element of go-ipfix library.
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
		"egressName",
		"egressIP",
		"appProtocolName",
		"httpVals",
	}
	AntreaInfoElementsIPv4 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv4"}...)
	AntreaInfoElementsIPv6 = append(antreaInfoElementsCommon, []string{"destinationClusterIPv6"}...)
)

type FlowExporter struct {
	collectorAddr          string
	conntrackConnStore     *connections.ConntrackConnectionStore
	denyConnStore          *connections.DenyConnectionStore
	process                ipfix.IPFIXExportingProcess
	elementsListv4         []ipfixentities.InfoElementWithValue
	elementsListv6         []ipfixentities.InfoElementWithValue
	ipfixSet               ipfixentities.Set
	numDataSetsSent        uint64 // used for unit tests.
	templateIDv4           uint16
	templateIDv6           uint16
	registry               ipfix.IPFIXRegistry
	v4Enabled              bool
	v6Enabled              bool
	exporterInput          exporter.ExporterInput
	k8sClient              kubernetes.Interface
	nodeRouteController    *noderoute.Controller
	isNetworkPolicyOnly    bool
	nodeName               string
	conntrackPriorityQueue *priorityqueue.ExpirePriorityQueue
	denyPriorityQueue      *priorityqueue.ExpirePriorityQueue
	expiredConns           []flowexporter.Connection
	egressQuerier          querier.EgressQuerier
	podStore               podstore.Interface
	l7Listener             *connections.L7Listener
}

func genObservationID(nodeName string) uint32 {
	h := fnv.New32()
	h.Write([]byte(nodeName))
	return h.Sum32()
}

func prepareExporterInputArgs(collectorProto, nodeName string) exporter.ExporterInput {
	expInput := exporter.ExporterInput{}
	// Exporting process requires domain observation ID.
	expInput.ObservationDomainID = genObservationID(nodeName)

	if collectorProto == "tls" {
		expInput.TLSClientConfig = &exporter.ExporterTLSClientConfig{}
		expInput.CollectorProtocol = "tcp"
	} else {
		expInput.TLSClientConfig = nil
		expInput.CollectorProtocol = collectorProto
	}

	return expInput
}

func NewFlowExporter(podStore podstore.Interface, proxier proxy.Proxier, k8sClient kubernetes.Interface, nodeRouteController *noderoute.Controller,
	trafficEncapMode config.TrafficEncapModeType, nodeConfig *config.NodeConfig, v4Enabled, v6Enabled bool, serviceCIDRNet, serviceCIDRNetv6 *net.IPNet,
	ovsDatapathType ovsconfig.OVSDatapathType, proxyEnabled bool, npQuerier querier.AgentNetworkPolicyInfoQuerier, o *flowexporter.FlowExporterOptions,
	egressQuerier querier.EgressQuerier, podL7FlowExporterAttrGetter connections.PodL7FlowExporterAttrGetter, l7FlowExporterEnabled bool) (*FlowExporter, error) {
	// Initialize IPFIX registry
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()

	// Prepare input args for IPFIX exporting process.
	nodeName, err := env.GetNodeName()
	if err != nil {
		return nil, err
	}
	expInput := prepareExporterInputArgs(o.FlowCollectorProto, nodeName)

	connTrackDumper := connections.InitializeConnTrackDumper(nodeConfig, serviceCIDRNet, serviceCIDRNetv6, ovsDatapathType, proxyEnabled)
	denyConnStore := connections.NewDenyConnectionStore(podStore, proxier, o)
	var l7Listener *connections.L7Listener
	var eventMapGetter connections.L7EventMapGetter
	if l7FlowExporterEnabled {
		l7Listener = connections.NewL7Listener(podL7FlowExporterAttrGetter, podStore)
		eventMapGetter = l7Listener
	}
	conntrackConnStore := connections.NewConntrackConnectionStore(connTrackDumper, v4Enabled, v6Enabled, npQuerier, podStore, proxier, eventMapGetter, o)
	if nodeRouteController == nil {
		klog.InfoS("NodeRouteController is nil, will not be able to determine flow type for connections")
	}

	return &FlowExporter{
		collectorAddr:          o.FlowCollectorAddr,
		conntrackConnStore:     conntrackConnStore,
		denyConnStore:          denyConnStore,
		registry:               registry,
		v4Enabled:              v4Enabled,
		v6Enabled:              v6Enabled,
		exporterInput:          expInput,
		ipfixSet:               ipfixentities.NewSet(false),
		k8sClient:              k8sClient,
		nodeRouteController:    nodeRouteController,
		isNetworkPolicyOnly:    trafficEncapMode.IsNetworkPolicyOnly(),
		nodeName:               nodeName,
		conntrackPriorityQueue: conntrackConnStore.GetPriorityQueue(),
		denyPriorityQueue:      denyConnStore.GetPriorityQueue(),
		expiredConns:           make([]flowexporter.Connection, 0, maxConnsToExport*2),
		egressQuerier:          egressQuerier,
		podStore:               podStore,
		l7Listener:             l7Listener,
	}, nil
}

func (exp *FlowExporter) GetDenyConnStore() *connections.DenyConnectionStore {
	return exp.denyConnStore
}

func (exp *FlowExporter) Run(stopCh <-chan struct{}) {
	go exp.podStore.Run(stopCh)
	// Start L7 connection flow socket
	if features.DefaultFeatureGate.Enabled(features.L7FlowExporter) {
		go exp.l7Listener.Run(stopCh)
	}
	// Start the goroutine to periodically delete stale deny connections.
	go exp.denyConnStore.RunPeriodicDeletion(stopCh)

	// Start the goroutine to poll conntrack flows.
	go exp.conntrackConnStore.Run(stopCh)

	defaultTimeout := exp.conntrackPriorityQueue.ActiveFlowTimeout
	expireTimer := time.NewTimer(defaultTimeout)
	for {
		select {
		case <-stopCh:
			if exp.process != nil {
				exp.process.CloseConnToCollector()
			}
			expireTimer.Stop()
			return
		case <-expireTimer.C:
			if exp.process == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := exp.initFlowExporter(ctx)
				cancel()
				if err != nil {
					klog.ErrorS(err, "Error when initializing flow exporter")
					// There could be other errors while initializing flow exporter
					// other than connecting to IPFIX collector, therefore closing
					// the connection and resetting the process.
					if exp.process != nil {
						exp.process.CloseConnToCollector()
						exp.process = nil
					}
					// Initializing flow exporter fails, will retry in next cycle.
					expireTimer.Reset(defaultTimeout)
					continue
				}
			}
			// Pop out the expired connections from the conntrack priority queue
			// and the deny priority queue, and send the data records.
			nextExpireTime, err := exp.sendFlowRecords()
			if err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				// If there is an error when sending flow records because of intermittent
				// connectivity, we reset the connection to IPFIX collector and retry
				// in the next export cycle to reinitialize the connection and send flow records.
				exp.process.CloseConnToCollector()
				exp.process = nil
				expireTimer.Reset(defaultTimeout)
				continue
			}
			expireTimer.Reset(nextExpireTime)
		}
	}
}

func (exp *FlowExporter) sendFlowRecords() (time.Duration, error) {
	currTime := time.Now()
	var expireTime1, expireTime2 time.Duration
	// We export records from denyConnStore first, then conntrackConnStore. We enforce the ordering to handle a
	// special case: for an inter-node connection with egress drop network policy, both conntrackConnStore and
	// denyConnStore from the same Node will send out records to Flow Aggregator. If the record from conntrackConnStore
	// arrives FA first, FA will not be able to capture the deny network policy metadata, and it will keep waiting
	// for a record from destination Node to finish flow correlation until timeout. Later on we probably should
	// consider doing a record deduplication between conntrackConnStore and denyConnStore before exporting records.
	exp.expiredConns, expireTime2 = exp.denyConnStore.GetExpiredConns(exp.expiredConns, currTime, maxConnsToExport)
	exp.expiredConns, expireTime1 = exp.conntrackConnStore.GetExpiredConns(exp.expiredConns, currTime, maxConnsToExport)
	// Select the shorter time out among two connection stores to do the next round of export.
	nextExpireTime := getMinTime(expireTime1, expireTime2)
	for i := range exp.expiredConns {
		if err := exp.exportConn(&exp.expiredConns[i]); err != nil {
			klog.ErrorS(err, "Error when sending expired flow record")
			return nextExpireTime, err
		}
	}
	// Clear expiredConns slice after exporting. Allocated memory is kept.
	exp.expiredConns = exp.expiredConns[:0]
	return nextExpireTime, nil
}

func (exp *FlowExporter) resolveCollectorAddress(ctx context.Context) error {
	exp.exporterInput.CollectorAddress = ""
	host, port, err := net.SplitHostPort(exp.collectorAddr)
	if err != nil {
		return err
	}
	ns, name := k8sutil.SplitNamespacedName(host)
	if ns == "" {
		exp.exporterInput.CollectorAddress = exp.collectorAddr
		return nil
	}
	svc, err := exp.k8sClient.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to resolve FlowAggregator Service: %s/%s", ns, name)
	}
	if svc.Spec.ClusterIP == "" {
		return fmt.Errorf("ClusterIP is not available for FlowAggregator Service: %s/%s", ns, name)
	}
	exp.exporterInput.CollectorAddress = net.JoinHostPort(svc.Spec.ClusterIP, port)
	if exp.exporterInput.TLSClientConfig != nil {
		exp.exporterInput.TLSClientConfig.ServerName = fmt.Sprintf("%s.%s.svc", name, ns)
	}
	klog.V(2).InfoS("Resolved FlowAggregator Service address", "address", exp.exporterInput.CollectorAddress)
	return nil
}

func (exp *FlowExporter) initFlowExporter(ctx context.Context) error {
	if err := exp.resolveCollectorAddress(ctx); err != nil {
		return err
	}
	var err error
	if exp.exporterInput.TLSClientConfig != nil {
		tlsConfig := exp.exporterInput.TLSClientConfig
		// if CA certificate, client certificate and key do not exist during initialization,
		// it will retry to obtain the credentials in next export cycle
		tlsConfig.CAData, err = getCACert(ctx, exp.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve CA cert: %v", err)
		}
		tlsConfig.CertData, tlsConfig.KeyData, err = getClientCertKey(ctx, exp.k8sClient)
		if err != nil {
			return fmt.Errorf("cannot retrieve client cert and key: %v", err)
		}
		// TLS transport does not need any tempRefTimeout, so sending 0.
		exp.exporterInput.TempRefTimeout = 0
	} else if exp.exporterInput.CollectorProtocol == "tcp" {
		// TCP transport does not need any tempRefTimeout, so sending 0.
		// tempRefTimeout is the template refresh timeout, which specifies how often
		// the exporting process should send the template again.
		exp.exporterInput.TempRefTimeout = 0
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s.
		exp.exporterInput.TempRefTimeout = 1800
	}
	expProcess, err := exporter.InitExportingProcess(exp.exporterInput)
	if err != nil {
		return fmt.Errorf("error when starting exporter: %v", err)
	}
	exp.process = expProcess
	if exp.v4Enabled {
		templateID := exp.process.NewTemplateID()
		exp.templateIDv4 = templateID
		sentBytes, err := exp.sendTemplateSet(false)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Initialized flow exporter for IPv4 flow records and sent %d bytes size of template record", sentBytes)
	}
	if exp.v6Enabled {
		templateID := exp.process.NewTemplateID()
		exp.templateIDv6 = templateID
		sentBytes, err := exp.sendTemplateSet(true)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Initialized flow exporter for IPv6 flow records and sent %d bytes size of template record", sentBytes)
	}
	metrics.ReconnectionsToFlowCollector.Inc()
	return nil
}

func (exp *FlowExporter) sendTemplateSet(isIPv6 bool) (int, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)

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
		ieWithValue, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
		if err != nil {
			return 0, fmt.Errorf("error when creating information element: %v", err)
		}
		elements = append(elements, ieWithValue)
	}
	for _, ie := range IANAReverseInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
		if err != nil {
			return 0, fmt.Errorf("error when creating information element: %v", err)
		}
		elements = append(elements, ieWithValue)
	}
	for _, ie := range AntreaInfoElements {
		element, err := exp.registry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, fmt.Errorf("information element %s is not present in Antrea registry", ie)
		}
		ieWithValue, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
		if err != nil {
			return 0, fmt.Errorf("error when creating information element: %v", err)
		}
		elements = append(elements, ieWithValue)
	}
	exp.ipfixSet.ResetSet()
	if err := exp.ipfixSet.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := exp.ipfixSet.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error in adding record to template set: %v", err)
	}
	sentBytes, err := exp.process.SendSet(exp.ipfixSet)
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

func (exp *FlowExporter) addConnToSet(conn *flowexporter.Connection) error {
	exp.ipfixSet.ResetSet()

	eL := exp.elementsListv4
	templateID := exp.templateIDv4
	if conn.FlowKey.SourceAddress.Is6() {
		templateID = exp.templateIDv6
		eL = exp.elementsListv6
	}
	if err := exp.ipfixSet.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	// Iterate over all infoElements in the list
	for i := range eL {
		ie := eL[i]
		switch ieName := ie.GetInfoElement().Name; ieName {
		case "flowStartSeconds":
			ie.SetUnsigned32Value(uint32(conn.StartTime.Unix()))
		case "flowEndSeconds":
			ie.SetUnsigned32Value(uint32(conn.StopTime.Unix()))
		case "flowEndReason":
			if flowexporter.IsConnectionDying(conn) {
				ie.SetUnsigned8Value(ipfixregistry.EndOfFlowReason)
			} else if conn.IsActive {
				ie.SetUnsigned8Value(ipfixregistry.ActiveTimeoutReason)
			} else {
				ie.SetUnsigned8Value(ipfixregistry.IdleTimeoutReason)
			}
		case "sourceIPv4Address":
			ie.SetIPAddressValue(conn.FlowKey.SourceAddress.AsSlice())
		case "destinationIPv4Address":
			ie.SetIPAddressValue(conn.FlowKey.DestinationAddress.AsSlice())
		case "sourceIPv6Address":
			ie.SetIPAddressValue(conn.FlowKey.SourceAddress.AsSlice())
		case "destinationIPv6Address":
			ie.SetIPAddressValue(conn.FlowKey.DestinationAddress.AsSlice())
		case "sourceTransportPort":
			ie.SetUnsigned16Value(conn.FlowKey.SourcePort)
		case "destinationTransportPort":
			ie.SetUnsigned16Value(conn.FlowKey.DestinationPort)
		case "protocolIdentifier":
			ie.SetUnsigned8Value(conn.FlowKey.Protocol)
		case "packetTotalCount":
			ie.SetUnsigned64Value(conn.OriginalPackets)
		case "octetTotalCount":
			ie.SetUnsigned64Value(conn.OriginalBytes)
		case "packetDeltaCount":
			deltaPkts := int64(conn.OriginalPackets) - int64(conn.PrevPackets)
			if deltaPkts < 0 {
				klog.InfoS("Packet delta count for connection should not be negative", "packet delta count", deltaPkts)
			}
			ie.SetUnsigned64Value(uint64(deltaPkts))
		case "octetDeltaCount":
			deltaBytes := int64(conn.OriginalBytes) - int64(conn.PrevBytes)
			if deltaBytes < 0 {
				klog.InfoS("Byte delta count for connection should not be negative", "byte delta count", deltaBytes)
			}
			ie.SetUnsigned64Value(uint64(deltaBytes))
		case "reversePacketTotalCount":
			ie.SetUnsigned64Value(conn.ReversePackets)
		case "reverseOctetTotalCount":
			ie.SetUnsigned64Value(conn.ReverseBytes)
		case "reversePacketDeltaCount":
			deltaPkts := int64(conn.ReversePackets) - int64(conn.PrevReversePackets)
			if deltaPkts < 0 {
				klog.InfoS("Packet delta count for connection should not be negative", "packet delta count", deltaPkts)
			}
			ie.SetUnsigned64Value(uint64(deltaPkts))
		case "reverseOctetDeltaCount":
			deltaBytes := int64(conn.ReverseBytes) - int64(conn.PrevReverseBytes)
			if deltaBytes < 0 {
				klog.InfoS("Byte delta count for connection should not be negative", "byte delta count", deltaBytes)
			}
			ie.SetUnsigned64Value(uint64(deltaBytes))
		case "sourcePodNamespace":
			ie.SetStringValue(conn.SourcePodNamespace)
		case "sourcePodName":
			ie.SetStringValue(conn.SourcePodName)
		case "sourceNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if conn.SourcePodName != "" {
				ie.SetStringValue(exp.nodeName)
			} else {
				ie.SetStringValue("")
			}
		case "destinationPodNamespace":
			ie.SetStringValue(conn.DestinationPodNamespace)
		case "destinationPodName":
			ie.SetStringValue(conn.DestinationPodName)
		case "destinationNodeName":
			// Add nodeName for only local pods whose pod names are resolved.
			if conn.DestinationPodName != "" {
				ie.SetStringValue(exp.nodeName)
			} else {
				ie.SetStringValue("")
			}
		case "destinationClusterIPv4":
			if conn.DestinationServicePortName != "" {
				ie.SetIPAddressValue(conn.OriginalDestinationAddress.AsSlice())
			} else {
				// Sending dummy IP as IPFIX collector expects constant length of data for IP field.
				// We should probably think of better approach as this involves customization of IPFIX collector to ignore
				// this dummy IP address.
				ie.SetIPAddressValue(net.IP{0, 0, 0, 0})
			}
		case "destinationClusterIPv6":
			if conn.DestinationServicePortName != "" {
				ie.SetIPAddressValue(conn.OriginalDestinationAddress.AsSlice())
			} else {
				// Same as destinationClusterIPv4.
				ie.SetIPAddressValue(net.ParseIP("::"))
			}
		case "destinationServicePort":
			if conn.DestinationServicePortName != "" {
				ie.SetUnsigned16Value(conn.OriginalDestinationPort)
			} else {
				ie.SetUnsigned16Value(uint16(0))
			}
		case "destinationServicePortName":
			ie.SetStringValue(conn.DestinationServicePortName)
		case "ingressNetworkPolicyName":
			ie.SetStringValue(conn.IngressNetworkPolicyName)
		case "ingressNetworkPolicyNamespace":
			ie.SetStringValue(conn.IngressNetworkPolicyNamespace)
		case "ingressNetworkPolicyType":
			ie.SetUnsigned8Value(conn.IngressNetworkPolicyType)
		case "ingressNetworkPolicyRuleName":
			ie.SetStringValue(conn.IngressNetworkPolicyRuleName)
		case "ingressNetworkPolicyRuleAction":
			ie.SetUnsigned8Value(conn.IngressNetworkPolicyRuleAction)
		case "egressNetworkPolicyName":
			ie.SetStringValue(conn.EgressNetworkPolicyName)
		case "egressNetworkPolicyNamespace":
			ie.SetStringValue(conn.EgressNetworkPolicyNamespace)
		case "egressNetworkPolicyType":
			ie.SetUnsigned8Value(conn.EgressNetworkPolicyType)
		case "egressNetworkPolicyRuleName":
			ie.SetStringValue(conn.EgressNetworkPolicyRuleName)
		case "egressNetworkPolicyRuleAction":
			ie.SetUnsigned8Value(conn.EgressNetworkPolicyRuleAction)
		case "tcpState":
			ie.SetStringValue(conn.TCPState)
		case "flowType":
			ie.SetUnsigned8Value(conn.FlowType)
		case "egressName":
			ie.SetStringValue(conn.EgressName)
		case "egressIP":
			ie.SetStringValue(conn.EgressIP)
		case "appProtocolName":
			ie.SetStringValue(conn.AppProtocolName)
		case "httpVals":
			ie.SetStringValue(conn.HttpVals)
		}
	}
	err := exp.ipfixSet.AddRecord(eL, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}
	return nil
}

func (exp *FlowExporter) sendDataSet() (int, error) {
	sentBytes, err := exp.process.SendSet(exp.ipfixSet)
	if err != nil {
		return 0, fmt.Errorf("error when sending data set: %v", err)
	}
	klog.V(4).InfoS("Data set sent successfully", "Bytes sent", sentBytes)
	return sentBytes, nil
}

func (exp *FlowExporter) findFlowType(conn flowexporter.Connection) uint8 {
	// TODO: support Pod-To-External flows in network policy only mode.
	if exp.isNetworkPolicyOnly {
		if conn.SourcePodName == "" || conn.DestinationPodName == "" {
			return ipfixregistry.FlowTypeInterNode
		}
		return ipfixregistry.FlowTypeIntraNode
	}

	if exp.nodeRouteController == nil {
		klog.V(4).InfoS("Can't find flowType without nodeRouteController")
		return 0
	}
	if exp.nodeRouteController.IPInPodSubnets(conn.FlowKey.SourceAddress.AsSlice()) {
		if conn.Mark&openflow.ServiceCTMark.GetRange().ToNXRange().ToUint32Mask() == openflow.ServiceCTMark.GetValue() || exp.nodeRouteController.IPInPodSubnets(conn.FlowKey.DestinationAddress.AsSlice()) {
			if conn.SourcePodName == "" || conn.DestinationPodName == "" {
				return ipfixregistry.FlowTypeInterNode
			}
			return ipfixregistry.FlowTypeIntraNode
		}
		return ipfixregistry.FlowTypeToExternal
	}
	// We do not support External-To-Pod flows for now.
	klog.Warningf("Source IP: %s doesn't exist in PodCIDRs", conn.FlowKey.SourceAddress.String())
	return 0
}

func (exp *FlowExporter) fillEgressInfo(conn *flowexporter.Connection) {
	egressName, egressIP, _, err := exp.egressQuerier.GetEgress(conn.SourcePodNamespace, conn.SourcePodName)
	if err != nil {
		// Egress is not enabled or no Egress is applied to this Pod
		return
	}
	conn.EgressName = egressName
	conn.EgressIP = egressIP
	klog.V(4).InfoS("Filling Egress Info for flow", "Egress", conn.EgressName, "EgressIP", conn.EgressIP, "SourcePodNamespace", conn.SourcePodNamespace, "SourcePodName", conn.SourcePodName)
}

func (exp *FlowExporter) exportConn(conn *flowexporter.Connection) error {
	conn.FlowType = exp.findFlowType(*conn)
	if conn.FlowType == ipfixregistry.FlowTypeToExternal {
		if conn.SourcePodNamespace != "" && conn.SourcePodName != "" {
			exp.fillEgressInfo(conn)
		} else {
			// Skip exporting the Pod-to-External connection at the Egress Node if it's different from the Source Node
			return nil
		}
	}
	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	if err := exp.addConnToSet(conn); err != nil {
		return err
	}
	if _, err := exp.sendDataSet(); err != nil {
		return err
	}
	exp.numDataSetsSent = exp.numDataSetsSent + 1
	klog.V(4).InfoS("Record for connection sent successfully", "flowKey", conn.FlowKey, "connection", conn)
	return nil
}

func getMinTime(t1, t2 time.Duration) time.Duration {
	if t1 <= t2 {
		return t1
	}
	return t2
}
