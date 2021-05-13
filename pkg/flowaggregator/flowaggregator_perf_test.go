// +build !race

// Copyright 2021 Antrea Authors
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
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ipfixcollector "github.com/vmware/go-ipfix/pkg/collector"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixexporter "github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clienttest "k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
)

var (
	numMessages  = 0
	numExporters = 100
	testDuration = 2 * time.Minute
)

/*
Test result from latest run on ToT main.
pkg/flowaggregator$ go test -test.v -run=none -test.benchmem  -bench=. -count=2 -memprofile memprofile.out -cpuprofile profile.out
goos: linux
goarch: amd64
pkg: antrea.io/antrea/pkg/flowaggregator
cpu: Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz
BenchmarkIntraNodeFlowRecords
    flowaggregator_perf_test.go:458: Num messages received: 1550264
BenchmarkIntraNodeFlowRecords-2   	       1	120004095225 ns/op	8876354472 B/op	332625061 allocs/op
PASS
*/
func BenchmarkIntraNodeFlowRecords(b *testing.B) {
	disableLogToStderr()

	ipfixregistry.LoadRegistry()
	testActiveTimeout = time.Second
	testInactiveTimeout = 1250 * time.Millisecond
	for i := 0; i < b.N; i++ {
		numMessages = 0
		stopCh := make(chan struct{})
		go testHandler(b, stopCh)
		localCollector := startLocalCollector(b, stopCh)
		k8sClient := clienttest.NewSimpleClientset()
		informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
		podInformer := informerFactory.Core().V1().Pods()
		flowAgg := NewFlowAggregator(
			localCollector.String(),
			localCollector.Network(),
			testActiveTimeout,
			testInactiveTimeout,
			AggregatorTransportProtocolTCP,
			"127.0.0.1:0:tcp",
			k8sClient,
			testObservationDomainID,
			podInformer,
			false)
		err := flowAgg.InitCollectingProcess()
		if err != nil {
			b.Fatalf("Error when creating collecting process in Flow Aggregator: %v", err)
		}
		err = flowAgg.InitAggregationProcess()
		if err != nil {
			b.Fatalf("Error when creating aggregation process in Flow Aggregator: %v", err)
		}

		go flowAgg.Run(stopCh)

		waitForCollectorReady(b, flowAgg.collectingProcess.GetCollectingProcess())

		// Start multiple exporters that simulate Antrea Agent Flow Exporters.
		for j := 0; j < numExporters; j++ {
			nodeName := "exporter-" + strconv.Itoa(j+1)
			go startExporter(b, flowAgg.collectingProcess.GetCollectingProcess(), stopCh, nodeName, uint32(j))
		}
		<-stopCh
	}
}

func startExporter(b *testing.B, cp *ipfixcollector.CollectingProcess, stopCh chan struct{}, nodeName string, nodeID uint32) {
	epInput := ipfixexporter.ExporterInput{
		CollectorAddress:    cp.GetAddress().String(),
		CollectorProtocol:   cp.GetAddress().Network(),
		ObservationDomainID: nodeID,
		TempRefTimeout:      0,
		PathMTU:             0,
		IsEncrypted:         false,
		CACert:              nil,
	}

	exportingProcess, err := ipfixexporter.InitExportingProcess(epInput)
	if err != nil {
		b.Errorf("Got error when connecting to %s", cp.GetAddress().String())
		return
	}
	defer exportingProcess.CloseConnToCollector() // Close exporting process
	set := ipfixentities.NewSet(false)
	if err = set.PrepareSet(ipfixentities.Template, testTemplateIDv4); err != nil {
		b.Errorf("Error when preparing the set: %v", err)
		return
	}
	// Send template set.
	elements, err := sendTemplateSet(exportingProcess, set, false)
	if err != nil {
		b.Errorf("Error when sending template set: %v", err)
		return
	}
	set.ResetSet()

	// Send multiple records
	i := 0
	for {
		select {
		case <-stopCh:
			return
		default:
			if i%50 == 0 {
				// Pausing after 100 records to simulate the behavior of Flow Exporter.
				time.Sleep(750 * time.Millisecond)
				i = 0
			}
			if err = set.PrepareSet(ipfixentities.Data, testTemplateIDv4); err != nil {
				b.Errorf("Error when preparing the set: %v", err)
				return
			}
			err = sendDataSet(exportingProcess, set, elements, nodeName)
			if err != nil {
				b.Errorf("Error when sending data set: %v", err)
				return
			}
			set.ResetSet()
			i++
		}
	}
}

func startLocalCollector(b *testing.B, stopCh chan struct{}) net.Addr {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		b.Error(err)
	}
	listener, err := net.ListenUDP("udp", address)
	if err != nil {
		b.Fatalf("Got error when creating a local udp server: %v", err)
	}
	go func() {
		defer listener.Close()
		for {
			select {
			case <-stopCh:
				return
			default:
				buff := make([]byte, 400)
				size, _, err := listener.ReadFrom(buff[0:])
				if err != nil {
					if size == 0 { // received stop collector message
						return
					}
					b.Errorf("Error in udp collecting process: %v", err)
					return
				}
				numMessages = numMessages + 1
			}
		}
	}()

	return listener.LocalAddr()
}

func sendTemplateSet(exportProcess *ipfixexporter.ExportingProcess, templateSet ipfixentities.Set, isIPv6 bool) ([]ipfixentities.InfoElementWithValue, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)

	IANAInfoElements := exporter.IANAInfoElementsIPv4
	AntreaInfoElements := exporter.AntreaInfoElementsIPv4
	templateID := testTemplateIDv4
	for _, ie := range IANAInfoElements {
		element, err := ipfixregistry.GetInfoElement(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return nil, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ieWithValue)
	}
	for _, ie := range exporter.IANAReverseInfoElements {
		element, err := ipfixregistry.GetInfoElement(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return nil, fmt.Errorf("%s not present. returned error: %v", ie, err)
		}
		ieWithValue := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ieWithValue)
	}
	for _, ie := range AntreaInfoElements {
		element, err := ipfixregistry.GetInfoElement(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return nil, fmt.Errorf("information element %s is not present in Antrea registry", ie)
		}
		ieWithValue := ipfixentities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ieWithValue)
	}

	err := templateSet.AddRecord(elements, templateID)
	if err != nil {
		return nil, fmt.Errorf("error in adding record to template set: %v", err)
	}

	_, err = exportProcess.SendSet(templateSet)
	if err != nil {
		return nil, fmt.Errorf("error in IPFIX exporting process when sending template record: %v", err)
	}

	return elements, nil
}

func sendDataSet(exportProcess *ipfixexporter.ExportingProcess, dataSet ipfixentities.Set, elements []ipfixentities.InfoElementWithValue, nodeName string) error {
	record := getFlowRecord()
	// Iterate over all infoElements in the list
	for i := range elements {
		ie := &elements[i]
		switch ieName := ie.Element.Name; ieName {
		case "flowStartSeconds":
			ie.Value = uint32(record.Conn.StartTime.Unix())
		case "flowEndSeconds":
			ie.Value = uint32(record.Conn.StopTime.Unix())
		case "flowEndReason":
			if flowexporter.IsConnectionDying(&record.Conn) {
				ie.Value = ipfixregistry.EndOfFlowReason
			} else if record.IsActive {
				ie.Value = ipfixregistry.ActiveTimeoutReason
			} else {
				ie.Value = ipfixregistry.IdleTimeoutReason
			}
		case "sourceIPv4Address":
			ie.Value = record.Conn.FlowKey.SourceAddress
		case "destinationIPv4Address":
			ie.Value = record.Conn.FlowKey.DestinationAddress
		case "sourceIPv6Address":
			ie.Value = record.Conn.FlowKey.SourceAddress
		case "destinationIPv6Address":
			ie.Value = record.Conn.FlowKey.DestinationAddress
		case "sourceTransportPort":
			ie.Value = record.Conn.FlowKey.SourcePort
		case "destinationTransportPort":
			ie.Value = record.Conn.FlowKey.DestinationPort
		case "protocolIdentifier":
			ie.Value = record.Conn.FlowKey.Protocol
		case "packetTotalCount":
			ie.Value = record.Conn.OriginalPackets
		case "octetTotalCount":
			ie.Value = record.Conn.OriginalBytes
		case "packetDeltaCount":
			deltaPkts := int64(record.Conn.OriginalPackets) - int64(record.PrevPackets)
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			ie.Value = uint64(deltaPkts)
		case "octetDeltaCount":
			deltaBytes := int64(record.Conn.OriginalBytes) - int64(record.PrevBytes)
			if deltaBytes < 0 {
				klog.Warningf("Byte delta count for connection should not be negative: %d", deltaBytes)
			}
			ie.Value = uint64(deltaBytes)
		case "reversePacketTotalCount":
			ie.Value = record.Conn.ReversePackets
		case "reverseOctetTotalCount":
			ie.Value = record.Conn.ReverseBytes
		case "reversePacketDeltaCount":
			deltaPkts := int64(record.Conn.ReversePackets) - int64(record.PrevReversePackets)
			if deltaPkts < 0 {
				klog.Warningf("Packet delta count for connection should not be negative: %d", deltaPkts)
			}
			ie.Value = uint64(deltaPkts)
		case "reverseOctetDeltaCount":
			deltaBytes := int64(record.Conn.ReverseBytes) - int64(record.PrevReverseBytes)
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
				ie.Value = record.Conn.DestinationServiceAddress
			} else {
				// Sending dummy IP as IPFIX collector expects constant length of data for IP field.
				// We should probably think of better approach as this involves customization of IPFIX collector to ignore
				// this dummy IP address.
				ie.Value = net.IP{0, 0, 0, 0}
			}
		case "destinationClusterIPv6":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.DestinationServiceAddress
			} else {
				// Same as destinationClusterIPv4.
				ie.Value = net.ParseIP("::")
			}
		case "destinationServicePort":
			if record.Conn.DestinationServicePortName != "" {
				ie.Value = record.Conn.DestinationServicePort
			} else {
				ie.Value = uint16(0)
			}
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
		case "ingressNetworkPolicyType":
			ie.Value = record.Conn.IngressNetworkPolicyType
		case "ingressNetworkPolicyRuleName":
			ie.Value = record.Conn.IngressNetworkPolicyRuleName
		case "ingressNetworkPolicyRuleAction":
			ie.Value = record.Conn.IngressNetworkPolicyRuleAction
		case "egressNetworkPolicyName":
			ie.Value = record.Conn.EgressNetworkPolicyName
		case "egressNetworkPolicyNamespace":
			ie.Value = record.Conn.EgressNetworkPolicyNamespace
		case "egressNetworkPolicyType":
			ie.Value = record.Conn.EgressNetworkPolicyType
		case "egressNetworkPolicyRuleName":
			ie.Value = record.Conn.EgressNetworkPolicyRuleName
		case "egressNetworkPolicyRuleAction":
			ie.Value = record.Conn.EgressNetworkPolicyRuleAction
		case "tcpState":
			ie.Value = record.Conn.TCPState
		case "flowType":
			ie.Value = ipfixregistry.FlowTypeIntraNode
		}
	}

	templateID := testTemplateIDv4
	if record.IsIPv6 {
		templateID = testTemplateIDv6
	}
	err := dataSet.AddRecord(elements, templateID)
	if err != nil {
		return fmt.Errorf("error in adding record to data set: %v", err)
	}
	_, err = exportProcess.SendSet(dataSet)
	if err != nil {
		return err
	}

	return nil
}

func getFlowRecord() *flowexporter.FlowRecord {
	src := net.ParseIP("192.168.0.100")
	dst := net.ParseIP("192.169.0.200")
	n, err := rand.Int(rand.Reader, big.NewInt(65000))
	if err != nil {
		klog.Errorf("error when generating random number: %v", err)
		return nil
	}
	srcPort := uint16(n.Uint64())
	n, err = rand.Int(rand.Reader, big.NewInt(65000))
	if err != nil {
		klog.Errorf("error when generating random number: %v", err)
		return nil
	}
	dstPort := uint16(n.Uint64())
	tuple := makeTuple(&src, &dst, 6, srcPort, dstPort)
	conn := flowexporter.Connection{
		StartTime:                  time.Now(),
		StopTime:                   time.Now(),
		IsPresent:                  true,
		FlowKey:                    tuple,
		OriginalPackets:            100,
		OriginalBytes:              10,
		ReversePackets:             50,
		ReverseBytes:               5,
		SourcePodNamespace:         "ns1",
		SourcePodName:              "pod1",
		DestinationPodNamespace:    "ns2",
		DestinationPodName:         "pod2",
		DestinationServicePortName: "service",
		DestinationServiceAddress:  net.ParseIP("172.100.1.200"),
		TCPState:                   "SYN_SENT",
	}
	record := &flowexporter.FlowRecord{
		Conn:               conn,
		PrevPackets:        0,
		PrevBytes:          0,
		PrevReversePackets: 0,
		PrevReverseBytes:   0,
		LastExportTime:     time.Now(),
		IsActive:           true,
	}
	return record
}

func makeTuple(srcIP *net.IP, dstIP *net.IP, protoID uint8, srcPort uint16, dstPort uint16) flowexporter.Tuple {
	tuple := flowexporter.Tuple{
		SourceAddress:      *srcIP,
		DestinationAddress: *dstIP,
		Protocol:           protoID,
		SourcePort:         srcPort,
		DestinationPort:    dstPort,
	}
	return tuple
}

func waitForCollectorReady(b *testing.B, cp *ipfixcollector.CollectingProcess) {
	checkConn := func() (bool, error) {
		if strings.Split(cp.GetAddress().String(), ":")[1] == "0" {
			return false, fmt.Errorf("random port is not resolved")
		}
		connection, err := net.Dial(cp.GetAddress().Network(), cp.GetAddress().String())
		if err != nil {
			return false, err
		}
		connection.Close()
		return true, nil
	}
	if err := wait.Poll(100*time.Millisecond, 1*time.Second, checkConn); err != nil {
		b.Errorf("Cannot establish connection to %s", cp.GetAddress().String())
	}
}

func testHandler(b *testing.B, stopCh chan struct{}) {
	timer := time.NewTimer(testDuration)
	for {
		select {
		case <-timer.C:
			b.Logf("Num messages received: %v", numMessages)
			close(stopCh)
			return
		}
	}
}

func disableLogToStderr() {
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	klogFlagSet.Parse([]string{"-logtostderr=false"})
}
