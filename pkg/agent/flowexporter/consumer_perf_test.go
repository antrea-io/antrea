//go:build !race
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

package flowexporter

import (
	"container/heap"
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/exporter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	exptest "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	testNumOfConns         = 20000
	testNumOfDenyConns     = 20000
	testNumOfDyingConns    = 2000
	testNumOfIdleDenyConns = 2000
	testBufferSize         = 1048

	testWithIPv6 = false
)

var recordsReceived = 0

// /*
// Sample output:
// go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportConntrackConns -benchtime=100x -memprofile memprofile.out -cpuprofile profile.out
// goos: linux
// goarch: amd64
// pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
// cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
// BenchmarkExportConntrackConns

// 	exporter_perf_test.go:95:
// 	    Summary:
// 	    Number of conntrack connections: 20000
// 	    Number of dying conntrack connections: 2000
// 	    Total connections received: 19564
// 	exporter_perf_test.go:95:
// 	    Summary:
// 	    Number of conntrack connections: 20000
// 	    Number of dying conntrack connections: 2000
// 	    Total connections received: 18259

// BenchmarkExportConntrackConns-2   	     100	   3174982 ns/op	  328104 B/op	    3262 allocs/op
// PASS
// ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	1.249s
// Reference value:

//	#conns
//	20000     100	   3174982 ns/op	  328104 B/op	    3262 allocs/op
//	30000     100	   5074667 ns/op	  489624 B/op	    4874 allocs/op
//	40000     100	   5910591 ns/op	  649683 B/op	    6442 allocs/op
//	50000     100	   8435327 ns/op	  811341 B/op	    8057 allocs/op
//
// */
func BenchmarkExportConntrackConns(b *testing.B) {
	disableLogToStderr()

	stopCh := make(chan struct{})
	defer close(stopCh)
	recordsReceived = 0
	consumer, err := setupConsumer(b, true, stopCh)
	if err != nil {
		b.Fatalf("error when setting up exporter: %v", err)
	}
	consumer.Connect(b.Context())
	for b.Loop() {
		for i := 0; i < int(math.Ceil(testNumOfConns/maxConnsToExport)); i++ {
			consumer.sendFlowRecords()
		}
	}
	b.Logf("\nSummary:\nNumber of conntrack connections: %d\nNumber of dying conntrack connections: %d\nTotal connections received: %d\n", testNumOfConns, testNumOfDyingConns, recordsReceived)
}

// /*
// Sample output:
// go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportDenyConns -benchtime=100x -memprofile memprofile.out -cpuprofile profile.out
// goos: linux
// goarch: amd64
// pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
// cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
// BenchmarkExportDenyConns

// 	exporter_perf_test.go:143:
// 	    Summary:
// 	    Number of deny connections: 20000
// 	    Number of idle deny connections: 2000
// 	    Total connections received: 19218
// 	exporter_perf_test.go:143:
// 	    Summary:
// 	    Number of deny connections: 20000
// 	    Number of idle deny connections: 2000
// 	    Total connections received: 19237

// BenchmarkExportDenyConns-2   	     100	   3133778 ns/op	  322203 B/op	    3474 allocs/op
// PASS
// ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	1.238s
// Reference value:

//	#conns
//	20000   100	   3133778 ns/op	  322203 B/op	    3474 allocs/op
//	30000   100	   4813561 ns/op	  480075 B/op	    5175 allocs/op
//	40000   100	   6772657 ns/op	  637599 B/op	    6860 allocs/op
//	50000   100	   7078690 ns/op	  795104 B/op	    8549 allocs/op
//
// */
func BenchmarkExportDenyConns(b *testing.B) {
	disableLogToStderr()

	stopCh := make(chan struct{})
	defer close(stopCh)
	recordsReceived = 0
	consumer, err := setupConsumer(b, true, stopCh)
	if err != nil {
		b.Fatalf("error when setting up exporter: %v", err)
	}
	consumer.Connect(b.Context())
	for b.Loop() {
		for i := 0; i < int(math.Ceil(testNumOfDenyConns/maxConnsToExport)); i++ {
			consumer.sendFlowRecords()
		}
	}
	b.Logf("\nSummary:\nNumber of deny connections: %d\nNumber of idle deny connections: %d\nTotal connections received: %d\n", testNumOfDenyConns, testNumOfIdleDenyConns, recordsReceived)
}

func NewConsumerForTest(tb testing.TB, config *ConsumerConfig) *Consumer {
	const (
		nodeName    = "test-node"
		obsDomainID = 0xabcd
	)

	v4Enabled := !testWithIPv6
	v6Enabled := testWithIPv6

	return &Consumer{
		ConsumerConfig:      config,
		expirePriorityQueue: priorityqueue.NewExpirePriorityQueue(config.activeFlowTimeout, config.idleFlowTimeout),
		exp:                 exporter.NewIPFIXExporter(string(config.protocol.TransportProtocol()), nodeName, obsDomainID, v4Enabled, v6Enabled),
		l7Events:            map[connection.ConnectionKey]connections.L7ProtocolFields{},
		prevStates:          map[connection.ConnectionKey]prevState{},
		exportConns:         make([]*connection.Connection, 0, maxConnsToExport),
	}
}

func setupConsumer(tb testing.TB, isConntrackConn bool, stopCh <-chan struct{}) (*Consumer, error) {
	var err error
	collectorAddr, err := startLocalServer(stopCh)
	if err != nil {
		return nil, err
	}

	// create connection store and generate connections
	cfg := &ConsumerConfig{
		address:   collectorAddr.String(),
		v4Enabled: !testWithIPv6,
		v6Enabled: testWithIPv6,
		protocol: &v1alpha1.FlowExporterIPFIXConfig{
			Transport: v1alpha1.FlowExporterTransportProtocol(collectorAddr.Network()),
		},
		activeFlowTimeout: testActiveFlowTimeout,
		idleFlowTimeout:   testIdleFlowTimeout,
	}
	consumer := NewConsumerForTest(tb, cfg)
	if isConntrackConn {
		addConns(consumer, consumer.expirePriorityQueue)
	} else {
		addDenyConns(consumer, consumer.expirePriorityQueue)
	}
	return consumer, err
}

func startLocalServer(stopCh <-chan struct{}) (net.Addr, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("error when creating local server: %v", err)
	}
	go func() {
		for {
			buff := make([]byte, testBufferSize)
			_, _, err := conn.ReadFromUDP(buff)
			if err != nil {
				return
			}
			recordsReceived++
		}
	}()
	go func() {
		<-stopCh
		conn.Close()
	}()
	return conn.LocalAddr(), nil
}

func addConns(consumer *Consumer, expirePriorityQueue *priorityqueue.ExpirePriorityQueue) {
	randomNum := int(getRandomNum(int64(testNumOfConns - testNumOfDyingConns)))
	conns := make([]*connection.Connection, 0, testNumOfConns)
	for i := range testNumOfConns {
		// create and add connection to connection store
		var src, dst, svc netip.Addr
		if testWithIPv6 {
			src = exptest.RandIPv6()
			dst = exptest.RandIPv6()
			svc = exptest.RandIPv6()
		} else {
			src = exptest.RandIPv4()
			dst = exptest.RandIPv4()
			svc = exptest.RandIPv4()
		}
		flowKey := connection.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		randomDuration := getRandomNum(255)
		conn := &connection.Connection{
			StartTime:     time.Now().Add(-time.Duration(randomDuration) * time.Second),
			StopTime:      time.Now(),
			IsPresent:     true,
			ReadyToDelete: false,
			FlowKey:       flowKey,
			OriginalStats: connection.Stats{
				Packets:        100,
				Bytes:          10,
				ReversePackets: 50,
				ReverseBytes:   5,
			},
			SourcePodNamespace:         "ns1",
			SourcePodName:              "pod1",
			DestinationPodNamespace:    "ns2",
			DestinationPodName:         "pod2",
			DestinationServicePortName: "service",
			OriginalDestinationAddress: svc,
			TCPState:                   "SYN_SENT",
		}
		connKey := connection.NewConnectionKey(conn)
		// set connection to dying state
		if i >= randomNum && i < testNumOfDyingConns+randomNum {
			conn.TCPState = "TIME_WAIT"
		}
		pqItem := &priorityqueue.ItemToExpire{
			ActiveExpireTime: time.Now().Add(-time.Duration(randomDuration) * time.Second),
			IdleExpireTime:   time.Now(),
		}
		pqItem.Conn = conn
		heap.Push(expirePriorityQueue, pqItem)
		expirePriorityQueue.KeyToItem[connKey] = pqItem
		conns = append(conns, conn)
	}
	consumer.handleUpdatedConns(conns, nil)
}

func addDenyConns(consumer *Consumer, expirePriorityQueue *priorityqueue.ExpirePriorityQueue) {
	conns := make([]*connection.Connection, 0, testNumOfDenyConns)
	for i := range testNumOfDenyConns {
		var src, dst netip.Addr
		if testWithIPv6 {
			src = exptest.RandIPv6()
			dst = exptest.RandIPv6()
		} else {
			src = exptest.RandIPv4()
			dst = exptest.RandIPv4()
		}
		flowKey := connection.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		randomDuration := getRandomNum(255)
		conn := &connection.Connection{
			StartTime: time.Now().Add(-time.Duration(randomDuration) * time.Second),
			StopTime:  time.Now(),
			FlowKey:   flowKey,
			OriginalStats: connection.Stats{
				Packets: 10,
				Bytes:   100,
			},
			SourcePodNamespace:            "ns1",
			SourcePodName:                 "pod1",
			EgressNetworkPolicyName:       "egress-reject",
			EgressNetworkPolicyType:       utils.PolicyTypeAntreaNetworkPolicy,
			EgressNetworkPolicyNamespace:  "egress-ns",
			EgressNetworkPolicyRuleAction: utils.NetworkPolicyRuleActionReject,
		}
		connKey := connection.NewConnectionKey(conn)
		pqItem := &priorityqueue.ItemToExpire{
			ActiveExpireTime: time.Now().Add(-time.Duration(randomDuration) * time.Second),
			IdleExpireTime:   time.Now(),
		}
		pqItem.Conn = conn
		heap.Push(expirePriorityQueue, pqItem)
		expirePriorityQueue.KeyToItem[connKey] = pqItem
		conns = append(conns, conn)
	}
	consumer.handleUpdatedConns(conns, nil)
}

func getRandomNum(value int64) uint64 {
	number, _ := rand.Int(rand.Reader, big.NewInt(value))
	return number.Uint64()
}

func disableLogToStderr() {
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	klogFlagSet.Parse([]string{"-logtostderr=false"})
}
