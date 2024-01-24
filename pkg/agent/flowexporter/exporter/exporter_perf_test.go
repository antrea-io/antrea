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

package exporter

import (
	"container/heap"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	exptest "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/ipfix"
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

/*
Sample output:
go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportConntrackConns -benchtime=100x -memprofile memprofile.out -cpuprofile profile.out
goos: linux
goarch: amd64
pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
BenchmarkExportConntrackConns

	exporter_perf_test.go:95:
	    Summary:
	    Number of conntrack connections: 20000
	    Number of dying conntrack connections: 2000
	    Total connections received: 19564
	exporter_perf_test.go:95:
	    Summary:
	    Number of conntrack connections: 20000
	    Number of dying conntrack connections: 2000
	    Total connections received: 18259

BenchmarkExportConntrackConns-2   	     100	   3174982 ns/op	  328104 B/op	    3262 allocs/op
PASS
ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	1.249s
Reference value:

	#conns
	20000     100	   3174982 ns/op	  328104 B/op	    3262 allocs/op
	30000     100	   5074667 ns/op	  489624 B/op	    4874 allocs/op
	40000     100	   5910591 ns/op	  649683 B/op	    6442 allocs/op
	50000     100	   8435327 ns/op	  811341 B/op	    8057 allocs/op
*/
func BenchmarkExportConntrackConns(b *testing.B) {
	disableLogToStderr()

	stopCh := make(chan struct{})
	defer close(stopCh)
	recordsReceived = 0
	exp, err := setupExporter(true, stopCh)
	if err != nil {
		b.Fatalf("error when setting up exporter: %v", err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		exp.initFlowExporter(context.Background())
		for i := 0; i < int(math.Ceil(testNumOfConns/maxConnsToExport)); i++ {
			exp.sendFlowRecords()
		}
	}
	b.StopTimer()
	b.Logf("\nSummary:\nNumber of conntrack connections: %d\nNumber of dying conntrack connections: %d\nTotal connections received: %d\n", testNumOfConns, testNumOfDyingConns, recordsReceived)
}

/*
Sample output:
go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportDenyConns -benchtime=100x -memprofile memprofile.out -cpuprofile profile.out
goos: linux
goarch: amd64
pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
BenchmarkExportDenyConns

	exporter_perf_test.go:143:
	    Summary:
	    Number of deny connections: 20000
	    Number of idle deny connections: 2000
	    Total connections received: 19218
	exporter_perf_test.go:143:
	    Summary:
	    Number of deny connections: 20000
	    Number of idle deny connections: 2000
	    Total connections received: 19237

BenchmarkExportDenyConns-2   	     100	   3133778 ns/op	  322203 B/op	    3474 allocs/op
PASS
ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	1.238s
Reference value:

	#conns
	20000   100	   3133778 ns/op	  322203 B/op	    3474 allocs/op
	30000   100	   4813561 ns/op	  480075 B/op	    5175 allocs/op
	40000   100	   6772657 ns/op	  637599 B/op	    6860 allocs/op
	50000   100	   7078690 ns/op	  795104 B/op	    8549 allocs/op
*/
func BenchmarkExportDenyConns(b *testing.B) {
	disableLogToStderr()

	stopCh := make(chan struct{})
	defer close(stopCh)
	recordsReceived = 0
	exp, err := setupExporter(false, stopCh)
	if err != nil {
		b.Fatalf("error when setting up exporter: %v", err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		exp.initFlowExporter(context.Background())
		for i := 0; i < int(math.Ceil(testNumOfDenyConns/maxConnsToExport)); i++ {
			exp.sendFlowRecords()
		}
	}
	b.StopTimer()
	b.Logf("\nSummary:\nNumber of deny connections: %d\nNumber of idle deny connections: %d\nTotal connections received: %d\n", testNumOfDenyConns, testNumOfIdleDenyConns, recordsReceived)
}

func NewFlowExporterForTest(o *flowexporter.FlowExporterOptions) *FlowExporter {
	// Initialize IPFIX registry
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()

	// Prepare input args for IPFIX exporting process.
	nodeName := "test-node"
	expInput := prepareExporterInputArgs(o.FlowCollectorProto, nodeName)

	v4Enabled := !testWithIPv6
	v6Enabled := testWithIPv6

	l7Listener := connections.NewL7Listener(nil, nil)
	denyConnStore := connections.NewDenyConnectionStore(nil, nil, o)
	conntrackConnStore := connections.NewConntrackConnectionStore(nil, v4Enabled, v6Enabled, nil, nil, nil, l7Listener, o)

	return &FlowExporter{
		collectorAddr:          o.FlowCollectorAddr,
		conntrackConnStore:     conntrackConnStore,
		denyConnStore:          denyConnStore,
		registry:               registry,
		v4Enabled:              v4Enabled,
		v6Enabled:              v6Enabled,
		exporterInput:          expInput,
		ipfixSet:               ipfixentities.NewSet(false),
		k8sClient:              nil,
		nodeRouteController:    nil,
		isNetworkPolicyOnly:    false,
		nodeName:               nodeName,
		conntrackPriorityQueue: conntrackConnStore.GetPriorityQueue(),
		denyPriorityQueue:      denyConnStore.GetPriorityQueue(),
		expiredConns:           make([]flowexporter.Connection, 0, maxConnsToExport*2),
		l7Listener:             l7Listener,
	}
}

func setupExporter(isConntrackConn bool, stopCh <-chan struct{}) (*FlowExporter, error) {
	var err error
	collectorAddr, err := startLocalServer(stopCh)
	if err != nil {
		return nil, err
	}

	// create connection store and generate connections
	o := &flowexporter.FlowExporterOptions{
		FlowCollectorAddr:      collectorAddr.String(),
		FlowCollectorProto:     collectorAddr.Network(),
		ActiveFlowTimeout:      testActiveFlowTimeout,
		IdleFlowTimeout:        testIdleFlowTimeout,
		StaleConnectionTimeout: 1,
		PollInterval:           1,
	}
	exp := NewFlowExporterForTest(o)
	if isConntrackConn {
		addConns(exp.conntrackConnStore, exp.conntrackConnStore.GetPriorityQueue())
	} else {
		addDenyConns(exp.denyConnStore, exp.denyConnStore.GetPriorityQueue())
	}
	return exp, err
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

func addConns(connStore *connections.ConntrackConnectionStore, expirePriorityQueue *priorityqueue.ExpirePriorityQueue) {
	randomNum := int(getRandomNum(int64(testNumOfConns - testNumOfDyingConns)))
	for i := 0; i < testNumOfConns; i++ {
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
		flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		randomDuration := getRandomNum(255)
		conn := &flowexporter.Connection{
			StartTime:                  time.Now().Add(-time.Duration(randomDuration) * time.Second),
			StopTime:                   time.Now(),
			IsPresent:                  true,
			ReadyToDelete:              false,
			FlowKey:                    flowKey,
			OriginalPackets:            100,
			OriginalBytes:              10,
			ReversePackets:             50,
			ReverseBytes:               5,
			SourcePodNamespace:         "ns1",
			SourcePodName:              "pod1",
			DestinationPodNamespace:    "ns2",
			DestinationPodName:         "pod2",
			DestinationServicePortName: "service",
			OriginalDestinationAddress: svc,
			TCPState:                   "SYN_SENT",
		}
		connKey := flowexporter.NewConnectionKey(conn)
		// set connection to dying state
		if i >= randomNum && i < testNumOfDyingConns+randomNum {
			conn.TCPState = "TIME_WAIT"
		}
		connStore.AddConnToMap(&connKey, conn)
		pqItem := &flowexporter.ItemToExpire{
			ActiveExpireTime: time.Now().Add(-time.Duration(randomDuration) * time.Second),
			IdleExpireTime:   time.Now(),
		}
		pqItem.Conn = conn
		heap.Push(expirePriorityQueue, pqItem)
		expirePriorityQueue.KeyToItem[connKey] = pqItem
	}
}

func addDenyConns(connStore *connections.DenyConnectionStore, expirePriorityQueue *priorityqueue.ExpirePriorityQueue) {
	for i := 0; i < testNumOfDenyConns; i++ {
		var src, dst netip.Addr
		if testWithIPv6 {
			src = exptest.RandIPv6()
			dst = exptest.RandIPv6()
		} else {
			src = exptest.RandIPv4()
			dst = exptest.RandIPv4()
		}
		flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		randomDuration := getRandomNum(255)
		conn := &flowexporter.Connection{
			StartTime:                     time.Now().Add(-time.Duration(randomDuration) * time.Second),
			StopTime:                      time.Now(),
			FlowKey:                       flowKey,
			OriginalPackets:               10,
			OriginalBytes:                 100,
			SourcePodNamespace:            "ns1",
			SourcePodName:                 "pod1",
			EgressNetworkPolicyName:       "egress-reject",
			EgressNetworkPolicyType:       registry.PolicyTypeAntreaNetworkPolicy,
			EgressNetworkPolicyNamespace:  "egress-ns",
			EgressNetworkPolicyRuleAction: registry.NetworkPolicyRuleActionReject,
		}
		connKey := flowexporter.NewConnectionKey(conn)
		connStore.AddConnToMap(&connKey, conn)
		pqItem := &flowexporter.ItemToExpire{
			ActiveExpireTime: time.Now().Add(-time.Duration(randomDuration) * time.Second),
			IdleExpireTime:   time.Now(),
		}
		pqItem.Conn = conn
		heap.Push(expirePriorityQueue, pqItem)
		expirePriorityQueue.KeyToItem[connKey] = pqItem
	}
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
