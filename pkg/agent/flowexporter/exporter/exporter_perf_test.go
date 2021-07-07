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
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
)

const (
	testNumOfConns         = 20000
	testNumOfDenyConns     = 20000
	testNumOfDyingConns    = 2000
	testNumOfIdleDenyConns = 2000
	testBufferSize         = 1048
)

var recordsReceived = 0

/*
Sample output:
go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportConntrackConns -benchtime=100x -memprofile memprofile.out -cpuprofile profile.out
goos: linux
goarch: amd64
pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
BenchmarkExportConntrackConns-2   	     100	   3484688 ns/op	  527820 B/op	    8214 allocs/op
--- BENCH: BenchmarkExportConntrackConns-2
    exporter_perf_test.go:92:
        Summary:
        Number of conntrack connections: 20000
        Number of dying conntrack connections: 2000
        Total connections received: 19698
    exporter_perf_test.go:92:
        Summary:
        Number of conntrack connections: 20000
        Number of dying conntrack connections: 2000
        Total connections received: 18509
	... [output truncated]
PASS
ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	1.134s
Reference value:
	#conns
	20000     100	   3484688 ns/op	  527820 B/op	    8214 allocs/op
	30000     100 	   5868374 ns/op	  788098 B/op	   12313 allocs/op
	40000     100	   7300047 ns/op	 1047562 B/op	   16392 allocs/op
	50000     100	   9312464 ns/op	 1308313 B/op	   20503 allocs/op
*/
func BenchmarkExportConntrackConns(b *testing.B) {
	disableLogToStderr()
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	recordsReceived = 0
	exp, err := setupExporter(true)
	if err != nil {
		b.Fatalf("error when setting up exporter: %v", err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		exp.initFlowExporter()
		for i := 0; i < int(math.Ceil(testNumOfConns/maxConnsToExport)); i++ {
			exp.sendFlowRecords()
		}
	}
	b.Logf("\nSummary:\nNumber of conntrack connections: %d\nNumber of dying conntrack connections: %d\nTotal connections received: %d\n", testNumOfConns, testNumOfDyingConns, recordsReceived)
}

/*
Sample output:
go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportDenyConns -benchtime=100x -memprofile memprofile.out -cpuprofile profile.out
goos: linux
goarch: amd64
pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
BenchmarkExportDenyConns-2   	     100	   3714699 ns/op	  507942 B/op	    7037 allocs/op
--- BENCH: BenchmarkExportDenyConns-2
    exporter_perf_test.go:135:
        Summary:
        Number of deny connections: 20000
        Number of idle deny connections: 2000
        Total connections received: 19742
    exporter_perf_test.go:135:
        Summary:
        Number of deny connections: 20000
        Number of idle deny connections: 2000
        Total connections received: 19671
	... [output truncated]
PASS
ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	1.331s
Reference value:
	#conns
	20000   100	   3714699 ns/op	  507942 B/op	    7037 allocs/op
	30000   100	   5073132 ns/op	  755810 B/op	   10488 allocs/op
	40000   100	   7874295 ns/op	 1004996 B/op	   13965 allocs/op
	50000   100	   8681581 ns/op	 1257332 B/op	   17527 allocs/op
*/
func BenchmarkExportDenyConns(b *testing.B) {
	disableLogToStderr()
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	recordsReceived = 0
	exp, err := setupExporter(false)
	if err != nil {
		b.Fatalf("error when setting up exporter: %v", err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		exp.initFlowExporter()
		for i := 0; i < int(math.Ceil(testNumOfDenyConns/maxConnsToExport)); i++ {
			exp.sendFlowRecords()
		}
	}
	b.Logf("\nSummary:\nNumber of deny connections: %d\nNumber of idle deny connections: %d\nTotal connections received: %d\n", testNumOfDenyConns, testNumOfIdleDenyConns, recordsReceived)

}

func setupExporter(isConntrackConn bool) (*flowExporter, error) {
	var err error
	collectorAddr, err := startLocalServer()
	if err != nil {
		return nil, err
	}

	// create connection store and generate connections
	conntrackPQ := priorityqueue.NewExpirePriorityQueue(testActiveFlowTimeout, testIdleFlowTimeout)
	denyPQ := priorityqueue.NewExpirePriorityQueue(testActiveFlowTimeout, testIdleFlowTimeout)
	denyConnStore := connections.NewDenyConnectionStore(nil, nil, denyPQ, 0)
	conntrackConnStore := connections.NewConntrackConnectionStore(nil, nil, true, false, nil, nil, 1, conntrackPQ, 1)
	if isConntrackConn {
		addConns(conntrackConnStore, conntrackPQ)
	} else {
		addDenyConns(denyConnStore, denyPQ)
	}

	exp, _ := NewFlowExporter(conntrackConnStore, denyConnStore, collectorAddr.String(), collectorAddr.Network(), true, false, nil, nil, false, conntrackPQ, denyPQ)
	return exp, err
}

func startLocalServer() (net.Addr, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("error when creating local server: %v", err)
	}
	go func() {
		defer conn.Close()
		for {
			buff := make([]byte, testBufferSize)
			_, _, err := conn.ReadFromUDP(buff)
			if err != nil {
				return
			}
			recordsReceived++
		}
	}()
	return conn.LocalAddr(), nil
}

func addConns(connStore *connections.ConntrackConnectionStore, expirePriorityQueue *priorityqueue.ExpirePriorityQueue) {
	randomNum := int(getRandomNum(int64(testNumOfConns - testNumOfDyingConns)))
	for i := 0; i < testNumOfConns; i++ {
		// create and add connection to connection store
		randomNum1 := getRandomNum(255)
		randomNum2 := getRandomNum(255)
		src := net.ParseIP(fmt.Sprintf("192.168.%d.%d", randomNum1, randomNum2))
		dst := net.ParseIP(fmt.Sprintf("192.169.%d.%d", randomNum2, randomNum1))
		flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		conn := &flowexporter.Connection{
			StartTime:                  time.Now().Add(-time.Duration(randomNum1) * time.Second),
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
			DestinationServiceAddress:  net.ParseIP("0.0.0.0"),
			TCPState:                   "SYN_SENT",
		}
		connKey := flowexporter.NewConnectionKey(conn)
		// set connection to dying state
		if i >= randomNum && i < testNumOfDyingConns+randomNum {
			conn.TCPState = "TIME_WAIT"
		}
		connStore.AddConnToMap(&connKey, conn)
		pqItem := &flowexporter.ItemToExpire{
			ActiveExpireTime: time.Now().Add(-time.Duration(randomNum1) * time.Second),
			IdleExpireTime:   time.Now(),
		}
		pqItem.Conn = conn
		heap.Push(expirePriorityQueue, pqItem)
		expirePriorityQueue.KeyToItem[connKey] = pqItem
	}
}

func addDenyConns(connStore *connections.DenyConnectionStore, expirePriorityQueue *priorityqueue.ExpirePriorityQueue) {
	for i := 0; i < testNumOfDenyConns; i++ {
		randomNum1 := getRandomNum(255)
		randomNum2 := getRandomNum(255)
		src := net.ParseIP(fmt.Sprintf("192.166.%d.%d", randomNum1, randomNum2))
		dst := net.ParseIP(fmt.Sprintf("192.167.%d.%d", randomNum2, randomNum1))
		flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		conn := &flowexporter.Connection{
			StartTime:                     time.Now().Add(-time.Duration(randomNum1) * time.Second),
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
			ActiveExpireTime: time.Now().Add(-time.Duration(randomNum1) * time.Second),
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
