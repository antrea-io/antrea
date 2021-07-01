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
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/flowexporter/flowrecords"
)

const (
	testNumOfConns         = 20000
	testNumOfDenyConns     = 20000
	testNumOfDyingConns    = 2000
	testNumOfIdleRecords   = 2000
	testNumOfIdleDenyConns = 2000
	testBufferSize         = 1048
)

var recordsReceived = 0

/*
Sample output:
	go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportConntrackConns -memprofile memprofile.out -cpuprofile profile.out
	goos: linux
	goarch: amd64
	pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	BenchmarkExportConntrackConns (truncated output)
		exporter_perf_test.go:79:
			Summary:
			Number of conntrack connections: 20000
			Number of dying conntrack connections: 2000
			Total connections received: 18703
	BenchmarkExportConntrackConns-2   	      75	  13750074 ns/op	  965550 B/op	   22268 allocs/op
	PASS
	ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	5.494s
Reference value:
	#conns
	20000     156	   8037522 ns/op	  340792 B/op	   13540 allocs/op
	30000      61	  20510362 ns/op	 1082075 B/op	   43304 allocs/op
	40000      39	  46557414 ns/op	 3180649 B/op	  127687 allocs/op
	50000      18	  55581807 ns/op	 4420593 B/op	  177554 allocs/op
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
		exp.sendFlowRecords()
	}
	b.Logf("\nSummary:\nNumber of conntrack connections: %d\nNumber of dying conntrack connections: %d\nTotal connections received: %d\n", testNumOfConns, testNumOfDyingConns, recordsReceived)
}

/*
Sample output:
	go test -test.v -run=BenchmarkExport -test.benchmem -bench=BenchmarkExportDenyConns -memprofile memprofile.out -cpuprofile profile.out
	goos: linux
	goarch: amd64
	pkg: antrea.io/antrea/pkg/agent/flowexporter/exporter
	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	BenchmarkExportDenyConns (truncated output)
		exporter_perf_test.go:112:
			Summary:
			Number of deny connections: 20000
			Number of idle deny connections: 2000
			Total connections received: 19124
	BenchmarkExportDenyConns-2   	     204	   6922004 ns/op	  357215 B/op	   12106 allocs/op
	PASS
	ok  	antrea.io/antrea/pkg/agent/flowexporter/exporter	6.189s
Reference value:
	#conns
	20000   210	   5401396 ns/op	  195415 B/op	    7908 allocs/op
	30000   102	  11793506 ns/op	  555344 B/op	   22770 allocs/op
	40000    64	  19141650 ns/op	 1239398 B/op	   51008 allocs/op
	50000    37	  27369835 ns/op	 2036012 B/op	   83802 allocs/op
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
		exp.sendFlowRecords()
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
	records := flowrecords.NewFlowRecords()
	denyConnStore := connections.NewDenyConnectionStore(nil, nil)
	conntrackConnStore := connections.NewConntrackConnectionStore(nil, flowrecords.NewFlowRecords(), nil, true, false, nil, nil, 1)
	if isConntrackConn {
		records = addConnsAndGetRecords(conntrackConnStore)
	} else {
		addDenyConns(denyConnStore)
	}

	exp, _ := NewFlowExporter(conntrackConnStore, records, denyConnStore, collectorAddr.String(), collectorAddr.Network(), testActiveFlowTimeout, testIdleFlowTimeout, true, false, nil, nil, false)
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

func addConnsAndGetRecords(connStore *connections.ConntrackConnectionStore) *flowrecords.FlowRecords {
	randomNum := int(getRandomNum(int64(testNumOfConns - testNumOfDyingConns)))
	records := flowrecords.NewFlowRecords()
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
			LastExportTime:             time.Now().Add(-time.Duration(randomNum1)*time.Millisecond - testActiveFlowTimeout),
			IsPresent:                  true,
			DoneExport:                 false,
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

		// generate record from connection and add the record to record map
		record := &flowexporter.FlowRecord{
			Conn:               *conn,
			PrevPackets:        0,
			PrevBytes:          0,
			PrevReversePackets: 0,
			PrevReverseBytes:   0,
			IsIPv6:             false,
			LastExportTime:     time.Now().Add(-testActiveFlowTimeout),
			IsActive:           true,
		}
		if i < testNumOfIdleRecords {
			record.PrevPackets = conn.OriginalPackets
			record.PrevReversePackets = conn.ReversePackets
			record.LastExportTime = time.Now().Add(-testIdleFlowTimeout)
		}
		records.AddFlowRecordToMap(&connKey, record)
	}
	return records
}

func addDenyConns(connStore *connections.DenyConnectionStore) {
	for i := 0; i < testNumOfDenyConns; i++ {
		randomNum1 := getRandomNum(255)
		randomNum2 := getRandomNum(255)
		src := net.ParseIP(fmt.Sprintf("192.166.%d.%d", randomNum1, randomNum2))
		dst := net.ParseIP(fmt.Sprintf("192.167.%d.%d", randomNum2, randomNum1))
		flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(i), DestinationPort: uint16(i)}
		conn := &flowexporter.Connection{
			StartTime:                     time.Now().Add(-time.Duration(randomNum1) * time.Second),
			StopTime:                      time.Now(),
			LastExportTime:                time.Now().Add(-time.Duration(randomNum1)*time.Millisecond - testActiveFlowTimeout),
			FlowKey:                       flowKey,
			OriginalPackets:               10,
			OriginalBytes:                 100,
			DeltaBytes:                    20,
			DeltaPackets:                  5,
			SourcePodNamespace:            "ns1",
			SourcePodName:                 "pod1",
			EgressNetworkPolicyName:       "egress-reject",
			EgressNetworkPolicyType:       registry.PolicyTypeAntreaNetworkPolicy,
			EgressNetworkPolicyNamespace:  "egress-ns",
			EgressNetworkPolicyRuleAction: registry.NetworkPolicyRuleActionReject,
		}
		if i < testNumOfIdleDenyConns {
			conn.LastExportTime = time.Now().Add(-testIdleFlowTimeout)
		}
		connKey := flowexporter.NewConnectionKey(conn)
		connStore.AddConnToMap(&connKey, conn)
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
