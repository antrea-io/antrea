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

package connections

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/flowexporter/flowrecords"
	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

const (
	testNumOfConns        = 10000
	testNumOfNewConns     = 1000
	testNumOfDeletedConns = 1000
)

/*
Sample output (10000 init connections, 1000 new connections, 1000 deleted connections):
    go test -test.v -run=BenchmarkPoll -test.benchmem -bench=. -memprofile memprofile.out -cpuprofile profile.out
	goos: linux
	goarch: amd64
	pkg: antrea.io/antrea/pkg/agent/flowexporter/connections
	cpu: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
	BenchmarkPoll
	BenchmarkPoll-2   	     116	   9068998 ns/op	  889713 B/op	   54458 allocs/op
	PASS
	ok  	antrea.io/antrea/pkg/agent/flowexporter/connections	3.618s
*/

func BenchmarkPoll(b *testing.B) {
	disableLogToStderr()
	connStore, mockConnDumper := setupConntrackConnStore(b)
	conns := generateConns()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return(conns, testNumOfConns, nil)
		connStore.Poll()
		b.StopTimer()
		conns = generateUpdatedConns(conns)
		b.StartTimer()
	}
	b.Logf("\nSummary:\nNumber of initial connections: %d\nNumber of new connections/poll: %d\nNumber of deleted connections/poll: %d\n", testNumOfConns, testNumOfNewConns, testNumOfDeletedConns)
}

func setupConntrackConnStore(b *testing.B) (*ConntrackConnectionStore, *connectionstest.MockConnTrackDumper) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	mockIfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	testInterface := &interfacestore.InterfaceConfig{
		Type: interfacestore.ContainerInterface,
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodName:      "pod",
			PodNamespace: "pod-ns",
		},
	}
	mockIfaceStore.EXPECT().GetInterfaceByIP(gomock.Any()).Return(testInterface, true).AnyTimes()

	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	mockConnDumper.EXPECT().GetMaxConnections().Return(100000, nil).AnyTimes()

	serviceStr := "10.0.0.1:30000/TCP"
	servicePortName := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "serviceNS1",
			Name:      "service1",
		},
		Port:     "30000",
		Protocol: v1.ProtocolTCP,
	}
	mockProxier := proxytest.NewMockProxier(ctrl)
	mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(servicePortName, true).AnyTimes()

	npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)

	return NewConntrackConnectionStore(mockConnDumper, flowrecords.NewFlowRecords(), mockIfaceStore, true, false, mockProxier, npQuerier, testPollInterval, testStaleConnectionTimeout), mockConnDumper
}

func generateConns() []*flowexporter.Connection {
	conns := make([]*flowexporter.Connection, testNumOfConns)
	for i := 0; i < testNumOfConns; i++ {
		conns[i] = getNewConn()
	}
	return conns
}

func generateUpdatedConns(conns []*flowexporter.Connection) []*flowexporter.Connection {
	length := len(conns) - testNumOfDeletedConns + testNumOfNewConns
	updatedConns := make([]*flowexporter.Connection, length)
	for i := 0; i < len(conns); i++ {
		// replace deleted connection with new connection
		if conns[i].DyingAndDoneExport == true {
			conns[i] = getNewConn()
		} else { // update rest of connections
			conns[i].OriginalPackets += 5
			conns[i].OriginalBytes += 20
			conns[i].ReversePackets += 2
			conns[i].ReverseBytes += 10
		}
		updatedConns[i] = conns[i]
	}
	for i := len(conns); i < length; i++ {
		updatedConns[i] = getNewConn()
	}
	randomNum := getRandomNum(int64(length - testNumOfDeletedConns))
	for i := randomNum; i < testNumOfDeletedConns+randomNum; i++ {
		// hardcode DyingAndDoneExport here for testing deletion of connections
		// not valid for testing update and export of records
		updatedConns[i].DyingAndDoneExport = true
	}
	return updatedConns
}

func getNewConn() *flowexporter.Connection {
	randomNum1 := getRandomNum(255)
	randomNum2 := getRandomNum(255)
	randomNum3 := getRandomNum(255)
	src := net.ParseIP(fmt.Sprintf("192.%d.%d.%d", randomNum1, randomNum2, randomNum3))
	dst := net.ParseIP(fmt.Sprintf("192.%d.%d.%d", randomNum3, randomNum2, randomNum1))
	flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(randomNum1), DestinationPort: uint16(randomNum2)}
	return &flowexporter.Connection{
		StartTime:                 time.Now().Add(-time.Duration(randomNum1) * time.Second),
		StopTime:                  time.Now(),
		IsPresent:                 true,
		DyingAndDoneExport:        false,
		FlowKey:                   flowKey,
		OriginalPackets:           10,
		OriginalBytes:             100,
		ReversePackets:            5,
		ReverseBytes:              50,
		DestinationServiceAddress: net.ParseIP("10.0.0.1"),
		DestinationServicePort:    30000,
		TCPState:                  "SYN_SENT",
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
