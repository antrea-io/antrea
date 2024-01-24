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
	"net/netip"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	exptest "antrea.io/antrea/pkg/agent/flowexporter/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytest "antrea.io/antrea/pkg/agent/proxy/testing"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	podstoretest "antrea.io/antrea/pkg/util/podstore/testing"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

const (
	testNumOfConns        = 10000
	testNumOfNewConns     = 1000
	testNumOfDeletedConns = 1000

	testWithIPv6 = false
)

var (
	svcIPv4 = netip.MustParseAddr("10.0.0.1")
	svcIPv6 = netip.MustParseAddr("2001:0:3238:dfe1:63::fefc")
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
	b.StopTimer()
	b.Logf("\nSummary:\nNumber of initial connections: %d\nNumber of new connections/poll: %d\nNumber of deleted connections/poll: %d\n", testNumOfConns, testNumOfNewConns, testNumOfDeletedConns)
}

/*
Sample output:
$ go test -run=XXX -bench=BenchmarkConnStore -benchtime=100x -test.benchmem -memprofile memprofile.out
goos: darwin
goarch: amd64
pkg: antrea.io/antrea/pkg/agent/flowexporter/connections
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkConnStore-12    	     100	 119354325 ns/op	20490802 B/op	  272626 allocs/op
PASS
ok  	antrea.io/antrea/pkg/agent/flowexporter/connections	13.111s
*/
func BenchmarkConnStore(b *testing.B) {
	disableLogToStderr()
	connStore, _ := setupConntrackConnStore(b)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		// include this in the benchmark (do not stop timer), to measure the memory
		// footprint of the connection store and all connections accurately.
		conns := generateConns()
		// add connections
		for _, conn := range conns {
			connStore.AddOrUpdateConn(conn)
		}
	}
	b.StopTimer()
	b.Logf("\nSummary:\nNumber of initial connections: %d\nNumber of new connections/poll: %d\nNumber of deleted connections/poll: %d\n", testNumOfConns, testNumOfNewConns, testNumOfDeletedConns)
}

func setupConntrackConnStore(b *testing.B) (*ConntrackConnectionStore, *connectionstest.MockConnTrackDumper) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()
	mockPodStore := podstoretest.NewMockInterface(ctrl)
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "pod-ns",
			Name:      "pod",
			UID:       "pod",
		},
		Status: v1.PodStatus{
			Phase: v1.PodPending,
		},
	}
	mockPodStore.EXPECT().GetPodByIPAndTime(gomock.Any(), gomock.Any()).Return(pod, true).AnyTimes()

	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	mockConnDumper.EXPECT().GetMaxConnections().Return(100000, nil).AnyTimes()

	svcIP := svcIPv4
	if testWithIPv6 {
		svcIP = svcIPv6
	}
	serviceStr := fmt.Sprintf("%s:30000/TCP", svcIP.String())
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
	l7Listener := NewL7Listener(nil, mockPodStore)
	return NewConntrackConnectionStore(mockConnDumper, true, false, npQuerier, mockPodStore, nil, l7Listener, testFlowExporterOptions), mockConnDumper
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
		if conns[i].ReadyToDelete == true {
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
		updatedConns[i].ReadyToDelete = true
	}
	return updatedConns
}

func getNewConn() *flowexporter.Connection {
	randomNum1 := getRandomNum(255)
	randomNum2 := getRandomNum(255)
	var src, dst, svc netip.Addr
	if testWithIPv6 {
		src = exptest.RandIPv6()
		dst = exptest.RandIPv6()
		svc = svcIPv6
	} else {
		src = exptest.RandIPv4()
		dst = exptest.RandIPv4()
		svc = svcIPv4
	}
	flowKey := flowexporter.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: uint16(randomNum1), DestinationPort: uint16(randomNum2)}
	return &flowexporter.Connection{
		StartTime:                  time.Now().Add(-time.Duration(randomNum1) * time.Second),
		StopTime:                   time.Now(),
		IsPresent:                  true,
		ReadyToDelete:              false,
		FlowKey:                    flowKey,
		OriginalPackets:            10,
		OriginalBytes:              100,
		ReversePackets:             5,
		ReverseBytes:               50,
		OriginalDestinationAddress: svc,
		OriginalDestinationPort:    30000,
		TCPState:                   "SYN_SENT",
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
