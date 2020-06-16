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

package ovstracing

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	interfacestoretest "github.com/vmware-tanzu/antrea/pkg/agent/interfacestore/testing"
	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	aqtest "github.com/vmware-tanzu/antrea/pkg/agent/querier/testing"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	ovsctltest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl/testing"
)

var (
	testTraceResult = "tracing result"
	testResponse    = Response{testTraceResult}

	tunnelVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	gatewayMAC, _       = net.ParseMAC("00:00:00:00:00:01")
	podMAC, _           = net.ParseMAC("00:00:00:00:00:11")

	testNodeConfig = &config.NodeConfig{
		GatewayConfig: &config.GatewayConfig{
			Name: "gw0",
			IP:   net.ParseIP("10.1.1.1"),
			MAC:  gatewayMAC},
	}

	gatewayInterface = &interfacestore.InterfaceConfig{Type: interfacestore.GatewayInterface, InterfaceName: "gw0"}
	tunnelInterface  = &interfacestore.InterfaceConfig{Type: interfacestore.TunnelInterface, InterfaceName: "tun0"}
	inPodInterface   = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "inPod",
		IP:            net.ParseIP("10.1.1.11"),
		MAC:           podMAC,
	}
	srcPodInterface = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "srcPod",
		IP:            net.ParseIP("10.1.1.12"),
		MAC:           podMAC,
	}
	dstPodInterface = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "dstPod",
		IP:            net.ParseIP("10.1.1.13"),
		MAC:           podMAC,
	}
)

type testCase struct {
	test           string
	port           string
	query          string
	calledTrace    bool
	expectedStatus int
}

func TestPodFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := []testCase{
		{
			test:           "Invalid port format",
			port:           "pod1",
			query:          "?port=inNS/inPod/xyz",
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "IP as inport port",
			query:          "?port=10.1.1.123",
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Invalid source Pod format",
			query:          "?source=srcNS/",
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Invalid dest Pod format",
			query:          "?destination=/dstPod",
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "IPv6 source",
			query:          "?source=2001:0db8:0000:0000:0000:ff00:0042:8329",
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Non-existing input Pod",
			port:           "pod",
			query:          "?port=inNS/inPod",
			expectedStatus: http.StatusNotFound,
		},
		{
			test:           "Non-existing source port",
			port:           "port",
			query:          "?source=port",
			expectedStatus: http.StatusNotFound,
		},
		{
			test:           "Duplicated source IP",
			query:          "?source=srcNS/srcPod&&flow=nw_src=10.1.1.123",
			calledTrace:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Duplicated dest IP",
			query:          "?destination=10.1.1.123&&flow=nw_dst=10.1.1.124",
			calledTrace:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Source IP with non-IP flow",
			query:          "?destination=10.1.1.123&&flow=arp",
			calledTrace:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Duplicate in_port",
			port:           "pod",
			query:          "?port=inNS/inPod&&flow=in_port=123",
			calledTrace:    true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			test:           "Default command",
			calledTrace:    true,
			expectedStatus: http.StatusOK,
		},
		{
			test:           "Pod-to-Pod traffic",
			port:           "pod",
			query:          "?port=inNS/inPod&&destination=dstNS/dstPod",
			calledTrace:    true,
			expectedStatus: http.StatusOK,
		},
		{
			test:           "Tunnel traffic",
			port:           "tun0",
			query:          "?port=tun0&&source=10.1.1.123&&destination=dstNS/dstPod",
			calledTrace:    true,
			expectedStatus: http.StatusOK,
		},
		{
			test:           "gw0 port",
			port:           "gw0",
			query:          "?port=gw0&&destination=dstNS/dstPod",
			calledTrace:    true,
			expectedStatus: http.StatusOK,
		},
	}
	for _, tc := range testcases {
		q := aqtest.NewMockAgentQuerier(ctrl)
		i := interfacestoretest.NewMockInterfaceStore(ctrl)
		ofc := oftest.NewMockClient(ctrl)
		ctl := ovsctltest.NewMockOVSCtlClient(ctrl)
		q.EXPECT().GetNodeConfig().Return(testNodeConfig).MaxTimes(1)

		if tc.expectedStatus == http.StatusNotFound {
			q.EXPECT().GetInterfaceStore().Return(i).Times(1)
			if tc.port == "pod" {
				i.EXPECT().GetContainerInterfacesByPod("inPod", "inNS").Return(nil).Times(1)
			} else {
				i.EXPECT().GetInterfaceByName(tc.port).Return(nil, false).Times(1)
			}
		}
		if tc.calledTrace {
			assert.False(t, tc.expectedStatus == http.StatusNotFound)

			q.EXPECT().GetInterfaceStore().Return(i).MaxTimes(3)
			if tc.port == "gw0" {
				i.EXPECT().GetInterfaceByName(tc.port).Return(gatewayInterface, true).Times(1)
			} else if tc.port == "tun0" {
				i.EXPECT().GetInterfaceByName(tc.port).Return(tunnelInterface, true).Times(1)
				q.EXPECT().GetOpenflowClient().Return(ofc).Times(1)
				ofc.EXPECT().GetTunnelVirtualMAC().Return(tunnelVirtualMAC).Times(1)
			} else if tc.port == "pod" {
				i.EXPECT().GetContainerInterfacesByPod("inPod", "inNS").Return([]*interfacestore.InterfaceConfig{inPodInterface}).Times(1)
			} else if tc.port != "" {
				i.EXPECT().GetInterfaceByName(tc.port).Return(inPodInterface, true).Times(1)
			}
			i.EXPECT().GetContainerInterfacesByPod("srcPod", "srcNS").Return([]*interfacestore.InterfaceConfig{srcPodInterface}).MaxTimes(1)
			i.EXPECT().GetContainerInterfacesByPod("dstPod", "dstNS").Return([]*interfacestore.InterfaceConfig{dstPodInterface}).MaxTimes(1)

			if tc.expectedStatus == http.StatusBadRequest {
				// "ovs-appctl" won't be executed. OVSCtlClient.Trace() will just
				// validate the TracingRequest and return.
				q.EXPECT().GetOVSCtlClient().Return(ovsctl.NewClient("br-int")).Times(1)
			} else {
				q.EXPECT().GetOVSCtlClient().Return(ctl).Times(1)
				if tc.expectedStatus == http.StatusOK {
					ctl.EXPECT().Trace(gomock.Any()).Return(testTraceResult, nil).Times(1)
				} else {
					ctl.EXPECT().Trace(gomock.Any()).Return(nil, errors.New("tracing error")).Times(1)
				}
			}
		} else {
			assert.True(t, tc.expectedStatus == http.StatusNotFound || tc.expectedStatus == http.StatusBadRequest)
		}

		runHTTPTest(t, &tc, q)
	}
}

func runHTTPTest(t *testing.T, tc *testCase, aq querier.AgentQuerier) {
	handler := HandleFunc(aq)
	req, err := http.NewRequest(http.MethodGet, tc.query, nil)
	assert.Nil(t, err)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, tc.expectedStatus, recorder.Code, tc.test)

	if tc.expectedStatus == http.StatusOK {
		var received Response
		err = json.Unmarshal(recorder.Body.Bytes(), &received)
		assert.Nil(t, err)
		assert.Equal(t, testResponse, received)
	}
}
