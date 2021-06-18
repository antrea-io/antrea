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

package podinterface

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/interfacestore"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	queriertest "antrea.io/antrea/pkg/agent/querier/testing"
)

// There are 3 pod-interfaces:
// Two pod-interfaces have same podName: podNames[0] which are in namespaceA and namespaceB.
// Another pod-interface with podName: podNames[1] is in namespaceA.
var ipStrs = []string{
	"192.168.0.0",
	"192.168.0.1",
	"192.168.0.2",
}

var macStrs = []string{
	"00:00:00:00:00:00",
	"00:00:00:00:00:01",
	"00:00:00:00:00:02",
}

var macs = []net.HardwareAddr{
	parseMAC(macStrs[0]),
	parseMAC(macStrs[1]),
	parseMAC(macStrs[2]),
}

var podNames = []string{
	"pod0",
	"pod1",
}

var responses = []Response{
	{
		PodName:       podNames[0],
		PodNamespace:  "namespaceA",
		InterfaceName: "interface0",
		IPs:           []string{ipStrs[0]},
		MAC:           macStrs[0],
		PortUUID:      "portuuid0",
		OFPort:        0,
		ContainerID:   "containerid0",
	},
	{
		PodName:       podNames[1],
		PodNamespace:  "namespaceA",
		InterfaceName: "interface1",
		IPs:           []string{ipStrs[1]},
		MAC:           macStrs[1],
		PortUUID:      "portuuid1",
		OFPort:        1,
		ContainerID:   "containerid1",
	},
	{
		PodName:       podNames[0],
		PodNamespace:  "namespaceB",
		InterfaceName: "interface2",
		IPs:           []string{ipStrs[2]},
		MAC:           macStrs[2],
		PortUUID:      "portuuid2",
		OFPort:        2,
		ContainerID:   "containerid2",
	},
}

var testInterfaceConfigs = []*interfacestore.InterfaceConfig{
	{
		InterfaceName: "interface0",
		IPs:           []net.IP{net.ParseIP(ipStrs[0])},
		MAC:           macs[0],
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: "portuuid0",
			OFPort:   0,
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			ContainerID:  "containerid0",
			PodName:      podNames[0],
			PodNamespace: "namespaceA",
		},
	},
	{
		InterfaceName: "interface1",
		IPs:           []net.IP{net.ParseIP(ipStrs[1])},
		MAC:           macs[1],
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: "portuuid1",
			OFPort:   1,
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			ContainerID:  "containerid1",
			PodName:      podNames[1],
			PodNamespace: "namespaceA",
		},
	},
	{
		InterfaceName: "interface2",
		IPs:           []net.IP{net.ParseIP(ipStrs[2])},
		MAC:           macs[2],
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: "portuuid2",
			OFPort:   2,
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			ContainerID:  "containerid2",
			PodName:      podNames[0],
			PodNamespace: "namespaceB",
		},
	},
}

func parseMAC(mac string) net.HardwareAddr {
	res, _ := net.ParseMAC(mac)
	return res
}

func TestPodInterfaceQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := map[string]struct {
		query           string
		expectedStatus  int
		expectedContent []Response
	}{
		"Hit Pod interface query, namespace provided": {
			query:           "?name=pod1&&namespace=namespaceA",
			expectedStatus:  http.StatusOK,
			expectedContent: []Response{responses[1]},
		},
		"Miss Pod interface query, namespace provided": {
			query:           "?name=pod1&&namespace=namespaceB",
			expectedStatus:  http.StatusNotFound,
			expectedContent: []Response{},
		},
		"Hit Pod interface list query, namespace not provided": {
			query:           "?name=pod0",
			expectedStatus:  http.StatusOK,
			expectedContent: []Response{responses[0], responses[2]},
		},
		"Miss Pod interface list query, namespace not provided": {
			query:           "?name=pod2",
			expectedStatus:  http.StatusNotFound,
			expectedContent: []Response{},
		},
	}

	for k, tc := range testcases {
		i := interfacestoretest.NewMockInterfaceStore(ctrl)
		i.EXPECT().GetInterfacesByType(interfacestore.ContainerInterface).Return(testInterfaceConfigs).AnyTimes()

		q := queriertest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetInterfaceStore().Return(i).AnyTimes()
		handler := HandleFunc(q)

		req, err := http.NewRequest(http.MethodGet, tc.query, nil)
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, tc.expectedStatus, recorder.Code, k)

		if tc.expectedStatus == http.StatusOK {
			var received []Response
			err = json.Unmarshal(recorder.Body.Bytes(), &received)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedContent, received)
		}
	}
}

func TestPodInterfaceListQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := map[string]struct {
		query           string
		expectedStatus  int
		expectedContent []Response
	}{
		"Hit pod interfaces in a namespace list query": {
			query:           "?name=&&namespace=namespaceA",
			expectedStatus:  http.StatusOK,
			expectedContent: []Response{responses[0], responses[1]},
		},
		"Miss pod interfaces in a namespaces list query": {
			query:           "?name=&&namespace=namespaceC",
			expectedStatus:  http.StatusOK,
			expectedContent: []Response(nil),
		},
		"Hit all pod interfaces in all namespace list query": {
			query:           "?name=&&namespace=",
			expectedStatus:  http.StatusOK,
			expectedContent: []Response{responses[0], responses[1], responses[2]},
		},
	}

	for k, tc := range testcases {
		i := interfacestoretest.NewMockInterfaceStore(ctrl)
		i.EXPECT().GetInterfacesByType(interfacestore.ContainerInterface).Return(testInterfaceConfigs).AnyTimes()

		q := queriertest.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetInterfaceStore().Return(i).AnyTimes()
		handler := HandleFunc(q)

		req, err := http.NewRequest(http.MethodGet, tc.query, nil)
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, tc.expectedStatus, recorder.Code, k)

		if tc.expectedStatus == http.StatusOK {
			var received []Response
			err = json.Unmarshal(recorder.Body.Bytes(), &received)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedContent, received)
		}
	}
}
