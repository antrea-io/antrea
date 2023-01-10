// Copyright 2021 Antrea Authors
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

package flowexport

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
)

const (
	defaultFlowCollectorProtocol = "tcp"
	defaultFlowCollectorPort     = "4739"
)

func TestParseFlowCollectorAddr(t *testing.T) {
	testcases := []struct {
		// input
		addr string
		// expectations
		expectedHost  string
		expectedPort  string
		expectedProto string
		expectedError error
	}{
		{
			addr:          "1.2.3.4:80:udp",
			expectedHost:  "1.2.3.4",
			expectedPort:  "80",
			expectedProto: "udp",
			expectedError: nil,
		},
		{
			addr:          "1.2.3.4:80",
			expectedHost:  "1.2.3.4",
			expectedPort:  "80",
			expectedProto: defaultFlowCollectorProtocol,
			expectedError: nil,
		},
		{
			addr:          "[fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:80:tcp",
			expectedHost:  "fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			expectedPort:  "80",
			expectedProto: "tcp",
			expectedError: nil,
		},
		{
			addr:          "flow-aggregator/flow-aggregator::tcp",
			expectedHost:  "flow-aggregator/flow-aggregator",
			expectedPort:  defaultFlowCollectorPort,
			expectedProto: "tcp",
			expectedError: nil,
		},
		{
			addr:          ":abbbsctp::",
			expectedHost:  "",
			expectedPort:  "",
			expectedProto: "",
			expectedError: fmt.Errorf("flow collector address is given in invalid format"),
		},
		{
			addr:          "1.2.3.4:80:sctp",
			expectedHost:  "",
			expectedPort:  "",
			expectedProto: "",
			expectedError: fmt.Errorf("connection over %s transport proto is not supported", "sctp"),
		},
	}
	for _, tc := range testcases {
		host, port, proto, err := ParseFlowCollectorAddr(tc.addr, defaultFlowCollectorPort, defaultFlowCollectorProtocol)
		if tc.expectedError != nil {
			assert.Equal(t, tc.expectedError, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedHost, host)
			assert.Equal(t, tc.expectedPort, port)
			assert.Equal(t, tc.expectedProto, proto)
		}
	}
}

func TestParseFlowIntervalString(t *testing.T) {
	testcases := []struct {
		// input
		intervalString string
		// expectations
		expectedFlowInterval time.Duration
		expectedError        error
	}{
		{
			intervalString:       "5s",
			expectedFlowInterval: 5 * time.Second,
			expectedError:        nil,
		},
		{
			intervalString:       "5ss",
			expectedFlowInterval: 0,
			expectedError:        fmt.Errorf("flow interval string is not provided in right format"),
		},
		{
			intervalString:       "1ms",
			expectedFlowInterval: 0,
			expectedError:        fmt.Errorf("flow interval should be greater than or equal to one second"),
		},
	}
	for _, tc := range testcases {
		flowInterval, err := ParseFlowIntervalString(tc.intervalString)
		if tc.expectedError != nil {
			assert.Equal(t, tc.expectedError, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedFlowInterval, flowInterval)
		}
	}
}

func TestParseTransportProtocol(t *testing.T) {
	testcases := []struct {
		// input
		transportProtocolInput flowaggregatorconfig.AggregatorTransportProtocol
		// expectations
		expectedTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol
		expectedError             error
	}{
		{
			transportProtocolInput:    "tcp",
			expectedTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolTCP,
			expectedError:             nil,
		},
		{
			transportProtocolInput:    "UDP",
			expectedTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolUDP,
			expectedError:             nil,
		},
		{
			transportProtocolInput:    "Tcp",
			expectedTransportProtocol: flowaggregatorconfig.AggregatorTransportProtocolTCP,
			expectedError:             nil,
		},
		{
			transportProtocolInput:    "sctp",
			expectedTransportProtocol: "",
			expectedError:             fmt.Errorf("collecting process over %s proto is not supported", "sctp"),
		},
	}
	for _, tc := range testcases {
		transportProtocol, err := ParseTransportProtocol(tc.transportProtocolInput)
		if tc.expectedError != nil {
			assert.Equal(t, tc.expectedError, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedTransportProtocol, transportProtocol)
		}
	}
}
