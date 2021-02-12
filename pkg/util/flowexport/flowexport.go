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
	"regexp"
	"strings"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/flowaggregator"
)

// ParseFlowCollectorAddr parses the flow collector address input for flow exporter and aggregator
func ParseFlowCollectorAddr(addr string, defaultPort string, defaultProtocol string) (string, string, string, error) {
	var strSlice []string
	var host, port, proto string
	match, err := regexp.MatchString("\\[.*\\]:.*", addr)
	if err != nil {
		return host, port, proto, fmt.Errorf("failed to parse FlowCollectorAddr: %s", addr)
	}
	if match {
		idx := strings.Index(addr, "]")
		strSlice = append(strSlice, addr[:idx+1])
		strSlice = append(strSlice, strings.Split(addr[idx+2:], ":")...)
	} else {
		strSlice = strings.Split(addr, ":")
	}
	if len(strSlice) == 3 {
		host = strSlice[0]
		if strSlice[1] == "" {
			port = defaultPort
		} else {
			port = strSlice[1]
		}
		if (strSlice[2] != "udp") && (strSlice[2] != "tcp") {
			return host, port, proto, fmt.Errorf("connection over %s transport proto is not supported", strSlice[2])
		}
		proto = strSlice[2]
	} else if len(strSlice) == 2 {
		host = strSlice[0]
		port = strSlice[1]
		proto = defaultProtocol
	} else if len(strSlice) == 1 {
		host = strSlice[0]
		port = defaultPort
		proto = defaultProtocol
	} else {
		return host, port, proto, fmt.Errorf("flow collector address is given in invalid format")
	}
	return host, port, proto, nil
}

// ParseFlowIntervalString parses the flow poll or export interval input string for flow exporter and aggregator
func ParseFlowIntervalString(intervalString string) (time.Duration, error) {
	flowInterval, err := time.ParseDuration(intervalString)
	if err != nil {
		return 0, fmt.Errorf("flow interval string is not provided in right format")
	}
	if flowInterval < time.Second {
		return 0, fmt.Errorf("flow interval should be greater than or equal to one second")
	}
	return flowInterval, nil
}

// ParseTransportProtocol parses the transport protocol input for the flow aggregator
func ParseTransportProtocol(trasnportProtocolInput flowaggregator.AggregatorTransportProtocol) (flowaggregator.AggregatorTransportProtocol, error) {
	upperProtocolInput := flowaggregator.AggregatorTransportProtocol(strings.ToUpper(string(trasnportProtocolInput)))
	if (upperProtocolInput != flowaggregator.AggregatorTransportProtocolTLS) && (upperProtocolInput != flowaggregator.AggregatorTransportProtocolUDP) && (upperProtocolInput != flowaggregator.AggregatorTransportProtocolTCP) {
		return "", fmt.Errorf("collecting process over %s proto is not supported", trasnportProtocolInput)
	}
	return upperProtocolInput, nil
}
