// Copyright 2025 Antrea Authors.
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

package filter

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

var inverseServiceProtocolMap = map[corev1.Protocol]uint8{
	corev1.ProtocolTCP:  6,
	corev1.ProtocolUDP:  17,
	corev1.ProtocolSCTP: 132,
}

// A set of protocols to filter records by
type ProtocolFilter struct {
	ipProtocolNumbers sets.Set[uint8]
}

// For a given protocol, return true if the protocol is allowed
func (p ProtocolFilter) Allow(protocol uint8) bool {
	return p.ipProtocolNumbers == nil || p.ipProtocolNumbers.Has(protocol)
}

// Returns a new ProtocolFilter with only valid protocols and
// Logs a message if invalid or unsupported protocols are found.
// When protocols is nil, all protocols will be allowed. When it is empty,
// all protocols are not allowed.
func NewProtocolFilter(protocols []string) ProtocolFilter {
	if protocols == nil {
		return ProtocolFilter{}
	}
	validatedProtocols := sets.Set[uint8]{}
	invalidProtocols := []string{}
	for _, protocol := range protocols {
		protocolNumber, ok := inverseServiceProtocolMap[corev1.Protocol(strings.ToUpper(protocol))]
		if !ok {
			invalidProtocols = append(invalidProtocols, protocol)
		} else {
			validatedProtocols.Insert(protocolNumber)
		}
	}

	if len(invalidProtocols) > 0 {
		klog.InfoS("Found unsupported protocol(s) in protocolFilter, refer to the docs for supported protocols", "invalid protocols in protocolFilter", strings.Join(invalidProtocols, ","))
	}

	if len(protocols) == 0 {
		klog.InfoS("filterProtocol is empty and nothing will be exported")
	}

	return ProtocolFilter{
		ipProtocolNumbers: validatedProtocols,
	}
}
