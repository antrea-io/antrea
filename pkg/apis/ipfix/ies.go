// Copyright 2025 Antrea Authors
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

package ipfix

import (
	"iter"

	"github.com/vmware/go-ipfix/pkg/registry"
)

type IPFamilyType string

const (
	IPFamilyBoth IPFamilyType = ""
	IPFamilyIPv4 IPFamilyType = "IPv4"
	IPFamilyIPv6 IPFamilyType = "IPv6"
)

type InfoElement struct {
	Name           string
	EnterpriseName string
	EnterpriseID   uint32
	IPFamily       IPFamilyType
}

// AllInfoElements is the ordered list of all Information Elements exported by the FlowExporter.
// Only add new elements to the end of this list!
// Prefer
var AllInfoElements = []InfoElement{
	// IANA
	{Name: "flowStartSeconds", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "flowEndSeconds", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "flowEndReason", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "sourceTransportPort", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "destinationTransportPort", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "protocolIdentifier", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "packetTotalCount", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "octetTotalCount", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "packetDeltaCount", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "octetDeltaCount", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID},
	{Name: "sourceIPv4Address", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID, IPFamily: IPFamilyIPv4},
	{Name: "destinationIPv4Address", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID, IPFamily: IPFamilyIPv4},
	{Name: "sourceIPv6Address", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID, IPFamily: IPFamilyIPv6},
	{Name: "destinationIPv6Address", EnterpriseName: "IANA", EnterpriseID: registry.IANAEnterpriseID, IPFamily: IPFamilyIPv6},

	// ReverseIANA
	{Name: "reversePacketTotalCount", EnterpriseName: "ReverseIANA", EnterpriseID: registry.IANAReversedEnterpriseID},
	{Name: "reverseOctetTotalCount", EnterpriseName: "ReverseIANA", EnterpriseID: registry.IANAReversedEnterpriseID},
	{Name: "reversePacketDeltaCount", EnterpriseName: "ReverseIANA", EnterpriseID: registry.IANAReversedEnterpriseID},
	{Name: "reverseOctetDeltaCount", EnterpriseName: "ReverseIANA", EnterpriseID: registry.IANAReversedEnterpriseID},

	// Antrea
	{Name: "sourcePodName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "sourcePodNamespace", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "sourceNodeName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "destinationPodName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "destinationPodNamespace", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "destinationNodeName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "destinationServicePort", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "destinationServicePortName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "ingressNetworkPolicyName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "ingressNetworkPolicyNamespace", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "ingressNetworkPolicyType", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "ingressNetworkPolicyRuleName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "ingressNetworkPolicyRuleAction", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressNetworkPolicyName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressNetworkPolicyNamespace", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressNetworkPolicyType", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressNetworkPolicyRuleName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressNetworkPolicyRuleAction", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "tcpState", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "flowType", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressIP", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "appProtocolName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "httpVals", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "egressNodeName", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID},
	{Name: "destinationClusterIPv4", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID, IPFamily: IPFamilyIPv4},
	{Name: "destinationClusterIPv6", EnterpriseName: "Antrea", EnterpriseID: registry.AntreaEnterpriseID, IPFamily: IPFamilyIPv6},
}

// AllInfoElementsIter returns an iter.Seq2 to iterate over the information elements for IPv4 or
// IPv6 flows.
func AllInfoElementsIter(isIPv6 bool) iter.Seq2[int, InfoElement] {
	return func(yield func(int, InfoElement) bool) {
		idx := 0
		for _, ie := range AllInfoElements {
			if (ie.IPFamily == IPFamilyIPv4 && isIPv6) || (ie.IPFamily == IPFamilyIPv6 && !isIPv6) {
				continue
			}
			if !yield(idx, ie) {
				return
			}
			idx++
		}
	}
}
