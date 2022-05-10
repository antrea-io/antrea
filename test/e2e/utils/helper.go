// Copyright 2022 Antrea Authors
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

package utils

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type AntreaPolicyProtocol string

const (
	ProtocolTCP  AntreaPolicyProtocol = "TCP"
	ProtocolUDP  AntreaPolicyProtocol = "UDP"
	ProtocolSCTP AntreaPolicyProtocol = "SCTP"
	ProtocolICMP AntreaPolicyProtocol = "ICMP"
)

func AntreaPolicyProtocolToK8sProtocol(antreaProtocol AntreaPolicyProtocol) (v1.Protocol, error) {
	switch antreaProtocol {
	case ProtocolTCP:
		return v1.ProtocolTCP, nil
	case ProtocolUDP:
		return v1.ProtocolUDP, nil
	case ProtocolSCTP:
		return v1.ProtocolSCTP, nil
	default:
		return "", fmt.Errorf("k8s doesn't support protocol %s", antreaProtocol)
	}
}

func GenPortsOrProtocols(protoc AntreaPolicyProtocol, port *int32, portName *string, endPort, icmpType, icmpCode *int32) ([]crdv1alpha1.NetworkPolicyPort, []crdv1alpha1.NetworkPolicyProtocol) {
	if protoc == ProtocolICMP {
		return nil, []crdv1alpha1.NetworkPolicyProtocol{
			{
				ICMP: &crdv1alpha1.ICMPProtocol{
					ICMPType: icmpType,
					ICMPCode: icmpCode,
				},
			},
		}
	}
	var ports []crdv1alpha1.NetworkPolicyPort
	k8sProtocol, _ := AntreaPolicyProtocolToK8sProtocol(protoc)
	if port != nil && portName != nil {
		panic("specify portname or port, not both")
	}
	if portName != nil {
		ports = []crdv1alpha1.NetworkPolicyPort{
			{
				Port:     &intstr.IntOrString{Type: intstr.String, StrVal: *portName},
				Protocol: &k8sProtocol,
			},
		}
	}
	if port != nil || endPort != nil {
		var pVal *intstr.IntOrString
		if port != nil {
			pVal = &intstr.IntOrString{IntVal: *port}
		}
		ports = []crdv1alpha1.NetworkPolicyPort{
			{
				Port:     pVal,
				EndPort:  endPort,
				Protocol: &k8sProtocol,
			},
		}
	}
	return ports, nil
}
