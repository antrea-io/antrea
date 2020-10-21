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

package v1beta1

import (
	"fmt"

	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
)

func init() {
	localSchemeBuilder.Register(addConversionFuncs)
}

// addConversionFuncs adds non-generated conversion functions to the given scheme.
func addConversionFuncs(scheme *runtime.Scheme) error {
	for _, kind := range []string{"AppliedToGroup", "AddressGroup", "NetworkPolicy"} {
		err := scheme.AddFieldLabelConversionFunc(SchemeGroupVersion.WithKind(kind),
			func(label, value string) (string, string, error) {
				switch label {
				// Antrea Agents select resources by nodeName.
				case "metadata.name", "nodeName":
					return label, value, nil
				default:
					return "", "", fmt.Errorf("field label not supported: %s", label)
				}
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func Convert_v1beta1_GroupMember_To_controlplane_GroupMember(in *GroupMember, out *controlplane.GroupMember, s conversion.Scope) error {
	if in.Pod != nil {
		out.Pod = &controlplane.PodReference{
			Name:      in.Pod.Name,
			Namespace: in.Pod.Namespace,
		}
	}
	if in.ExternalEntity != nil {
		out.ExternalEntity = &controlplane.ExternalEntityReference{
			Name:      in.ExternalEntity.Name,
			Namespace: in.ExternalEntity.Namespace,
		}
	}
	var ports []controlplane.NamedPort
	ips := make([]controlplane.IPAddress, len(in.Endpoints))
	for i, ep := range in.Endpoints {
		if i == 0 {
			for _, p := range ep.Ports {
				ports = append(ports, controlplane.NamedPort{
					Protocol: controlplane.Protocol(p.Protocol), Port: p.Port, Name: p.Name,
				})
			}
		}
		ips[i] = controlplane.IPAddress(ep.IP)
	}
	out.Ports = ports
	out.IPs = ips
	return nil
}

func Convert_controlplane_GroupMember_To_v1beta1_GroupMember(in *controlplane.GroupMember, out *GroupMember, s conversion.Scope) error {
	if in.Pod != nil {
		out.Pod = &PodReference{
			Name:      in.Pod.Name,
			Namespace: in.Pod.Namespace,
		}
	}
	if in.ExternalEntity != nil {
		out.ExternalEntity = &ExternalEntityReference{
			Name:      in.ExternalEntity.Name,
			Namespace: in.ExternalEntity.Namespace,
		}
	}
	var ports []NamedPort
	for _, p := range in.Ports {
		ports = append(ports, NamedPort{
			Protocol: Protocol(p.Protocol), Port: p.Port, Name: p.Name,
		})
	}
	endpoints := make([]Endpoint, len(in.IPs))
	for i, ip := range in.IPs {
		endpoints[i] = Endpoint{
			IP:    IPAddress(ip),
			Ports: ports,
		}
	}
	out.Endpoints = endpoints
	return nil
}
