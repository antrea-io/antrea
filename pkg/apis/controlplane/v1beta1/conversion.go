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

func Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(in *GroupMemberPod, out *controlplane.GroupMember, s conversion.Scope) error {
	out.Pod = &controlplane.PodReference{
		Name:      in.Pod.Name,
		Namespace: in.Pod.Namespace,
	}
	out.IPs = []controlplane.IPAddress{controlplane.IPAddress(in.IP)}
	ports := make([]controlplane.NamedPort, len(in.Ports))
	for i, p := range in.Ports {
		ports[i] = controlplane.NamedPort{
			Protocol: controlplane.Protocol(p.Protocol), Port: p.Port, Name: p.Name,
		}
	}
	out.Ports = ports
	return nil
}

func Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(in *controlplane.GroupMember, out *GroupMemberPod, s conversion.Scope) error {
	if in.Pod == nil || len(in.IPs) > 1 {
		return fmt.Errorf("cannot convert ExternalEntity or dual stack Pod into GroupMemberPod")
	}
	out.Pod = &PodReference{
		Name:      in.Pod.Name,
		Namespace: in.Pod.Namespace,
	}
	if len(in.IPs) > 0 {
		out.IP = IPAddress(in.IPs[0])
	}
	ports := make([]NamedPort, len(in.Ports))
	for i, p := range in.Ports {
		ports[i] = NamedPort{
			Protocol: Protocol(p.Protocol), Port: p.Port, Name: p.Name,
		}
	}
	out.Ports = ports
	return nil
}

func Convert_v1beta1_AddressGroup_To_controlplane_AddressGroup(in *AddressGroup, out *controlplane.AddressGroup, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var groupMembers []controlplane.GroupMember
	for i := range in.Pods {
		p := in.Pods[i]
		var podMember controlplane.GroupMember
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&p, &podMember, nil)
		groupMembers = append(groupMembers, podMember)
	}
	for i := range in.GroupMembers {
		m := in.GroupMembers[i]
		var member controlplane.GroupMember
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&m, &member, nil)
		groupMembers = append(groupMembers, member)
	}
	out.GroupMembers = groupMembers
	return nil
}

func Convert_controlplane_AddressGroup_To_v1beta1_AddressGroup(in *controlplane.AddressGroup, out *AddressGroup, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var groupMembers []GroupMember
	var pods []GroupMemberPod
	for i := range in.GroupMembers {
		m := in.GroupMembers[i]
		if m.Pod != nil {
			var pod GroupMemberPod
			if err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&m, &pod, nil); err != nil {
				return err
			}
			pods = append(pods, pod)
		} else if m.ExternalEntity != nil {
			var ee GroupMember
			Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&m, &ee, nil)
			groupMembers = append(groupMembers, ee)
		}
	}
	out.Pods = pods
	out.GroupMembers = groupMembers
	return nil
}

func Convert_v1beta1_AddressGroupPatch_To_controlplane_AddressGroupPatch(in *AddressGroupPatch, out *controlplane.AddressGroupPatch, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var addedMembers, removedMembers []controlplane.GroupMember
	for i := range in.AddedPods {
		p := in.AddedPods[i]
		var podMember controlplane.GroupMember
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&p, &podMember, nil)
		addedMembers = append(addedMembers, podMember)
	}
	for i := range in.RemovedPods {
		p := in.RemovedPods[i]
		var podMember controlplane.GroupMember
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&p, &podMember, nil)
		removedMembers = append(removedMembers, podMember)
	}
	for i := range in.AddedGroupMembers {
		m := in.AddedGroupMembers[i]
		var member controlplane.GroupMember
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&m, &member, nil)
		addedMembers = append(addedMembers, member)
	}
	for i := range in.RemovedGroupMembers {
		m := in.RemovedGroupMembers[i]
		var member controlplane.GroupMember
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&m, &member, nil)
		removedMembers = append(removedMembers, member)
	}
	out.AddedGroupMembers = addedMembers
	out.RemovedGroupMembers = removedMembers
	return nil
}

func Convert_controlplane_AddressGroupPatch_To_v1beta1_AddressGroupPatch(in *controlplane.AddressGroupPatch, out *AddressGroupPatch, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var addedPods, removedPods []GroupMemberPod
	var addedMembers, removedMembers []GroupMember
	for i := range in.AddedGroupMembers {
		m := in.AddedGroupMembers[i]
		if m.Pod != nil {
			var pod GroupMemberPod
			if err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&m, &pod, nil); err != nil {
				return err
			}
			addedPods = append(addedPods, pod)
		} else if m.ExternalEntity != nil {
			var ee GroupMember
			Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&m, &ee, nil)
			addedMembers = append(addedMembers, ee)
		}
	}
	for i := range in.RemovedGroupMembers {
		m := in.RemovedGroupMembers[i]
		if m.Pod != nil {
			var pod GroupMemberPod
			if err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&m, &pod, nil); err != nil {
				return err
			}
			removedPods = append(removedPods, pod)
		} else if m.ExternalEntity != nil {
			var ee GroupMember
			Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&m, &ee, nil)
			removedMembers = append(removedMembers, ee)
		}
	}
	out.AddedPods = addedPods
	out.RemovedPods = removedPods
	out.AddedGroupMembers = addedMembers
	out.RemovedGroupMembers = removedMembers
	return nil
}

func Convert_v1beta1_AppliedToGroup_To_controlplane_AppliedToGroup(in *AppliedToGroup, out *controlplane.AppliedToGroup, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var groupMembers []controlplane.GroupMember
	for i := range in.Pods {
		p := in.Pods[i]
		var podMember controlplane.GroupMember
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&p, &podMember, nil)
		groupMembers = append(groupMembers, podMember)
	}
	for i := range in.GroupMembers {
		m := in.GroupMembers[i]
		var member controlplane.GroupMember
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&m, &member, nil)
		groupMembers = append(groupMembers, member)
	}
	out.GroupMembers = groupMembers
	return nil
}

func Convert_controlplane_AppliedToGroup_To_v1beta1_AppliedToGroup(in *controlplane.AppliedToGroup, out *AppliedToGroup, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var groupMembers []GroupMember
	var pods []GroupMemberPod
	for i := range in.GroupMembers {
		m := in.GroupMembers[i]
		if m.Pod != nil {
			var pod GroupMemberPod
			if err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&m, &pod, nil); err != nil {
				return err
			}
			pods = append(pods, pod)
		} else if m.ExternalEntity != nil {
			var ee GroupMember
			Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&m, &ee, nil)
			groupMembers = append(groupMembers, ee)
		}
	}
	out.Pods = pods
	out.GroupMembers = groupMembers
	return nil
}

func Convert_v1beta1_AppliedToGroupPatch_To_controlplane_AppliedToGroupPatch(in *AppliedToGroupPatch, out *controlplane.AppliedToGroupPatch, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var addedMembers []controlplane.GroupMember
	var removedMembers []controlplane.GroupMember
	for i := range in.AddedPods {
		p := in.AddedPods[i]
		var podMember controlplane.GroupMember
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&p, &podMember, nil)
		addedMembers = append(addedMembers, podMember)
	}
	for i := range in.RemovedPods {
		p := in.RemovedPods[i]
		var podMember controlplane.GroupMember
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&p, &podMember, nil)
		removedMembers = append(removedMembers, podMember)
	}
	for i := range in.AddedGroupMembers {
		m := in.AddedGroupMembers[i]
		var member controlplane.GroupMember
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&m, &member, nil)
		addedMembers = append(addedMembers, member)
	}
	for i := range in.RemovedGroupMembers {
		m := in.RemovedGroupMembers[i]
		var member controlplane.GroupMember
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&m, &member, nil)
		removedMembers = append(removedMembers, member)
	}
	out.AddedGroupMembers = addedMembers
	out.RemovedGroupMembers = removedMembers
	return nil
}

func Convert_controlplane_AppliedToGroupPatch_To_v1beta1_AppliedToGroupPatch(in *controlplane.AppliedToGroupPatch, out *AppliedToGroupPatch, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	var addedPods, removedPods []GroupMemberPod
	var addedMembers, removedMembers []GroupMember
	for i := range in.AddedGroupMembers {
		m := in.AddedGroupMembers[i]
		if m.Pod != nil {
			var pod GroupMemberPod
			if err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&m, &pod, nil); err != nil {
				return err
			}
			addedPods = append(addedPods, pod)
		} else if m.ExternalEntity != nil {
			var ee GroupMember
			Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&m, &ee, nil)
			addedMembers = append(addedMembers, ee)
		}
	}
	for i := range in.RemovedGroupMembers {
		m := in.RemovedGroupMembers[i]
		if m.Pod != nil {
			var pod GroupMemberPod
			if err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&m, &pod, nil); err != nil {
				return err
			}
			removedPods = append(removedPods, pod)
		} else if m.ExternalEntity != nil {
			var ee GroupMember
			Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&m, &ee, nil)
			removedMembers = append(removedMembers, ee)
		}
	}
	out.AddedPods = addedPods
	out.RemovedPods = removedPods
	out.AddedGroupMembers = addedMembers
	out.RemovedGroupMembers = removedMembers
	return nil
}
