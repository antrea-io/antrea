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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
)

var (
	cpPorts = []controlplane.NamedPort{
		{
			Port:     80,
			Name:     "HTTP",
			Protocol: controlplane.ProtocolTCP,
		},
		{
			Port:     443,
			Name:     "HTTP",
			Protocol: controlplane.ProtocolTCP,
		},
	}
	cpGroupMember = controlplane.GroupMember{
		ExternalEntity: &controlplane.ExternalEntityReference{
			Name: "test-ee", Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{
			controlplane.IPAddress(net.ParseIP("127.0.0.1")),
			controlplane.IPAddress(net.ParseIP("127.0.0.2")),
		},
		Ports: cpPorts,
	}
	cpGroupMember2 = controlplane.GroupMember{
		ExternalEntity: &controlplane.ExternalEntityReference{
			Name: "test-ee2", Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{
			controlplane.IPAddress(net.ParseIP("127.0.0.3")),
			controlplane.IPAddress(net.ParseIP("127.0.0.4")),
		},
		Ports: cpPorts,
	}
	cpPodGroupMember = controlplane.GroupMember{
		Pod: &controlplane.PodReference{
			Name: "test-pod", Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{
			controlplane.IPAddress(net.ParseIP("10.0.0.1")),
		},
		Ports: cpPorts,
	}
	cpPodGroupMember2 = controlplane.GroupMember{
		Pod: &controlplane.PodReference{
			Name: "test-pod2", Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{
			controlplane.IPAddress(net.ParseIP("10.0.0.2")),
		},
		Ports: cpPorts,
	}
	v1b1Ports = []NamedPort{
		{
			Port:     80,
			Name:     "HTTP",
			Protocol: ProtocolTCP,
		},
		{
			Port:     443,
			Name:     "HTTP",
			Protocol: ProtocolTCP,
		},
	}
	v1b1GroupMember = GroupMember{
		ExternalEntity: &ExternalEntityReference{"test-ee", "test-ns"},
		Endpoints: []Endpoint{
			{
				IP:    IPAddress(net.ParseIP("127.0.0.1")),
				Ports: v1b1Ports,
			},
			{
				IP:    IPAddress(net.ParseIP("127.0.0.2")),
				Ports: v1b1Ports,
			},
		},
	}
	v1b1GroupMember2 = GroupMember{
		ExternalEntity: &ExternalEntityReference{"test-ee2", "test-ns"},
		Endpoints: []Endpoint{
			{
				IP:    IPAddress(net.ParseIP("127.0.0.3")),
				Ports: v1b1Ports,
			},
			{
				IP:    IPAddress(net.ParseIP("127.0.0.4")),
				Ports: v1b1Ports,
			},
		},
	}
	v1b1GroupMemberPod = GroupMemberPod{
		Pod:   &PodReference{"test-pod", "test-ns"},
		IP:    IPAddress(net.ParseIP("10.0.0.1")),
		Ports: v1b1Ports,
	}
	v1b1GroupMemberPod2 = GroupMemberPod{
		Pod:   &PodReference{"test-pod2", "test-ns"},
		IP:    IPAddress(net.ParseIP("10.0.0.2")),
		Ports: v1b1Ports,
	}
)

func TestConvertBetweenV1beta1AndControlplaneGroupMember(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	var convertedCPGroupMember controlplane.GroupMember
	var convertedV1B1GroupMember GroupMember
	require.NoError(t,
		Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&cpGroupMember, &convertedV1B1GroupMember, nil))
	assert.Equal(t, v1b1GroupMember, convertedV1B1GroupMember, "controlplane.GroupMember -> v1beta1.GroupMember")
	require.NoError(t,
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&v1b1GroupMember, &convertedCPGroupMember, nil))
	assert.Equal(t, cpGroupMember, convertedCPGroupMember, "v1beta1.GroupMember -> controlplane.GroupMember")
}

func TestConvertBetweenV1beta1GroupMemberPodAndControlplaneGroupMember(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	var convertedCPGroupMember controlplane.GroupMember
	var convertedV1B1GroupMemberPod GroupMemberPod
	err := Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&cpGroupMember, &convertedV1B1GroupMemberPod, true)
	require.Errorf(t, err, "should not be able to convert group member with multiple IPs to GroupMemberPod")
	require.NoError(t,
		Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&cpPodGroupMember, &convertedV1B1GroupMemberPod, true))
	assert.Equal(t, v1b1GroupMemberPod, convertedV1B1GroupMemberPod, "controlplane.GroupMember -> v1beta1.GroupMemberPod")
	var convertedV1B1GroupMemberPodWithoutPodRef GroupMemberPod
	require.NoError(t,
		Convert_controlplane_GroupMember_To_v1beta1_GroupMemberPod(&cpPodGroupMember, &convertedV1B1GroupMemberPodWithoutPodRef, false))
	expectedV1b1GroupMemberPodWithoutPodRef := *v1b1GroupMemberPod.DeepCopy()
	expectedV1b1GroupMemberPodWithoutPodRef.Pod = nil
	assert.Equal(t, expectedV1b1GroupMemberPodWithoutPodRef, convertedV1B1GroupMemberPodWithoutPodRef, "controlplane.GroupMember -> v1beta1.GroupMemberPod")
	require.NoError(t,
		Convert_v1beta1_GroupMemberPod_To_controlplane_GroupMember(&v1b1GroupMemberPod, &convertedCPGroupMember, nil))
	assert.Equal(t, cpPodGroupMember, convertedCPGroupMember, "v1beta1.GroupMemberPod -> controlplane.GroupMember")
}

func TestConvertBetweenV1beta1AndControlplaneAddressGroup(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	v1b1AddressGroup := AddressGroup{
		Pods:         []GroupMemberPod{v1b1GroupMemberPod},
		GroupMembers: []GroupMember{v1b1GroupMember},
	}
	cpAddressGroup := controlplane.AddressGroup{
		GroupMembers: []controlplane.GroupMember{cpPodGroupMember, cpGroupMember},
	}
	var convertedCPAddressGroup controlplane.AddressGroup
	var convertedV1B1AddressGroup AddressGroup
	expectedV1B1AddressGroup := v1b1AddressGroup.DeepCopy()
	expectedV1B1AddressGroup.Pods[0].Pod = nil
	require.NoError(t,
		Convert_controlplane_AddressGroup_To_v1beta1_AddressGroup(&cpAddressGroup, &convertedV1B1AddressGroup, nil))
	assert.Equal(t, *expectedV1B1AddressGroup, convertedV1B1AddressGroup)
	require.NoError(t,
		Convert_v1beta1_AddressGroup_To_controlplane_AddressGroup(&v1b1AddressGroup, &convertedCPAddressGroup, nil))
	assert.Equal(t, cpAddressGroup, convertedCPAddressGroup)
}

func TestConvertBetweenV1beta1AndControlplaneAddressGroupPatch(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	v1b1AddressGroupPatch := AddressGroupPatch{
		AddedPods:           []GroupMemberPod{v1b1GroupMemberPod},
		RemovedPods:         []GroupMemberPod{v1b1GroupMemberPod2},
		AddedGroupMembers:   []GroupMember{v1b1GroupMember},
		RemovedGroupMembers: []GroupMember{v1b1GroupMember2},
	}
	cpAddressGroupPatch := controlplane.AddressGroupPatch{
		AddedGroupMembers:   []controlplane.GroupMember{cpPodGroupMember, cpGroupMember},
		RemovedGroupMembers: []controlplane.GroupMember{cpPodGroupMember2, cpGroupMember2},
	}
	var convertedCPPatch controlplane.AddressGroupPatch
	var convertedV1B1Patch AddressGroupPatch
	expectedV1B1AddressGroupPatch := v1b1AddressGroupPatch.DeepCopy()
	expectedV1B1AddressGroupPatch.AddedPods[0].Pod = nil
	expectedV1B1AddressGroupPatch.RemovedPods[0].Pod = nil
	require.NoError(t,
		Convert_controlplane_AddressGroupPatch_To_v1beta1_AddressGroupPatch(&cpAddressGroupPatch, &convertedV1B1Patch, nil))
	assert.Equal(t, *expectedV1B1AddressGroupPatch, convertedV1B1Patch)
	require.NoError(t,
		Convert_v1beta1_AddressGroupPatch_To_controlplane_AddressGroupPatch(&v1b1AddressGroupPatch, &convertedCPPatch, nil))
	assert.Equal(t, cpAddressGroupPatch, convertedCPPatch)
}

func TestConvertBetweenV1beta1AndControlplaneAppliedToGroup(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	v1b1AppliedToGroup := AppliedToGroup{
		Pods:         []GroupMemberPod{v1b1GroupMemberPod},
		GroupMembers: []GroupMember{v1b1GroupMember},
	}
	cpAppliedToGroup := controlplane.AppliedToGroup{
		GroupMembers: []controlplane.GroupMember{cpPodGroupMember, cpGroupMember},
	}
	var convertedCPAppliedToGroup controlplane.AppliedToGroup
	var convertedV1B1AppliedToGroup AppliedToGroup
	require.NoError(t,
		Convert_controlplane_AppliedToGroup_To_v1beta1_AppliedToGroup(&cpAppliedToGroup, &convertedV1B1AppliedToGroup, nil))
	assert.Equal(t, v1b1AppliedToGroup, convertedV1B1AppliedToGroup)
	require.NoError(t,
		Convert_v1beta1_AppliedToGroup_To_controlplane_AppliedToGroup(&v1b1AppliedToGroup, &convertedCPAppliedToGroup, nil))
	assert.Equal(t, cpAppliedToGroup, convertedCPAppliedToGroup)
}

func TestConvertBetweenV1beta1AndControlplaneAppliedToGroupPatch(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	v1b1AppliedToGroupPatch := AppliedToGroupPatch{
		AddedPods:           []GroupMemberPod{v1b1GroupMemberPod},
		RemovedPods:         []GroupMemberPod{v1b1GroupMemberPod2},
		AddedGroupMembers:   []GroupMember{v1b1GroupMember},
		RemovedGroupMembers: []GroupMember{v1b1GroupMember2},
	}
	cpAppliedToGroupPatch := controlplane.AppliedToGroupPatch{
		AddedGroupMembers:   []controlplane.GroupMember{cpPodGroupMember, cpGroupMember},
		RemovedGroupMembers: []controlplane.GroupMember{cpPodGroupMember2, cpGroupMember2},
	}
	var convertedCPPatch controlplane.AppliedToGroupPatch
	var convertedV1B1Patch AppliedToGroupPatch
	require.NoError(t,
		Convert_controlplane_AppliedToGroupPatch_To_v1beta1_AppliedToGroupPatch(&cpAppliedToGroupPatch, &convertedV1B1Patch, nil))
	assert.Equal(t, v1b1AppliedToGroupPatch, convertedV1B1Patch)
	require.NoError(t,
		Convert_v1beta1_AppliedToGroupPatch_To_controlplane_AppliedToGroupPatch(&v1b1AppliedToGroupPatch, &convertedCPPatch, nil))
	assert.Equal(t, cpAppliedToGroupPatch, convertedCPPatch)
}
