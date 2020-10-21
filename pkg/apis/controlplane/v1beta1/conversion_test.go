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

func TestConvertBetweenv1beta1AndControlplaneGroupMember(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, RegisterConversions(scheme))

	v1b1Ports := []NamedPort{
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
	cpPorts := []controlplane.NamedPort{
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
	v1b1GroupMember := GroupMember{
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
	cpGroupMember := controlplane.GroupMember{
		ExternalEntity: &controlplane.ExternalEntityReference{Name: "test-ee", Namespace: "test-ns"},
		IPs: []controlplane.IPAddress{
			controlplane.IPAddress(net.ParseIP("127.0.0.1")),
			controlplane.IPAddress(net.ParseIP("127.0.0.2")),
		},
		Ports: cpPorts,
	}

	var convertedCPGroupMember controlplane.GroupMember
	var convertedV1B1GroupMember GroupMember
	require.NoError(t,
		Convert_controlplane_GroupMember_To_v1beta1_GroupMember(&cpGroupMember, &convertedV1B1GroupMember, nil))
	assert.Equal(t, v1b1GroupMember, convertedV1B1GroupMember, "controlplane.GroupMember -> v1beta1.GroupMember")
	require.NoError(t,
		Convert_v1beta1_GroupMember_To_controlplane_GroupMember(&v1b1GroupMember, &convertedCPGroupMember, nil))
	assert.Equal(t, cpGroupMember, convertedCPGroupMember, "v1beta1.GroupMember -> controlplane.GroupMember")
}
