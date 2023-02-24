// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/interfacestore"
)

func TestGetRejectType(t *testing.T) {
	tests := []struct {
		name               string
		isServiceTraffic   bool
		antreaProxyEnabled bool
		srcIsLocal         bool
		dstIsLocal         bool
		expectRejectType   RejectType
	}{
		{
			name:               "RejectPodLocal",
			isServiceTraffic:   false,
			antreaProxyEnabled: true,
			srcIsLocal:         true,
			dstIsLocal:         true,
			expectRejectType:   RejectPodLocal,
		},
		{
			name:               "RejectPodRemoteToLocal",
			isServiceTraffic:   false,
			antreaProxyEnabled: true,
			srcIsLocal:         false,
			dstIsLocal:         true,
			expectRejectType:   RejectPodRemoteToLocal,
		},
		{
			name:               "RejectPodLocalToRemote",
			isServiceTraffic:   false,
			antreaProxyEnabled: true,
			srcIsLocal:         true,
			dstIsLocal:         false,
			expectRejectType:   RejectPodLocalToRemote,
		},
		{
			name:               "RejectServiceLocal",
			isServiceTraffic:   true,
			antreaProxyEnabled: true,
			srcIsLocal:         true,
			dstIsLocal:         true,
			expectRejectType:   RejectServiceLocal,
		},
		{
			name:               "RejectServiceRemoteToLocal",
			isServiceTraffic:   true,
			antreaProxyEnabled: true,
			srcIsLocal:         false,
			dstIsLocal:         true,
			expectRejectType:   RejectServiceRemoteToLocal,
		},
		{
			name:               "RejectServiceLocalToRemote",
			isServiceTraffic:   true,
			antreaProxyEnabled: true,
			srcIsLocal:         true,
			dstIsLocal:         false,
			expectRejectType:   RejectServiceLocalToRemote,
		},
		{
			name:               "RejectNoAPServiceLocal",
			isServiceTraffic:   true,
			antreaProxyEnabled: false,
			srcIsLocal:         true,
			dstIsLocal:         true,
			expectRejectType:   RejectNoAPServiceLocal,
		},
		{
			name:               "RejectNoAPServiceRemoteToLocal",
			isServiceTraffic:   true,
			antreaProxyEnabled: false,
			srcIsLocal:         false,
			dstIsLocal:         true,
			expectRejectType:   RejectNoAPServiceRemoteToLocal,
		},
		{
			name:               "RejectServiceRemoteToExternal",
			isServiceTraffic:   true,
			antreaProxyEnabled: true,
			srcIsLocal:         false,
			dstIsLocal:         false,
			expectRejectType:   RejectServiceRemoteToExternal,
		},
		{
			name:               "Unsupported pod2pod remote2remote",
			isServiceTraffic:   false,
			antreaProxyEnabled: true,
			srcIsLocal:         false,
			dstIsLocal:         false,
			expectRejectType:   Unsupported,
		},
		{
			name:               "Unsupported noAP remote2remote",
			isServiceTraffic:   true,
			antreaProxyEnabled: false,
			srcIsLocal:         false,
			dstIsLocal:         false,
			expectRejectType:   Unsupported,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rejectType := getRejectType(tt.isServiceTraffic, tt.antreaProxyEnabled, tt.srcIsLocal, tt.dstIsLocal)
			assert.Equal(t, tt.expectRejectType, rejectType)
		})
	}
}

func TestGetRejectOFPorts(t *testing.T) {
	unsetPort := uint32(0)
	tunPort := uint32(1)
	gwPort := uint32(2)
	srcIface := &interfacestore.InterfaceConfig{
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 3,
		},
	}
	externalSrcIface := &interfacestore.InterfaceConfig{
		Type: interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 3,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			UplinkPort: &interfacestore.OVSPortConfig{
				OFPort: 4,
			},
		},
	}
	dstIface := &interfacestore.InterfaceConfig{
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 5,
		},
	}
	externalDstIface := &interfacestore.InterfaceConfig{
		Type: interfacestore.ExternalEntityInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 5,
		},
		EntityInterfaceConfig: &interfacestore.EntityInterfaceConfig{
			UplinkPort: &interfacestore.OVSPortConfig{
				OFPort: 6,
			},
		},
	}
	tests := []struct {
		name          string
		rejectType    RejectType
		tunPort       uint32
		srcInterface  *interfacestore.InterfaceConfig
		dstInterface  *interfacestore.InterfaceConfig
		expectInPort  uint32
		expectOutPort uint32
	}{
		{
			name:          "RejectPodLocal",
			rejectType:    RejectPodLocal,
			srcInterface:  srcIface,
			dstInterface:  dstIface,
			expectInPort:  uint32(srcIface.OFPort),
			expectOutPort: uint32(dstIface.OFPort),
		},
		{
			name:          "RejectPodLocalToRemote",
			rejectType:    RejectPodLocalToRemote,
			srcInterface:  srcIface,
			expectInPort:  uint32(srcIface.OFPort),
			expectOutPort: unsetPort,
		},
		{
			name:          "RejectPodLocalToRemoteExternal",
			rejectType:    RejectPodLocalToRemote,
			srcInterface:  externalSrcIface,
			expectInPort:  uint32(externalSrcIface.OFPort),
			expectOutPort: uint32(externalSrcIface.UplinkPort.OFPort),
		},
		{
			name:          "RejectPodRemoteToLocal",
			rejectType:    RejectPodRemoteToLocal,
			dstInterface:  dstIface,
			expectInPort:  gwPort,
			expectOutPort: uint32(dstIface.OFPort),
		},
		{
			name:          "RejectPodRemoteToLocalExternal",
			rejectType:    RejectPodRemoteToLocal,
			dstInterface:  externalDstIface,
			expectInPort:  uint32(externalDstIface.UplinkPort.OFPort),
			expectOutPort: uint32(externalDstIface.OFPort),
		},
		{
			name:          "RejectServiceLocal",
			rejectType:    RejectServiceLocal,
			srcInterface:  srcIface,
			expectInPort:  uint32(srcIface.OFPort),
			expectOutPort: unsetPort,
		},
		{
			name:          "RejectServiceLocalToRemote",
			rejectType:    RejectServiceLocalToRemote,
			srcInterface:  srcIface,
			expectInPort:  uint32(srcIface.OFPort),
			expectOutPort: unsetPort,
		},
		{
			name:          "RejectServiceRemoteToLocal",
			rejectType:    RejectServiceRemoteToLocal,
			expectInPort:  gwPort,
			expectOutPort: unsetPort,
		},
		{
			name:          "RejectNoAPServiceLocal",
			rejectType:    RejectNoAPServiceLocal,
			srcInterface:  srcIface,
			expectInPort:  uint32(srcIface.OFPort),
			expectOutPort: gwPort,
		},
		{
			name:          "RejectNoAPServiceRemoteToLocal",
			rejectType:    RejectNoAPServiceRemoteToLocal,
			tunPort:       tunPort,
			expectInPort:  tunPort,
			expectOutPort: gwPort,
		},
		{
			name:          "RejectNoAPServiceRemoteToLocalWithoutTun",
			rejectType:    RejectNoAPServiceRemoteToLocal,
			tunPort:       unsetPort,
			expectInPort:  gwPort,
			expectOutPort: gwPort,
		},
		{
			name:          "RejectServiceRemoteToExternal",
			rejectType:    RejectServiceRemoteToExternal,
			tunPort:       tunPort,
			expectInPort:  tunPort,
			expectOutPort: unsetPort,
		},
		{
			name:          "RejectServiceRemoteToExternalWithoutTun",
			rejectType:    RejectServiceRemoteToExternal,
			tunPort:       unsetPort,
			expectInPort:  gwPort,
			expectOutPort: unsetPort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inPort, outPort := getRejectOFPorts(tt.rejectType, tt.srcInterface, tt.dstInterface, gwPort, tt.tunPort)
			assert.Equal(t, tt.expectInPort, inPort)
			assert.Equal(t, tt.expectOutPort, outPort)
		})
	}
}
