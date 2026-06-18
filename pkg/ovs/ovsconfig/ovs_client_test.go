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

package ovsconfig

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
)

func TestBuildPortDataCommon(t *testing.T) {
	macStr := "9a:23:45:23:22:41"
	intfMAC, _ := net.ParseMAC(macStr)
	for _, tc := range []struct {
		name     string
		port     *Port
		intf     *Interface
		portData *OVSPortData
	}{
		{
			name: "gw-port",
			port: &Port{Name: "antrea-gw0", ExternalIDs: map[string]string{"antrea-type": "gateway"}},
			intf: &Interface{Name: "antrea-gw0", MAC: ptr.To(macStr), Type: "internal", OFPort: ptr.To(2)},
			portData: &OVSPortData{
				Name:        "antrea-gw0",
				ExternalIDs: map[string]string{"antrea-type": "gateway"},
				Options:     nil,
				IFType:      "internal",
				OFPort:      2,
				MAC:         intfMAC,
			},
		}, {
			name: "tun-port",
			port: &Port{Name: "antrea-tun0", ExternalIDs: map[string]string{"antrea-type": "tunnel"}},
			intf: &Interface{Name: "antrea-tun0", MAC: ptr.To(macStr), Type: "geneve", OFPort: ptr.To(1), Options: map[string]string{"key": "flow", "remote_ip": "flow"}},
			portData: &OVSPortData{
				Name:        "antrea-tun0",
				ExternalIDs: map[string]string{"antrea-type": "tunnel"},
				Options:     map[string]string{"key": "flow", "remote_ip": "flow"},
				IFType:      "geneve",
				OFPort:      1,
				MAC:         intfMAC,
			},
		}, {
			name: "general-port",
			port: &Port{Name: "p0", ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.4"}},
			intf: &Interface{Name: "p0", MAC: ptr.To(macStr), Type: "", OFPort: ptr.To(3)},
			portData: &OVSPortData{
				Name:        "p0",
				ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.4"},
				Options:     nil,
				IFType:      "",
				OFPort:      3,
				MAC:         intfMAC,
			},
		}, {
			name: "access-port",
			port: &Port{Name: "p1", Tag: ptr.To(10), ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.5"}},
			intf: &Interface{Name: "p1", MAC: ptr.To(macStr), Type: "", OFPort: ptr.To(3)},
			portData: &OVSPortData{
				Name:        "p1",
				ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.5"},
				Options:     nil,
				IFType:      "",
				OFPort:      3,
				VLANID:      10,
				MAC:         intfMAC,
			},
		}, {
			name: "no-mac-port",
			port: &Port{Name: "p2", ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.5"}},
			intf: &Interface{Name: "p2", MAC: nil, Type: "", OFPort: ptr.To(4)},
			portData: &OVSPortData{
				Name:        "p2",
				ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.5"},
				Options:     nil,
				IFType:      "",
				OFPort:      4,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portData := &OVSPortData{}
			buildPortDataCommon(tc.port, tc.intf, portData)
			assert.Equal(t, tc.portData, portData)
		})
	}

}
