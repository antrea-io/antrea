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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOVSClient(t *testing.T) {
	_, err := parseOvsVersion(nil)
	assert.Error(t, err)

	// raw strings are not accepted, we want to make sure the function doesn't panic and returns an error
	_, err = parseOvsVersion("ovs_version")
	assert.Error(t, err)

	m1 := map[string]string{"ovs_version": "1"}
	_, err = parseOvsVersion(m1)
	assert.NoError(t, err)

	m2 := map[string]interface{}{"ovs_version": "1.2.3.4.5"}
	_, err = parseOvsVersion(m2)
	assert.NoError(t, err)

}

func TestBuildPortDataCommon(t *testing.T) {
	macStr := "9a:23:45:23:22:41"
	intfMAC, _ := net.ParseMAC(macStr)
	for _, tc := range []struct {
		name     string
		port     map[string]interface{}
		intf     map[string]interface{}
		portData *OVSPortData
	}{
		{
			name: "gw-port",
			port: map[string]interface{}{"name": "antrea-gw0", "external_ids": []interface{}{"map", []interface{}{[]interface{}{"antrea-type", "gateway"}}}},
			intf: map[string]interface{}{"name": "antrea-gw0", "mac": macStr, "type": "internal", "ofport": float64(2), "options": []interface{}{""}},
			portData: &OVSPortData{
				Name:        "antrea-gw0",
				ExternalIDs: map[string]string{"antrea-type": "gateway"},
				Options:     map[string]string{},
				IFType:      "internal",
				OFPort:      2,
				MAC:         intfMAC,
			},
		}, {
			name: "tun-port",
			port: map[string]interface{}{"name": "antrea-tun0", "external_ids": []interface{}{"map", []interface{}{[]interface{}{"antrea-type", "tunnel"}}}},
			intf: map[string]interface{}{"name": "antrea-tun0", "mac": macStr, "type": "geneve", "ofport": float64(1), "options": []interface{}{"map", []interface{}{[]interface{}{"key", "flow"}, []interface{}{"remote_ip", "flow"}}}},
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
			port: map[string]interface{}{"name": "p0", "external_ids": []interface{}{"map", []interface{}{[]interface{}{"antrea-type", "container"}, []interface{}{"ip", "1.2.3.4"}}}},
			intf: map[string]interface{}{"name": "p0", "mac": []interface{}{macStr}, "type": "", "ofport": float64(3), "options": []interface{}{""}},
			portData: &OVSPortData{
				Name:        "p0",
				ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.4"},
				Options:     map[string]string{},
				IFType:      "",
				OFPort:      3,
				MAC:         intfMAC,
			},
		}, {
			name: "access-port",
			port: map[string]interface{}{"name": "p1", "tag": float64(10), "external_ids": []interface{}{"map", []interface{}{[]interface{}{"antrea-type", "container"}, []interface{}{"ip", "1.2.3.5"}}}},
			intf: map[string]interface{}{"name": "p1", "mac": macStr, "type": "", "ofport": float64(3), "options": []interface{}{""}},
			portData: &OVSPortData{
				Name:        "p1",
				ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.5"},
				Options:     map[string]string{},
				IFType:      "",
				OFPort:      3,
				VLANID:      10,
				MAC:         intfMAC,
			},
		}, {
			name: "no-mac-port",
			port: map[string]interface{}{"name": "p2", "external_ids": []interface{}{"map", []interface{}{[]interface{}{"antrea-type", "container"}, []interface{}{"ip", "1.2.3.5"}}}},
			intf: map[string]interface{}{"name": "p2", "mac": []interface{}{}, "type": "", "ofport": float64(4), "options": []interface{}{""}},
			portData: &OVSPortData{
				Name:        "p2",
				ExternalIDs: map[string]string{"antrea-type": "container", "ip": "1.2.3.5"},
				Options:     map[string]string{},
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

func TestParseHardwareOffloadConfig(t *testing.T) {
	tests := []struct {
		name            string
		otherConfig     map[string]string
		expectedEnabled bool
		expectErr       bool
		errContains     string
	}{
		{
			name:            "empty config returns false",
			otherConfig:     map[string]string{},
			expectedEnabled: false,
		},
		{
			name:            "hw-offload set to true",
			otherConfig:     map[string]string{"hw-offload": "true"},
			expectedEnabled: true,
		},
		{
			name:            "hw-offload set to false",
			otherConfig:     map[string]string{"hw-offload": "false"},
			expectedEnabled: false,
		},
		{
			name:            "hw-offload set to 1 (alternate truthy form)",
			otherConfig:     map[string]string{"hw-offload": "1"},
			expectedEnabled: true,
		},
		{
			name:            "hw-offload set to 0 (alternate falsy form)",
			otherConfig:     map[string]string{"hw-offload": "0"},
			expectedEnabled: false,
		},
		{
			name:        "hw-offload set to invalid value returns error with original string",
			otherConfig: map[string]string{"hw-offload": "notabool"},
			expectErr:   true,
			errContains: "notabool",
		},
		{
			name:            "unrelated keys present, no hw-offload key returns false",
			otherConfig:     map[string]string{"flow-restore-wait": "true", "disable-in-band": "true"},
			expectedEnabled: false,
		},
		{
			name:            "multiple keys including hw-offload true",
			otherConfig:     map[string]string{"flow-restore-wait": "true", "hw-offload": "true"},
			expectedEnabled: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enabled, err := parseHardwareOffloadConfig(tc.otherConfig)
			if tc.expectErr {
				require.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), tc.errContains),
					"expected error message to contain %q, got: %s", tc.errContains, err.Error())
				assert.False(t, enabled)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedEnabled, enabled)
			}
		})
	}
}
