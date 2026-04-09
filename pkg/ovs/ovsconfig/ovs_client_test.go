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

func TestBuildPortDataCommonTrunks(t *testing.T) {
	basePort := func(trunks interface{}) map[string]interface{} {
		return map[string]interface{}{
			"name":         "eth1",
			"external_ids": []interface{}{"map", []interface{}{}},
			"trunks":       trunks,
		}
	}
	baseIntf := map[string]interface{}{
		"name":    "eth1",
		"mac":     []interface{}{},
		"type":    "",
		"ofport":  float64(1),
		"options": []interface{}{""},
	}

	tests := []struct {
		name       string
		trunks     interface{}
		wantTrunks []uint16
	}{
		{
			name:       "no trunks field (nil)",
			trunks:     nil,
			wantTrunks: nil,
		},
		{
			name:       "empty set",
			trunks:     []interface{}{"set", []interface{}{}},
			wantTrunks: nil,
		},
		{
			name:       "multi-value set",
			trunks:     []interface{}{"set", []interface{}{float64(100), float64(200)}},
			wantTrunks: []uint16{100, 200},
		},
		{
			// OVSDB returns a bare scalar (float64) for a single-element set.
			// This is the case that previously caused clearStaleTrunks to skip
			// single-VLAN trunk ports.
			name:       "single VLAN — bare scalar (OVSDB single-element encoding)",
			trunks:     float64(100),
			wantTrunks: []uint16{100},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := basePort(tc.trunks)
			portData := &OVSPortData{}
			buildPortDataCommon(port, baseIntf, portData)
			assert.Equal(t, tc.wantTrunks, portData.Trunks)
		})
	}
}

func TestParseVLANSpecs(t *testing.T) {
	tests := []struct {
		name        string
		specs       []string
		wantIDs     []uint16
		expectedErr string
	}{
		{
			name:    "single VLAN",
			specs:   []string{"100"},
			wantIDs: []uint16{100},
		},
		{
			name:    "range",
			specs:   []string{"10-12"},
			wantIDs: []uint16{10, 11, 12},
		},
		{
			name:    "mixed",
			specs:   []string{"5", "10-11"},
			wantIDs: []uint16{5, 10, 11},
		},
		{
			name:        "invalid single",
			specs:       []string{"abc"},
			expectedErr: "invalid VLAN ID",
		},
		{
			name:        "inverted range",
			specs:       []string{"200-100"},
			expectedErr: "VLAN range start",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseVLANSpecs(tc.specs)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.wantIDs, got)
			}
		})
	}
}
