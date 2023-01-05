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

package l7engine

import (
	"encoding/json"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	v1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type fakeSuricata struct {
	calledScCommands      sets.String
	startSuricataFnCalled bool
}

func newFakeSuricata() *fakeSuricata {
	return &fakeSuricata{
		calledScCommands:      sets.NewString(),
		startSuricataFnCalled: false,
	}
}

func (f *fakeSuricata) suricataSCFn(cmd *scCmd) (*scCmdRet, error) {
	cmdBytes, _ := json.Marshal(cmd)
	f.calledScCommands.Insert(string(cmdBytes))
	return &scCmdRet{Return: scCmdRetOK}, nil
}

func (f *fakeSuricata) startSuricataFn() {
	f.startSuricataFnCalled = true
	defaultFS.Create(suricataCommandSocket)
}

func TestConvertProtocolHTTP(t *testing.T) {
	testCases := []struct {
		name     string
		http     *v1beta.HTTPProtocol
		expected string
	}{
		{
			name:     "without host,method,path",
			http:     &v1beta.HTTPProtocol{},
			expected: "",
		},
		{
			name: "with host,method,exact path",
			http: &v1beta.HTTPProtocol{
				Host:   "www.google.com",
				Method: "GET",
				Path:   "/index.html",
			},
			expected: `http.uri; content:"/index.html"; startswith; endswith; http.method; content:"GET"; http.host; content:"www.google.com"; startswith; endswith;`,
		},
		{
			name: "with host suffix, path prefix",
			http: &v1beta.HTTPProtocol{
				Host: "*.foo.com",
				Path: "/api/v2/*",
			},
			expected: `http.uri; content:"/api/v2/"; startswith; http.host; content:".foo.com"; endswith;`,
		},
		{
			name: "with host pattern",
			http: &v1beta.HTTPProtocol{
				Host: "*.foo.*",
			},
			expected: `http.host; content:".foo.";`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, convertProtocolHTTP(tc.http))
		})
	}
}

func TestStartSuricata(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defer func() {
		defaultFS = afero.NewOsFs()
	}()

	_, err := defaultFS.Create(defaultSuricataConfigPath)
	assert.NoError(t, err)

	fe := NewReconciler()
	fs := newFakeSuricata()
	fe.suricataSCFn = fs.suricataSCFn
	fe.startSuricataFn = fs.startSuricataFn

	fe.startSuricata()

	ok, err := afero.FileContainsBytes(defaultFS, antreaSuricataConfigPath, []byte(`---
af-packet:
  - interface: antrea-l7-tap0
    threads: auto
    cluster-id: 80
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    copy-mode: ips
    copy-iface: antrea-l7-tap1
  - interface:  antrea-l7-tap1
    threads: auto
    cluster-id: 81
    cluster-type: cluster_flow
    defrag: no
    use-mmap: yes
    tpacket-v2: yes
    checksum-checks: no
    copy-mode: ips
    copy-iface: antrea-l7-tap0
multi-detect:
  enabled: yes
  selector: vlan`))
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = afero.FileContainsBytes(defaultFS, defaultSuricataConfigPath, []byte("include: /etc/suricata/antrea.yaml"))
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestRuleLifecycle(t *testing.T) {
	ruleID := "123456"
	vlanID := uint32(1)
	policyName := "AntreaNetworkPolicy:test-l7"

	testCases := []struct {
		name                 string
		l7Protocols          []v1beta.L7Protocol
		updatedL7Protocols   []v1beta.L7Protocol
		expectedRules        string
		expectedUpdatedRules string
	}{
		{
			name: "protocol HTTP",
			l7Protocols: []v1beta.L7Protocol{
				{
					HTTP: &v1beta.HTTPProtocol{
						Host:   "www.google.com",
						Method: "GET",
						Path:   "/index.html",
					},
				},
			},
			updatedL7Protocols: []v1beta.L7Protocol{
				{
					HTTP: &v1beta.HTTPProtocol{},
				},
			},
			expectedRules:        `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; http.uri; content:"/index.html"; startswith; endswith; http.method; content:"GET"; http.host; content:"www.google.com"; startswith; endswith; sid: 2;)`,
			expectedUpdatedRules: `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; sid: 2;)`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defaultFS = afero.NewMemMapFs()
			defer func() {
				defaultFS = afero.NewOsFs()
			}()

			_, err := defaultFS.Create(defaultSuricataConfigPath)
			assert.NoError(t, err)

			fe := NewReconciler()
			fs := newFakeSuricata()
			fe.suricataSCFn = fs.suricataSCFn
			fe.startSuricataFn = fs.startSuricataFn

			// Test add a L7 NetworkPolicy.
			assert.NoError(t, fe.AddRule(ruleID, policyName, vlanID, tc.l7Protocols))

			rulesPath := generateTenantRulesPath(vlanID)
			ok, err := afero.FileContainsBytes(defaultFS, rulesPath, []byte(tc.expectedRules))
			assert.NoError(t, err)
			assert.True(t, ok)

			configPath := generateTenantConfigPath(vlanID)
			ok, err = afero.FileContainsBytes(defaultFS, configPath, []byte(rulesPath))
			assert.NoError(t, err)
			assert.True(t, ok)

			expectedSCCommands := sets.NewString(`{"command":"register-tenant","arguments":{"id":1,"filename":"/etc/suricata/antrea-tenant-1.yaml"}}`, `{"command":"register-tenant-handler","arguments":{"id":1,"htype":"vlan","hargs":1}}`)
			assert.True(t, fs.startSuricataFnCalled)
			assert.Equal(t, expectedSCCommands, fs.calledScCommands)

			// Update the added L7 NetworkPolicy.
			assert.NoError(t, fe.AddRule(ruleID, policyName, vlanID, tc.updatedL7Protocols))
			expectedSCCommands.Insert(`{"command":"reload-tenant","arguments":{"id":1,"filename":"/etc/suricata/antrea-tenant-1.yaml"}}`)
			assert.Equal(t, expectedSCCommands, fs.calledScCommands)

			// Delete the L7 NetworkPolicy.
			assert.NoError(t, fe.DeleteRule(ruleID, vlanID))
			expectedSCCommands.Insert(`{"command":"unregister-tenant-handler","arguments":{"id":1,"htype":"vlan","hargs":1}}`, `{"command":"unregister-tenant","arguments":{"id":1}}`)
			assert.Equal(t, expectedSCCommands, fs.calledScCommands)

			exists, err := afero.Exists(defaultFS, rulesPath)
			assert.NoError(t, err)
			assert.False(t, exists)

			exists, err = afero.Exists(defaultFS, configPath)
			assert.NoError(t, err)
			assert.False(t, exists)
		})
	}
}