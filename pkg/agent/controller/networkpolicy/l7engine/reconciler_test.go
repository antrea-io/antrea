//go:build !windows

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
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"

	oftesting "antrea.io/antrea/v2/pkg/agent/openflow/testing"
	v1beta "antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
)

type fakeSuricata struct {
	calledScCommands      sets.Set[string]
	startSuricataFnCalled bool
}

func newFakeSuricata() *fakeSuricata {
	return &fakeSuricata{
		calledScCommands:      sets.New[string](),
		startSuricataFnCalled: false,
	}
}

func (f *fakeSuricata) suricataScFunc(scCmd string) (*scCmdRet, error) {
	f.calledScCommands.Insert(scCmd)
	return &scCmdRet{Return: scCmdOK}, nil
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

func TestConvertProtocolTLS(t *testing.T) {
	testCases := []struct {
		name     string
		tls      *v1beta.TLSProtocol
		expected string
	}{
		{
			name:     "without SNI",
			tls:      &v1beta.TLSProtocol{},
			expected: "",
		},
		{
			name: "with SNI",
			tls: &v1beta.TLSProtocol{
				SNI: "google.com",
			},
			expected: `tls.sni; content:"google.com"; startswith; endswith;`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, convertProtocolTLS(tc.tls))
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

	fe := NewReconciler(nil)
	fs := newFakeSuricata()
	fe.suricataScFn = fs.suricataScFunc
	fe.startSuricataFn = fs.startSuricataFn

	fe.startSuricata()

	ok, err := afero.FileContainsBytes(defaultFS, antreaSuricataConfigPath, []byte(suricataAntreaConfigData))
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, err = afero.FileContainsBytes(defaultFS, defaultSuricataConfigPath, []byte("include: /etc/suricata/antrea.yaml"))
	assert.NoError(t, err)
	assert.True(t, ok)

	// Suricata fails to start without the rules file, and writing it fails without the directory.
	exists, err := afero.DirExists(defaultFS, rulesDir)
	assert.NoError(t, err)
	assert.True(t, exists)
	ok, err = afero.FileContainsBytes(defaultFS, rulesPath, []byte(commonRulesData))
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestWriteRules(t *testing.T) {
	testCases := []struct {
		name          string
		vlanID        uint32
		protoKeywords map[string]sets.Set[string]
		sid           int
		expected      string
		expectedSID   int
	}{
		{
			name:   "protocol HTTP",
			vlanID: 1,
			protoKeywords: map[string]sets.Set[string]{
				protocolHTTP: sets.New[string](`http.uri; content:"/index.html"; startswith; endswith;`),
			},
			sid: 2,
			expected: `alert ip any any -> any any (vlan.id: 1; flowbits: set,antrea_l7_1; flowbits: set,antrea_l7; flowbits: noalert; sid: 2;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flow: to_server, established; app-layer-protocol: !http; sid: 3;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flow: to_server, established; app-layer-protocol: failed; sid: 4;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flowbits: isnotset,antrea_l7_allowed; flow: to_server, established; flow.bytes_toserver: >65536; sid: 5;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flowbits: isnotset,antrea_l7_allowed; flow: to_server, established; flow.age: >5; sid: 6;)
reject http1:request_headers any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; sid: 7;)
pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flowbits: set,antrea_l7_allowed; http.uri; content:"/index.html"; startswith; endswith; sid: 8;)
`,
			expectedSID: 9,
		},
		{
			// Only TLS is allowed, so the volume bound is the TLS one.
			name:   "protocol TLS",
			vlanID: 3,
			protoKeywords: map[string]sets.Set[string]{
				protocolTLS: sets.New[string](`tls.sni; content:"foo.bar.com"; startswith; endswith;`),
			},
			sid: 2,
			expected: `alert ip any any -> any any (vlan.id: 3; flowbits: set,antrea_l7_3; flowbits: set,antrea_l7; flowbits: noalert; sid: 2;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_3; flow: to_server, established; app-layer-protocol: !tls; sid: 3;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_3; flow: to_server, established; app-layer-protocol: failed; sid: 4;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_3; flowbits: isnotset,antrea_l7_allowed; flow: to_server, established; flow.bytes_toserver: >16384; sid: 5;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_3; flowbits: isnotset,antrea_l7_allowed; flow: to_server, established; flow.age: >5; sid: 6;)
reject tls:client_hello_done any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_3; sid: 7;)
pass tls any any -> any any (msg: "Allow tls by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_3; flowbits: set,antrea_l7_allowed; tls.sni; content:"foo.bar.com"; startswith; endswith; sid: 8;)
`,
			expectedSID: 9,
		},
		{
			// The HTTP criteria are empty, so the rule allows all HTTP and no rule rejecting HTTP on its
			// content is generated. The SIDs continue from where the preceding L7 rule left off.
			name:   "protocol HTTP allowing anything, and TLS",
			vlanID: 2,
			protoKeywords: map[string]sets.Set[string]{
				protocolHTTP: sets.New[string](""),
				protocolTLS:  sets.New[string](`tls.sni; content:"foo.bar.com"; startswith; endswith;`),
			},
			sid: 9,
			expected: `alert ip any any -> any any (vlan.id: 2; flowbits: set,antrea_l7_2; flowbits: set,antrea_l7; flowbits: noalert; sid: 9;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; flow: to_server, established; app-layer-protocol: !http; app-layer-protocol: !tls; sid: 10;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; flow: to_server, established; app-layer-protocol: failed; sid: 11;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; flowbits: isnotset,antrea_l7_allowed; flow: to_server, established; flow.bytes_toserver: >65536; sid: 12;)
reject ip any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; flowbits: isnotset,antrea_l7_allowed; flow: to_server, established; flow.age: >5; sid: 13;)
reject tls:client_hello_done any any -> any any (msg: "Reject by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; sid: 14;)
pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; flowbits: set,antrea_l7_allowed; sid: 15;)
pass tls any any -> any any (msg: "Allow tls by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_2; flowbits: set,antrea_l7_allowed; tls.sni; content:"foo.bar.com"; startswith; endswith; sid: 16;)
`,
			expectedSID: 17,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			rule := &l7Rule{
				policyName:    "AntreaNetworkPolicy:test-l7",
				vlanID:        tc.vlanID,
				protoKeywords: tc.protoKeywords,
			}
			assert.Equal(t, tc.expectedSID, writeRules(buf, rule, tc.sid))
			assert.Equal(t, tc.expected, buf.String())
		})
	}
}

// TestRulesFileSIDsAreUnique verifies that no two rules in the file share a SID, whatever the L7
// rules are. Suricata refuses a rules file holding a duplicate SID, so a collision would stop every
// L7 rule on the Node from being enforced.
func TestRulesFileSIDsAreUnique(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defer func() {
		defaultFS = afero.NewOsFs()
	}()
	_, err := defaultFS.Create(defaultSuricataConfigPath)
	assert.NoError(t, err)

	ctrl := gomock.NewController(t)
	mockOfClient := oftesting.NewMockClient(ctrl)
	fe := NewReconciler(mockOfClient)
	fs := newFakeSuricata()
	fe.suricataScFn = fs.suricataScFunc
	fe.startSuricataFn = fs.startSuricataFn
	mockOfClient.EXPECT().InstallL7NetworkPolicyFlows().Times(1)

	// One L7 rule with many more criteria than the others, which is what used to take the SIDs of the
	// L7 rule after it.
	var manyProtocols []v1beta.L7Protocol
	for i := 0; i < 2000; i++ {
		manyProtocols = append(manyProtocols, v1beta.L7Protocol{HTTP: &v1beta.HTTPProtocol{Path: fmt.Sprintf("/p%d", i)}})
	}
	assert.NoError(t, fe.AddRule("ruleA", "AntreaNetworkPolicy:test-a", 1, manyProtocols))
	assert.NoError(t, fe.AddRule("ruleB", "AntreaNetworkPolicy:test-b", 2, []v1beta.L7Protocol{{HTTP: &v1beta.HTTPProtocol{Path: "/b"}}}))

	data, err := afero.ReadFile(defaultFS, rulesPath)
	assert.NoError(t, err)
	sidRegexp := regexp.MustCompile(`sid: (\d+);`)
	seen := sets.New[string]()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		m := sidRegexp.FindStringSubmatch(line)
		require.Len(t, m, 2, "Every rule carries a SID: %s", line)
		require.False(t, seen.Has(m[1]), "SID %s is used more than once", m[1])
		seen.Insert(m[1])
	}
	assert.Len(t, lines, seen.Len())
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
			expectedRules:        `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flowbits: set,antrea_l7_allowed; http.uri; content:"/index.html"; startswith; endswith; http.method; content:"GET"; http.host; content:"www.google.com"; startswith; endswith; sid: 8;)`,
			expectedUpdatedRules: `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-l7"; flowbits: isset,antrea_l7_1; flowbits: set,antrea_l7_allowed; sid: 7;)`,
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

			ctrl := gomock.NewController(t)
			mockOfClient := oftesting.NewMockClient(ctrl)
			fe := NewReconciler(mockOfClient)
			fs := newFakeSuricata()
			fe.suricataScFn = fs.suricataScFunc
			fe.startSuricataFn = fs.startSuricataFn

			mockOfClient.EXPECT().InstallL7NetworkPolicyFlows().Times(1)

			// Test add a L7 NetworkPolicy.
			assert.NoError(t, fe.AddRule(ruleID, policyName, vlanID, tc.l7Protocols))

			ok, err := afero.FileContainsBytes(defaultFS, rulesPath, []byte(tc.expectedRules))
			assert.NoError(t, err)
			assert.True(t, ok)

			// The rules rejecting the traffic which belongs to no L7 rule are always present.
			ok, err = afero.FileContainsBytes(defaultFS, rulesPath, []byte(commonRulesData))
			assert.NoError(t, err)
			assert.True(t, ok)

			expectedScCommands := sets.New[string]("ruleset-reload-rules")
			assert.True(t, fs.startSuricataFnCalled)
			assert.Equal(t, expectedScCommands, fs.calledScCommands)

			// Update the added L7 NetworkPolicy.
			assert.NoError(t, fe.AddRule(ruleID, policyName, vlanID, tc.updatedL7Protocols))
			ok, err = afero.FileContainsBytes(defaultFS, rulesPath, []byte(tc.expectedUpdatedRules))
			assert.NoError(t, err)
			assert.True(t, ok)

			// Delete the L7 NetworkPolicy. The rules file is kept, Suricata fails to start without it,
			// but the rules of the deleted L7 rule are gone.
			assert.NoError(t, fe.DeleteRule(ruleID, vlanID))
			data, err := afero.ReadFile(defaultFS, rulesPath)
			assert.NoError(t, err)
			assert.Equal(t, commonRulesData, string(data))
		})
	}
}

// TestRuleIsolation verifies that the rules of one L7 rule are scoped to its own VLAN ID, so that
// adding or deleting an L7 rule never changes the rules of another.
func TestRuleIsolation(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defer func() {
		defaultFS = afero.NewOsFs()
	}()

	_, err := defaultFS.Create(defaultSuricataConfigPath)
	assert.NoError(t, err)

	ctrl := gomock.NewController(t)
	mockOfClient := oftesting.NewMockClient(ctrl)
	fe := NewReconciler(mockOfClient)
	fs := newFakeSuricata()
	fe.suricataScFn = fs.suricataScFunc
	fe.startSuricataFn = fs.startSuricataFn
	mockOfClient.EXPECT().InstallL7NetworkPolicyFlows().Times(1)

	protocolsA := []v1beta.L7Protocol{{HTTP: &v1beta.HTTPProtocol{Path: "/a"}}}
	protocolsB := []v1beta.L7Protocol{{HTTP: &v1beta.HTTPProtocol{Path: "/b"}}}
	assert.NoError(t, fe.AddRule("ruleA", "AntreaNetworkPolicy:test-a", 1, protocolsA))
	assert.NoError(t, fe.AddRule("ruleB", "AntreaNetworkPolicy:test-b", 2, protocolsB))

	// Every rule of an L7 rule is scoped to the flowbit of its own VLAN ID.
	data, err := afero.ReadFile(defaultFS, rulesPath)
	assert.NoError(t, err)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		switch {
		case strings.Contains(line, "test-a"):
			assert.Contains(t, line, "antrea_l7_1")
			assert.NotContains(t, line, "antrea_l7_2")
		case strings.Contains(line, "test-b"):
			assert.Contains(t, line, "antrea_l7_2")
			assert.NotContains(t, line, "antrea_l7_1")
		}
	}

	// Deleting one L7 rule leaves the rules of the other unchanged apart from their SIDs, which are
	// handed out as the file is written.
	assert.NoError(t, fe.DeleteRule("ruleA", 1))
	data, err = afero.ReadFile(defaultFS, rulesPath)
	assert.NoError(t, err)
	assert.NotContains(t, string(data), "test-a")
	assert.Contains(t, string(data), `pass http any any -> any any (msg: "Allow http by AntreaNetworkPolicy:test-b"; flowbits: isset,antrea_l7_2; flowbits: set,antrea_l7_allowed; http.uri; content:"/b"; startswith; endswith; sid: 8;)`)
}

// newTestReconciler returns a Reconciler backed by an in-memory filesystem and a fake Suricata, and
// the mock OpenFlow client for the test to program. The caller must restore defaultFS.
func newTestReconciler(t *testing.T) (*Reconciler, *oftesting.MockClient) {
	defaultFS = afero.NewMemMapFs()
	_, err := defaultFS.Create(defaultSuricataConfigPath)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	mockOfClient := oftesting.NewMockClient(ctrl)
	fe := NewReconciler(mockOfClient)
	fs := newFakeSuricata()
	fe.suricataScFn = fs.suricataScFunc
	fe.startSuricataFn = fs.startSuricataFn
	return fe, mockOfClient
}

// TestSyncRulesCoalesces verifies that a sync includes every change made before it and that nothing
// is reloaded when nothing has changed, which is what lets concurrent changes share one reload.
func TestSyncRulesCoalesces(t *testing.T) {
	fe, _ := newTestReconciler(t)
	defer func() {
		defaultFS = afero.NewOsFs()
	}()
	var reloads atomic.Int32
	fe.suricataScFn = func(string) (*scCmdRet, error) {
		reloads.Add(1)
		return &scCmdRet{Return: scCmdOK}, nil
	}
	require.NoError(t, fe.StartSuricataOnce())

	// Two changes made without syncing in between are carried by one sync.
	fe.rulesMutex.Lock()
	fe.rulesByVlanID[1] = &l7Rule{policyName: "AntreaNetworkPolicy:test-a", vlanID: 1, protoKeywords: map[string]sets.Set[string]{protocolHTTP: sets.New[string]("")}}
	fe.rulesByVlanID[2] = &l7Rule{policyName: "AntreaNetworkPolicy:test-b", vlanID: 2, protoKeywords: map[string]sets.Set[string]{protocolHTTP: sets.New[string]("")}}
	fe.rulesChanged = true
	fe.rulesMutex.Unlock()
	assert.NoError(t, fe.syncRules())
	assert.Equal(t, int32(1), reloads.Load())
	data, err := afero.ReadFile(defaultFS, rulesPath)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "test-a")
	assert.Contains(t, string(data), "test-b")

	// A sync with nothing changed does not reload.
	assert.NoError(t, fe.syncRules())
	assert.Equal(t, int32(1), reloads.Load())

	// A sync which fails leaves the change pending, so the next sync reloads again.
	fe.suricataScFn = func(string) (*scCmdRet, error) {
		reloads.Add(1)
		return &scCmdRet{Return: "NOK", Message: "boom"}, nil
	}
	assert.Error(t, fe.updateRules(3, &l7Rule{policyName: "AntreaNetworkPolicy:test-c", vlanID: 3, protoKeywords: map[string]sets.Set[string]{protocolHTTP: sets.New[string]("")}}))
	assert.Equal(t, int32(2), reloads.Load())
	fe.suricataScFn = func(string) (*scCmdRet, error) {
		reloads.Add(1)
		return &scCmdRet{Return: scCmdOK}, nil
	}
	assert.NoError(t, fe.syncRules())
	assert.Equal(t, int32(3), reloads.Load())
}

// TestConcurrentRuleChangesShareReloads verifies that changes arriving while a reload is in flight
// are folded into the reload that follows it rather than each reloading in turn.
func TestConcurrentRuleChangesShareReloads(t *testing.T) {
	fe, mockOfClient := newTestReconciler(t)
	defer func() {
		defaultFS = afero.NewOsFs()
	}()
	mockOfClient.EXPECT().InstallL7NetworkPolicyFlows().Times(1)
	var reloads atomic.Int32
	release := make(chan struct{})
	fe.suricataScFn = func(string) (*scCmdRet, error) {
		// The first reload blocks until every change has been made, so that the others queue behind it.
		if reloads.Add(1) == 1 {
			<-release
		}
		return &scCmdRet{Return: scCmdOK}, nil
	}
	require.NoError(t, fe.StartSuricataOnce())
	require.NoError(t, fe.initializeL7FlowsOnce.Do(fe.initializeL7Flows))

	const numRules = 4
	var wg sync.WaitGroup
	for i := 1; i <= numRules; i++ {
		wg.Add(1)
		go func(vlanID uint32) {
			defer wg.Done()
			protocols := []v1beta.L7Protocol{{HTTP: &v1beta.HTTPProtocol{Path: fmt.Sprintf("/%d", vlanID)}}}
			assert.NoError(t, fe.AddRule(fmt.Sprintf("rule%d", vlanID), "AntreaNetworkPolicy:test", vlanID, protocols))
		}(uint32(i))
	}
	// Every change has been recorded once the map holds every rule. Each goroutine records its change
	// and marks the rules changed in one critical section, so from here on the reload which follows
	// the blocked one sees all of them.
	assert.Eventually(t, func() bool {
		fe.rulesMutex.Lock()
		defer fe.rulesMutex.Unlock()
		return len(fe.rulesByVlanID) == numRules
	}, 5*time.Second, 10*time.Millisecond)
	close(release)
	wg.Wait()

	// One reload for the change that started first, one for everything that arrived while it ran.
	assert.Equal(t, int32(2), reloads.Load())
	data, err := afero.ReadFile(defaultFS, rulesPath)
	assert.NoError(t, err)
	for i := 1; i <= numRules; i++ {
		assert.Contains(t, string(data), fmt.Sprintf(`content:"/%d"`, i))
	}
}

func TestInitializeL7FlowsOnce(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockOfClient := oftesting.NewMockClient(ctrl)
	fe := NewReconciler(mockOfClient)

	mockOfClient.EXPECT().InstallL7NetworkPolicyFlows().Return(fmt.Errorf("error"))
	mockOfClient.EXPECT().InstallL7NetworkPolicyFlows().Return(nil)

	var wg sync.WaitGroup
	var errOccurred int32
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := fe.initializeL7FlowsOnce.Do(fe.initializeL7Flows)
			if err != nil {
				atomic.AddInt32(&errOccurred, 1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), errOccurred)
}
