// Copyright 2021 Antrea Authors
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
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/config"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
)

func newMockFQDNController(t *testing.T, controller *gomock.Controller, dnsServer *string,
	clockToInject clock.WithTicker, fqdnCacheMinTTL uint32) (*fqdnController, *openflowtest.MockClient) {
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOFClient.EXPECT().NewDNSPacketInConjunction(gomock.Any()).Return(nil).AnyTimes()
	dirtyRuleHandler := func(rule string) {}
	dnsServerAddr := "8.8.8.8:53" // dummy DNS server, will not be used since we don't send any request in these tests
	if dnsServer != nil {
		dnsServerAddr = *dnsServer
	}
	if clockToInject == nil {
		clockToInject = clock.RealClock{}
	}
	f, err := newFQDNController(
		mockOFClient,
		newIDAllocator(testAsyncDeleteInterval),
		dnsServerAddr,
		dirtyRuleHandler,
		true,
		false,
		config.DefaultHostGatewayOFPort,
		clockToInject,
		fqdnCacheMinTTL,
	)
	require.NoError(t, err)
	return f, mockOFClient
}

func TestAddFQDNRule(t *testing.T) {
	selectorItem1 := fqdnSelectorItem{
		matchName: "test.antrea.io",
	}
	selectorItem2 := fqdnSelectorItem{
		matchRegex: "^.*antrea[.]io$",
	}
	tests := []struct {
		name                       string
		existingSelectorToRuleIDs  map[fqdnSelectorItem]sets.Set[string]
		existingDNSCache           map[string]dnsMeta
		existingFQDNToSelectorItem map[string]sets.Set[fqdnSelectorItem]
		existingFQDNToSelectedPods map[string]sets.Set[int32]
		ruleID                     string
		fqdns                      []string
		podAddrs                   sets.Set[int32]
		finalSelectorToRuleIDs     map[fqdnSelectorItem]sets.Set[string]
		finalFQDNToSelectorItem    map[string]sets.Set[fqdnSelectorItem]
		addressAdded               bool
		addressRemoved             bool
		enqueuedFQDNs              []string
	}{
		{
			name:     "addNewMatchNameSelector",
			ruleID:   "mockRule1",
			fqdns:    []string{"test.antrea.io"},
			podAddrs: sets.New[int32](1),
			finalSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
			},
			finalFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			addressAdded:   true,
			addressRemoved: false,
			enqueuedFQDNs:  []string{"test.antrea.io"},
		},
		{
			name: "addSameMatchNameSelector",
			existingSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
			},
			existingDNSCache: map[string]dnsMeta{
				"test.antrea.io": {},
			},
			existingFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			existingFQDNToSelectedPods: map[string]sets.Set[int32]{
				"test.antrea.io": sets.New[int32](1),
			},
			ruleID:   "mockRule1",
			fqdns:    []string{"test.antrea.io"},
			podAddrs: sets.New[int32](1),
			finalSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
			},
			finalFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			addressAdded:   false,
			addressRemoved: false,
		},
		{
			name: "addNewMatchNameSelectorMatchingExisting",
			existingSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
			},
			existingDNSCache: map[string]dnsMeta{
				"test.antrea.io": {},
			},
			existingFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			ruleID:   "mockRule2",
			fqdns:    []string{"test.antrea.io"},
			podAddrs: sets.New[int32](2),
			finalSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1", "mockRule2"),
			},
			finalFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			addressAdded:   true,
			addressRemoved: false,
		},
		{
			name: "addNewMatchRegexSelectorMatchExisting",
			existingSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
			},
			existingDNSCache: map[string]dnsMeta{
				"test.antrea.io": {},
			},
			existingFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			ruleID:   "mockRule2",
			fqdns:    []string{"*antrea.io"},
			podAddrs: sets.New[int32](2),
			finalSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
				selectorItem2: sets.New[string]("mockRule2")},
			finalFQDNToSelectorItem: map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1, selectorItem2),
			},
			addressAdded:   true,
			addressRemoved: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			f, c := newMockFQDNController(t, controller, nil, nil, 0)
			if tt.addressAdded {
				c.EXPECT().AddAddressToDNSConjunction(dnsInterceptRuleID, gomock.Any()).Times(1)
			}
			if tt.addressRemoved {
				c.EXPECT().DeleteAddressFromDNSConjunction(dnsInterceptRuleID, gomock.Any()).Times(1)
			}
			if tt.existingSelectorToRuleIDs != nil {
				f.selectorItemToRuleIDs = tt.existingSelectorToRuleIDs
				f.fqdnToSelectorItem = tt.existingFQDNToSelectorItem
			}
			if tt.existingFQDNToSelectedPods != nil {
				f.fqdnRuleToSelectedPods = tt.existingFQDNToSelectedPods
			}
			if tt.existingDNSCache != nil {
				f.dnsEntryCache = tt.existingDNSCache
			}
			require.NoError(t, f.addFQDNRule(tt.ruleID, tt.fqdns, tt.podAddrs), "Error when adding FQDN rule")
			assert.Equal(t, tt.finalSelectorToRuleIDs, f.selectorItemToRuleIDs)
			assert.Equal(t, tt.finalFQDNToSelectorItem, f.fqdnToSelectorItem)
			var enqueuedFQDNs []string
			for f.dnsQueryQueue.Len() > 0 {
				item, _ := f.dnsQueryQueue.Get()
				f.dnsQueryQueue.Done(item)
				enqueuedFQDNs = append(enqueuedFQDNs, item)
			}
			assert.ElementsMatch(t, tt.enqueuedFQDNs, enqueuedFQDNs)
		})
	}
}

type fqdnRuleAddArgs struct {
	ruleID         string
	fqdns          []string
	podOFAddresses sets.Set[int32]
}

func TestDeleteFQDNRule(t *testing.T) {
	selectorItem1 := fqdnSelectorItem{
		matchName: "test.antrea.io",
	}
	selectorItem2 := fqdnSelectorItem{
		matchRegex: "^.*antrea[.]io$",
	}
	selectorItem3 := fqdnSelectorItem{
		matchName: "maps.google.com",
	}
	tests := []struct {
		name                    string
		previouslyAddedRules    []fqdnRuleAddArgs
		existingDNSCache        map[string]dnsMeta
		ruleID                  string
		fqdns                   []string
		finalSelectorToRuleIDs  map[fqdnSelectorItem]sets.Set[string]
		finalFQDNToSelectorItem map[string]sets.Set[fqdnSelectorItem]
		addressRemoved          bool
	}{
		{
			"test-1",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"test.antrea.io"},
					sets.New[int32](1),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			"mockRule1",
			[]string{"test.antrea.io"},
			map[fqdnSelectorItem]sets.Set[string]{},
			map[string]sets.Set[fqdnSelectorItem]{},
			true,
		},
		{
			"test-2",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"test.antrea.io"},
					sets.New[int32](1),
				},
				{
					"mockRule2",
					[]string{"test.antrea.io"},
					sets.New[int32](2),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			"mockRule1",
			[]string{"test.antrea.io"},
			map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule2"),
			},
			map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem1),
			},
			true,
		},
		{
			"test-3",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"test.antrea.io"},
					sets.New[int32](1),
				},
				{
					"mockRule2",
					[]string{"*antrea.io"},
					sets.New[int32](2),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			"mockRule1",
			[]string{"test.antrea.io"},
			map[fqdnSelectorItem]sets.Set[string]{
				selectorItem2: sets.New[string]("mockRule2"),
			},
			map[string]sets.Set[fqdnSelectorItem]{
				"test.antrea.io": sets.New(selectorItem2),
			},
			true,
		},
		{
			"test-4",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"maps.google.com"},
					sets.New[int32](1),
				},
				{
					"mockRule2",
					[]string{"*antrea.io"},
					sets.New[int32](2),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io":  {},
				"maps.google.com": {},
			},
			"mockRule2",
			[]string{"*antrea.io"},
			map[fqdnSelectorItem]sets.Set[string]{
				selectorItem3: sets.New[string]("mockRule1"),
			},
			map[string]sets.Set[fqdnSelectorItem]{
				"maps.google.com": sets.New(selectorItem3),
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			f, c := newMockFQDNController(t, controller, nil, nil, 0)
			c.EXPECT().AddAddressToDNSConjunction(dnsInterceptRuleID, gomock.Any()).Times(len(tt.previouslyAddedRules))
			f.dnsEntryCache = tt.existingDNSCache
			if tt.addressRemoved {
				c.EXPECT().DeleteAddressFromDNSConjunction(dnsInterceptRuleID, gomock.Any()).Times(1)
			}
			for _, r := range tt.previouslyAddedRules {
				require.NoError(t, f.addFQDNRule(r.ruleID, r.fqdns, r.podOFAddresses), "Error when adding FQDN rule")
			}
			require.NoError(t, f.deleteFQDNRule(tt.ruleID, tt.fqdns), "Error when deleting FQDN rule")
			assert.Equal(t, tt.finalSelectorToRuleIDs, f.selectorItemToRuleIDs)
			assert.Equal(t, tt.finalFQDNToSelectorItem, f.fqdnToSelectorItem)
		})
	}
}

func TestLookupIPFallback(t *testing.T) {
	controller := gomock.NewController(t)
	dnsServer := "" // force a fallback to local resolver
	f, _ := newMockFQDNController(t, controller, &dnsServer, nil, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// not ideal as a unit test because it requires the ability to resolve
	// DNS names, but we don't expect this to be an actual problem.
	err := f.lookupIP(ctx, "www.google.com")
	require.NoError(t, err, "Error when resolving name")
}

func TestString(t *testing.T) {
	tests := []struct {
		name           string
		selectorItem   *fqdnSelectorItem
		expectedOutput string
	}{
		{
			name: "matching the regex",
			selectorItem: &fqdnSelectorItem{
				matchRegex: "^.*antrea[.]io$",
			},
			expectedOutput: "matchRegex:^.*antrea[.]io$",
		},
		{
			name: "matching the name",
			selectorItem: &fqdnSelectorItem{
				matchName: "test.antrea.io",
			},
			expectedOutput: "matchName:test.antrea.io",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOutput := tc.selectorItem.String()
			assert.Equal(t, tc.expectedOutput, gotOutput)
		})
	}
}

func TestGetIPsForFQDNSelectors(t *testing.T) {
	selectorItem := fqdnSelectorItem{
		matchName: "test.antrea.io",
	}
	tests := []struct {
		name                       string
		fqdns                      []string
		existingSelectorItemToFQDN map[fqdnSelectorItem]sets.Set[string]
		existingDNSCache           map[string]dnsMeta
		expectedMatchedIPs         []net.IP
	}{
		{
			name:  "matched ip found",
			fqdns: []string{"test.antrea.io"},
			existingSelectorItemToFQDN: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem: sets.New[string]("test.antrea.io"),
			},
			existingDNSCache: map[string]dnsMeta{
				"test.antrea.io": {
					responseIPs: map[string]ipWithExpiration{
						"127.0.0.1":    {net.ParseIP("127.0.0.1"), time.Now()},
						"192.155.12.1": {net.ParseIP("192.155.12.1"), time.Now()},
						"192.158.1.38": {net.ParseIP("192.158.1.38"), time.Now()},
					},
				},
			},
			expectedMatchedIPs: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.155.12.1"), net.ParseIP("192.158.1.38")},
		},
		{
			name:               "no matched ip",
			fqdns:              []string{"^.*antrea[.]io$"},
			expectedMatchedIPs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			f, _ := newMockFQDNController(t, controller, nil, nil, 0)
			if tc.existingSelectorItemToFQDN != nil {
				f.selectorItemToFQDN = tc.existingSelectorItemToFQDN
			}
			if tc.existingDNSCache != nil {
				f.dnsEntryCache = tc.existingDNSCache
			}
			gotOutput := f.getIPsForFQDNSelectors(tc.fqdns)
			assert.ElementsMatch(t, tc.expectedMatchedIPs, gotOutput)
		})
	}
}

func TestSyncDirtyRules(t *testing.T) {
	testFQDN := "test.antrea.io"
	selectorItem := fqdnSelectorItem{
		matchName: testFQDN,
	}
	testFQDN2 := "dev.antrea.io"
	selectorItem2 := fqdnSelectorItem{
		matchName: testFQDN2,
	}
	testFQDN3 := "*antrea.io"
	selectorItem3 := fqdnSelectorItem{
		matchRegex: testFQDN3,
	}
	tests := []struct {
		name                        string
		fqdnsToSync                 []string
		waitChs                     []chan error
		addressUpdates              []bool
		prevDirtyRules              sets.Set[string]
		notifications               []ruleRealizationUpdate
		expectedDirtyRuleSyncCalls  []string
		expectedDirtyRulesRemaining sets.Set[string]
		expectErr                   bool
	}{
		{
			name:                        "test non-blocking dirty rule sync without address update",
			fqdnsToSync:                 []string{testFQDN},
			prevDirtyRules:              sets.New[string](),
			addressUpdates:              []bool{false},
			waitChs:                     []chan error{nil},
			notifications:               []ruleRealizationUpdate{},
			expectedDirtyRuleSyncCalls:  []string{},
			expectedDirtyRulesRemaining: sets.New[string](),
			expectErr:                   false,
		},
		{
			name:                        "test non-blocking dirty rule sync with address update",
			fqdnsToSync:                 []string{testFQDN},
			prevDirtyRules:              sets.New[string](),
			addressUpdates:              []bool{true},
			waitChs:                     []chan error{nil},
			notifications:               []ruleRealizationUpdate{{"1", nil}, {"2", nil}},
			expectedDirtyRuleSyncCalls:  []string{"1", "2"},
			expectedDirtyRulesRemaining: sets.New[string](),
			expectErr:                   false,
		},
		{
			name:                        "test blocking dirty rule sync with address update",
			fqdnsToSync:                 []string{testFQDN},
			prevDirtyRules:              sets.New[string](),
			waitChs:                     []chan error{make(chan error, 1)},
			addressUpdates:              []bool{true},
			notifications:               []ruleRealizationUpdate{{"1", nil}, {"2", nil}},
			expectedDirtyRuleSyncCalls:  []string{"1", "2"},
			expectedDirtyRulesRemaining: sets.New[string](),
			expectErr:                   false,
		},
		{
			name:                        "test blocking dirty rule sync with failed rule realization",
			fqdnsToSync:                 []string{testFQDN},
			prevDirtyRules:              sets.New[string](),
			waitChs:                     []chan error{make(chan error, 1)},
			addressUpdates:              []bool{true},
			notifications:               []ruleRealizationUpdate{{"1", nil}, {"2", fmt.Errorf("ovs err")}},
			expectedDirtyRuleSyncCalls:  []string{"1", "2"},
			expectedDirtyRulesRemaining: sets.New[string]("2"),
			expectErr:                   true,
		},
		{
			name:                        "test blocking dirty rule sync without address update but previously failed rule realization",
			fqdnsToSync:                 []string{testFQDN},
			prevDirtyRules:              sets.New[string]("2"),
			waitChs:                     []chan error{make(chan error, 1)},
			addressUpdates:              []bool{false},
			notifications:               []ruleRealizationUpdate{{"2", nil}},
			expectedDirtyRuleSyncCalls:  []string{"2"},
			expectedDirtyRulesRemaining: sets.New[string](),
			expectErr:                   false,
		},
		{
			name:                        "test blocking dirty rule sync without address update",
			fqdnsToSync:                 []string{testFQDN},
			prevDirtyRules:              sets.New[string](),
			waitChs:                     []chan error{make(chan error, 1)},
			addressUpdates:              []bool{false},
			notifications:               []ruleRealizationUpdate{},
			expectedDirtyRuleSyncCalls:  []string{},
			expectedDirtyRulesRemaining: sets.New[string](),
			expectErr:                   false,
		},
		{
			name:                        "test blocking single dirty rule multiple FQDN concurrent updates",
			fqdnsToSync:                 []string{testFQDN, testFQDN2},
			prevDirtyRules:              sets.New[string](),
			waitChs:                     []chan error{make(chan error, 1), make(chan error, 1)},
			addressUpdates:              []bool{true, false},
			notifications:               []ruleRealizationUpdate{{"1", nil}, {"2", nil}},
			expectedDirtyRuleSyncCalls:  []string{"1", "2", "2"},
			expectedDirtyRulesRemaining: sets.New[string](),
			expectErr:                   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			f, _ := newMockFQDNController(t, controller, nil, nil, 0)
			var dirtyRuleSyncCalls []string
			f.dirtyRuleHandler = func(s string) {
				dirtyRuleSyncCalls = append(dirtyRuleSyncCalls, s)
			}
			f.addFQDNSelector("1", []string{testFQDN})
			f.addFQDNSelector("1", []string{testFQDN3})
			f.addFQDNSelector("2", []string{testFQDN})
			f.addFQDNSelector("2", []string{testFQDN2})
			f.setFQDNMatchSelector(testFQDN, selectorItem)
			f.setFQDNMatchSelector(testFQDN2, selectorItem2)
			f.setFQDNMatchSelector(testFQDN, selectorItem3)
			f.setFQDNMatchSelector(testFQDN2, selectorItem3)
			// This simulates failed rule syncs in previous syncDirtyRules() calls
			if len(tc.prevDirtyRules) > 0 {
				f.ruleSyncTracker.dirtyRules = tc.prevDirtyRules
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			go f.runRuleSyncTracker(stopCh)

			for i, fqdn := range tc.fqdnsToSync {
				f.syncDirtyRules(fqdn, tc.waitChs[i], tc.addressUpdates[i])
			}
			for _, update := range tc.notifications {
				f.ruleSyncTracker.updateCh <- update
			}
			assert.ElementsMatch(t, tc.expectedDirtyRuleSyncCalls, dirtyRuleSyncCalls)
			for _, waitCh := range tc.waitChs {
				if waitCh != nil {
					assert.Eventually(t, func() bool {
						select {
						case err := <-waitCh:
							if err != nil && !tc.expectErr {
								return false
							}
						}
						return true
					}, ruleRealizationTimeout, time.Millisecond*10, "Failed to successfully wait for rule syncs")
				}
			}
			assert.Equal(t, tc.expectedDirtyRulesRemaining, f.ruleSyncTracker.getDirtyRules())
		})
	}
}

func TestOnDNSResponse(t *testing.T) {
	testFQDN := "fqdn-test-pod.lfx.test"
	selectorItem1 := fqdnSelectorItem{
		matchName: testFQDN,
	}
	selectorItem2 := fqdnSelectorItem{
		matchName: "random-domain.com",
	}
	currentTime := time.Now()

	tests := []struct {
		name                  string
		existingDNSCache      map[string]dnsMeta
		dnsResponseIPs        map[string]ipWithExpiration
		expectedIPs           map[string]ipWithExpiration
		expectedRequeryAfter  *time.Duration
		mockSelectorToRuleIDs map[fqdnSelectorItem]sets.Set[string]
	}{
		{
			name: "new IP added",
			existingDNSCache: map[string]dnsMeta{
				testFQDN: {
					responseIPs: map[string]ipWithExpiration{
						"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
						"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(6 * time.Second)},
					},
				},
			},
			dnsResponseIPs: map[string]ipWithExpiration{
				"192.1.1.3": {ip: net.ParseIP("192.1.1.3"), expirationTime: currentTime.Add(10 * time.Second)},
			},
			expectedIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
				"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(6 * time.Second)},
				"192.1.1.3": {ip: net.ParseIP("192.1.1.3"), expirationTime: currentTime.Add(10 * time.Second)},
			},
			expectedRequeryAfter: ptr.To(5 * time.Second),
		},
		{
			name: "empty DNS response",
			existingDNSCache: map[string]dnsMeta{
				testFQDN: {
					responseIPs: map[string]ipWithExpiration{
						"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
						"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(6 * time.Second)},
					},
				},
			},
			dnsResponseIPs: map[string]ipWithExpiration{},
			expectedIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
				"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(6 * time.Second)},
			},
		},
		{
			name: "old IP present in DNS response is retained with an updated TTL fetched from response",
			existingDNSCache: map[string]dnsMeta{
				testFQDN: {
					responseIPs: map[string]ipWithExpiration{
						"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
						"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(1 * time.Second)},
					},
				},
			},
			dnsResponseIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(1 * time.Second)},
				"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
				"192.1.1.2": {ip: net.ParseIP("192.1.1.2"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedRequeryAfter: ptr.To(5 * time.Second),
		},
		{
			name: "stale IP with expired TTL is evicted",
			existingDNSCache: map[string]dnsMeta{
				testFQDN: {
					responseIPs: map[string]ipWithExpiration{
						"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(-1 * time.Second)},
					},
				},
			},
			dnsResponseIPs: map[string]ipWithExpiration{
				"192.1.1.3": {ip: net.ParseIP("192.1.1.3"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedIPs: map[string]ipWithExpiration{
				"192.1.1.3": {ip: net.ParseIP("192.1.1.3"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedRequeryAfter: ptr.To(5 * time.Second),
		},
		{
			name:             "existingDNSCache is empty, the new response matches a selector.",
			existingDNSCache: map[string]dnsMeta{},
			dnsResponseIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedRequeryAfter: ptr.To(5 * time.Second),
			mockSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem1: sets.New[string]("mockRule1"),
			},
		},
		{
			name:             "existingDNSCache is empty, the new response doesn't match any selector",
			existingDNSCache: map[string]dnsMeta{},
			dnsResponseIPs: map[string]ipWithExpiration{
				"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
			},
			expectedIPs: nil,
			mockSelectorToRuleIDs: map[fqdnSelectorItem]sets.Set[string]{
				selectorItem2: sets.New[string]("mockRule2"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClock := newFakeClock(currentTime)
			controller := gomock.NewController(t)
			f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
			f.dnsEntryCache = tc.existingDNSCache
			if tc.mockSelectorToRuleIDs != nil {
				f.selectorItemToRuleIDs = tc.mockSelectorToRuleIDs
			}
			require.Zero(t, fakeClock.TimersAdded())

			f.onDNSResponse(testFQDN, tc.dnsResponseIPs, nil)

			cachedDnsMetaData, _ := f.dnsEntryCache[testFQDN]

			assert.Equal(t, tc.expectedIPs, cachedDnsMetaData.responseIPs, "FQDN cache doesn't match expected entries")

			if tc.expectedRequeryAfter != nil {
				// Wait for the DelayingQueue to create the timer which signals that the
				// DNS request for the FQDN item is ready to be sent.
				require.Eventually(t, func() bool { return fakeClock.TimersAdded() > 0 }, 1*time.Second, 10*time.Millisecond)

				fakeClock.Step(*tc.expectedRequeryAfter)
				// needed to avoid blocking on Get() in case of failure
				require.Eventually(t, func() bool { return f.dnsQueryQueue.Len() > 0 }, 1*time.Second, 10*time.Millisecond)
				item, _ := f.dnsQueryQueue.Get()
				f.dnsQueryQueue.Done(item)
				assert.Equal(t, testFQDN, item)
			} else {
				// make sure that there is no requery
				assert.Never(t, func() bool { return f.dnsQueryQueue.Len() > 0 }, 100*time.Millisecond, 10*time.Millisecond)
			}
		})
	}
}

// TestParseDNSResponseOnFQDNCacheMinTTL tests the behavior of the parseDNSResponse function when
// handling DNS responses with varying TTL values, and checks if the TTL used for caching respects
// the minimum TTL (fqdnCacheMinTTL) for a given Fully Qualified Domain Name (FQDN).
func TestParseDNSResponseOnFQDNCacheMinTTL(t *testing.T) {
	currentTime := time.Now()
	testIPv4 := "192.168.1.1"
	testIPv6 := "2001:db8::1"
	testFQDN := "fqdn-test-pod.lfx.test"
	getDNSMsg := func(ttl uint32) *dns.Msg {
		return &dns.Msg{
			Question: []dns.Question{
				{Name: testFQDN, Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: testFQDN, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   testFQDN,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					A: net.ParseIP(testIPv4),
				},
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   testFQDN,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					AAAA: net.ParseIP(testIPv6),
				},
			},
		}
	}
	tests := []struct {
		name            string
		expectedTTL     time.Duration
		fqdnCacheMinTTL uint32
		responseTTL     uint32
	}{
		{
			name:            "Response TTL less than fqdnCacheMinTTL",
			expectedTTL:     10,
			fqdnCacheMinTTL: 10,
			responseTTL:     5,
		},
		{
			name:            "Response TTL more than fqdnCacheMinTTL",
			expectedTTL:     10,
			fqdnCacheMinTTL: 5,
			responseTTL:     10,
		},
		{
			name:            "Response TTL equal to fqdnCacheMinTTL",
			expectedTTL:     5,
			fqdnCacheMinTTL: 5,
			responseTTL:     5,
		},
		{
			name:            "fqdnCacheMinTTL is not set",
			expectedTTL:     5,
			fqdnCacheMinTTL: 0,
			responseTTL:     5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClock := newFakeClock(currentTime)
			controller := gomock.NewController(t)
			f, _ := newMockFQDNController(t, controller, nil, fakeClock, tc.fqdnCacheMinTTL)
			f.ipv6Enabled = true // this test needs IPv6 enabled
			dnsMsg := getDNSMsg(tc.responseTTL)
			_, responseIPs, err := f.parseDNSResponse(dnsMsg)
			require.NoError(t, err)
			expectedExpirationTime := currentTime.Add(tc.expectedTTL * time.Second)
			assert.Equal(t, expectedExpirationTime, responseIPs[testIPv4].expirationTime)
			assert.Equal(t, expectedExpirationTime, responseIPs[testIPv6].expirationTime)
		})
	}
}
