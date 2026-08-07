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
	kmetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/testutil"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/metrics"
	openflowtest "antrea.io/antrea/v2/pkg/agent/openflow/testing"
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
		newIDAllocator(MinAllocatorAsyncDeleteInterval),
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

// isTracked returns whether fqdn is selected by at least one fqdnSelectorItem. Only
// the tests need to ask this of a fqdnCache, hence its definition here.
func (c *fqdnCache) isTracked(fqdn string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	_, ok := c.entries[fqdn]
	return ok
}

// isSelectedBy returns whether fqdn is currently tracked for selectorItem. It is
// false for a FQDN which selectorItem selects but has evicted. Only the tests need
// to ask this of a fqdnCache, hence its definition here.
func (c *fqdnCache) isSelectedBy(fqdn string, selectorItem fqdnSelectorItem) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.entries[fqdn]
	if !ok {
		return false
	}
	_, ok = entry.selectorElems[selectorItem]
	return ok
}

// size returns the number of tracked FQDNs. Only the tests need to ask this of a
// fqdnCache, hence its definition here.
func (c *fqdnCache) size() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return len(c.entries)
}

// seedFQDNCacheForTest brings the fqdnCache of f to a given state: each FQDN of
// fqdnToSelectorItem starts being tracked for the fqdnSelectorItems which select
// it, and the FQDNs of dnsCache are recorded as resolved. It is the equivalent, for
// the tests which need to start from an existing state, of assigning the maps which
// the fqdnCache replaced.
func seedFQDNCacheForTest(f *fqdnController, dnsCache map[string]dnsMeta, fqdnToSelectorItem map[string]sets.Set[fqdnSelectorItem]) {
	for fqdn, selectorItems := range fqdnToSelectorItem {
		for selectorItem := range selectorItems {
			f.fqdnCache.track(fqdn, selectorItem)
		}
	}
	for fqdn, meta := range dnsCache {
		f.fqdnCache.setResolved(fqdn, meta, f.clock.Now().Add(time.Hour))
	}
}

// resolveFQDNForTest tracks fqdn for every fqdnSelectorItem known to f which selects
// it and records it as resolved, as the processing of a DNS response would.
func resolveFQDNForTest(f *fqdnController, fqdn string, meta dnsMeta) {
	f.fqdnSelectorMutex.Lock()
	defer f.fqdnSelectorMutex.Unlock()
	for selectorItem := range f.selectorItemToRuleIDs {
		if f.matches(selectorItem, fqdn) {
			f.fqdnCache.track(fqdn, selectorItem)
		}
	}
	f.fqdnCache.setResolved(fqdn, meta, f.clock.Now().Add(time.Hour))
}

// trackedFQDNsForTest returns the FQDNs tracked by f, mapped to the
// fqdnSelectorItems which select them.
func trackedFQDNsForTest(f *fqdnController) map[string]sets.Set[fqdnSelectorItem] {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	tracked := map[string]sets.Set[fqdnSelectorItem]{}
	for fqdn, entry := range f.fqdnCache.entries {
		selectorItems := sets.New[fqdnSelectorItem]()
		for selectorItem := range entry.selectorElems {
			selectorItems.Insert(selectorItem)
		}
		tracked[fqdn] = selectorItems
	}
	return tracked
}

// entryForTest returns the fqdnCacheEntry which currently tracks fqdn, for the tests
// which need to call the methods taking one without going through nextDue.
func entryForTest(f *fqdnController, fqdn string) *fqdnCacheEntry {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	return f.fqdnCache.entries[fqdn]
}

// isQueryingForTest returns whether a worker is making a DNS query for entry.
func isQueryingForTest(f *fqdnController, entry *fqdnCacheEntry) bool {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	return entry.querying
}

// requeryAtForTest returns the time at which the next DNS query for fqdn is
// scheduled, and whether one is scheduled at all.
func requeryAtForTest(f *fqdnController, fqdn string) (time.Time, bool) {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	entry, ok := f.fqdnCache.entries[fqdn]
	if !ok || entry.heapIndex == notScheduled {
		return time.Time{}, false
	}
	return entry.requeryAt, true
}

// scheduledFQDNsForTest returns the FQDNs which have a DNS query scheduled.
func scheduledFQDNsForTest(f *fqdnController) []string {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	fqdns := make([]string, 0, len(f.fqdnCache.scheduled))
	for _, entry := range f.fqdnCache.scheduled {
		fqdns = append(fqdns, entry.fqdn)
	}
	return fqdns
}

// clearScheduleForTest cancels every scheduled DNS query, so that a test which seeds
// the cache can assert on the queries scheduled by the code under test alone.
func clearScheduleForTest(f *fqdnController) {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	for _, entry := range f.fqdnCache.scheduled {
		entry.heapIndex = notScheduled
	}
	f.fqdnCache.scheduled = nil
}

// scheduledCountForTest returns the number of FQDNs which have a DNS query scheduled.
func scheduledCountForTest(f *fqdnController) int {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	return len(f.fqdnCache.scheduled)
}

// subscribedRulesForTest returns the rules whose realization a DNS response is
// currently held on.
func subscribedRulesForTest(f *fqdnController) []string {
	f.ruleSyncTracker.mutex.RLock()
	defer f.ruleSyncTracker.mutex.RUnlock()
	rules := make([]string, 0, len(f.ruleSyncTracker.ruleToSubscribers))
	for ruleID := range f.ruleSyncTracker.ruleToSubscribers {
		rules = append(rules, ruleID)
	}
	return rules
}

// dueFQDNsForTest returns the FQDNs whose DNS query is due, without waiting for any
// to become due.
func dueFQDNsForTest(f *fqdnController) []string {
	f.fqdnCache.mutex.Lock()
	defer f.fqdnCache.mutex.Unlock()
	var due []string
	now := f.fqdnCache.clock.Now()
	for _, entry := range f.fqdnCache.scheduled {
		if !entry.requeryAt.After(now) {
			due = append(due, entry.fqdn)
		}
	}
	return due
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
			}
			if tt.existingFQDNToSelectedPods != nil {
				f.fqdnRuleToSelectedPods = tt.existingFQDNToSelectedPods
			}
			seedFQDNCacheForTest(f, tt.existingDNSCache, tt.existingFQDNToSelectorItem)
			require.NoError(t, f.addFQDNRule(tt.ruleID, tt.fqdns, tt.podAddrs), "Error when adding FQDN rule")
			assert.Equal(t, tt.finalSelectorToRuleIDs, f.selectorItemToRuleIDs)
			assert.Equal(t, tt.finalFQDNToSelectorItem, trackedFQDNsForTest(f))
			assert.ElementsMatch(t, tt.enqueuedFQDNs, dueFQDNsForTest(f))
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
			if tt.addressRemoved {
				c.EXPECT().DeleteAddressFromDNSConjunction(dnsInterceptRuleID, gomock.Any()).Times(1)
			}
			for _, r := range tt.previouslyAddedRules {
				require.NoError(t, f.addFQDNRule(r.ruleID, r.fqdns, r.podOFAddresses), "Error when adding FQDN rule")
			}
			// The FQDNs which were already resolved when the rules were added start being
			// tracked for the selectors of these rules which select them.
			for fqdn, meta := range tt.existingDNSCache {
				resolveFQDNForTest(f, fqdn, meta)
			}
			require.NoError(t, f.deleteFQDNRule(tt.ruleID, tt.fqdns), "Error when deleting FQDN rule")
			assert.Equal(t, tt.finalSelectorToRuleIDs, f.selectorItemToRuleIDs)
			assert.Equal(t, tt.finalFQDNToSelectorItem, trackedFQDNsForTest(f))
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
			for selectorItem, fqdns := range tc.existingSelectorItemToFQDN {
				f.selectorItemToRuleIDs[selectorItem] = sets.New[string]("mockRule")
				for fqdn := range fqdns {
					f.fqdnCache.track(fqdn, selectorItem)
				}
			}
			seedFQDNCacheForTest(f, tc.existingDNSCache, nil)
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
			f.fqdnCache.track(testFQDN, selectorItem)
			f.fqdnCache.track(testFQDN2, selectorItem2)
			f.fqdnCache.track(testFQDN, selectorItem3)
			f.fqdnCache.track(testFQDN2, selectorItem3)
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
						err := <-waitCh
						return err == nil || tc.expectErr
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
		name             string
		existingDNSCache map[string]dnsMeta
		dnsResponseIPs   map[string]ipWithExpiration
		// fromPod reports whether the resolution was initiated by a client Pod and its
		// response intercepted, as opposed to being one of the DNS queries which the
		// fqdnController makes itself. It is the only way a FQDN which no fqdnSelectorItem
		// names explicitly, and which is therefore not tracked yet, can be resolved.
		fromPod               bool
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
			fromPod:     true,
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
			if tc.mockSelectorToRuleIDs != nil {
				f.selectorItemToRuleIDs = tc.mockSelectorToRuleIDs
			}
			// A fqdnSelectorItem which selects a FQDN by exact name starts tracking it as soon
			// as the selector is added, before the first DNS query for it completes (see
			// addFQDNSelector).
			for selectorItem := range f.selectorItemToRuleIDs {
				if selectorItem.matchRegex == "" {
					f.fqdnCache.track(selectorItem.matchName, selectorItem)
				}
			}
			// The FQDNs which are already in the cache are tracked for the selector which
			// selects them by exact name.
			for fqdn, meta := range tc.existingDNSCache {
				f.fqdnCache.track(fqdn, fqdnSelectorItem{matchName: fqdn})
				f.fqdnCache.setResolved(fqdn, meta, currentTime.Add(time.Hour))
			}
			// Only the DNS queries which onDNSResponse schedules are of interest here.
			clearScheduleForTest(f)

			var waitCh chan error
			if tc.fromPod {
				// The channel is buffered so that syncDirtyRules never blocks on it.
				waitCh = make(chan error, 1)
			}
			f.onDNSResponse(testFQDN, tc.dnsResponseIPs, waitCh)

			cachedDnsMetaData, _, _ := f.fqdnCache.meta(testFQDN)
			assert.Equal(t, tc.expectedIPs, cachedDnsMetaData.responseIPs, "FQDN cache doesn't match expected entries")

			requeryAt, scheduled := requeryAtForTest(f, testFQDN)
			if tc.expectedRequeryAfter != nil {
				// The DNS query which refreshes the IPs of the FQDN must be scheduled for
				// when the first of them expires.
				require.True(t, scheduled, "A DNS query must be scheduled for the FQDN")
				assert.Equal(t, currentTime.Add(*tc.expectedRequeryAfter), requeryAt)
			} else {
				assert.False(t, scheduled, "No DNS query must be scheduled for the FQDN")
			}
		})
	}
}

// expectedFQDNsPerSelectorCap and expectedTrackedFQDNsCap are the expected values of
// maxFQDNsPerSelector and maxTrackedFQDNs. They are kept as literals (rather than
// referencing the production constants) so that the tests below fail on the
// behavior, and not just on the compile, if either cap is removed.
const (
	expectedFQDNsPerSelectorCap = 1024
	expectedTrackedFQDNsCap     = 10000
)

func TestFQDNCacheCaps(t *testing.T) {
	assert.Equal(t, expectedFQDNsPerSelectorCap, maxFQDNsPerSelector)
	assert.Equal(t, expectedTrackedFQDNsCap, maxTrackedFQDNs)
}

// shrinkFQDNCacheForTest replaces the fqdnCache of f with one using smaller caps, so
// that the tests which need to reach the global cap stay fast and readable. The
// production values are asserted by TestFQDNCacheCaps.
func shrinkFQDNCacheForTest(f *fqdnController, maxEntries, maxEntriesPerSelector int) {
	f.fqdnCache = newFQDNCache(f.clock, maxEntries, maxEntriesPerSelector)
}

// onDNSResponseFromPodForTest drives a single response with one IP through onDNSResponse, as if the
// name resolution had been initiated by a client Pod and the response intercepted, which is how
// FQDNs matching a wildcard selector are discovered.
func onDNSResponseFromPodForTest(f *fqdnController, fqdn string, currentTime time.Time) {
	// The channel is buffered so that syncDirtyRules never blocks on it.
	onDNSResponseForTest(f, fqdn, currentTime, make(chan error, 1))
}

// onDNSResponseFromRequeryForTest drives a single response with one IP through onDNSResponse, as if
// the name resolution had been initiated by the fqdnController itself, to refresh a FQDN whose TTL
// expired.
func onDNSResponseFromRequeryForTest(f *fqdnController, fqdn string, currentTime time.Time) {
	onDNSResponseForTest(f, fqdn, currentTime, nil)
}

func onDNSResponseForTest(f *fqdnController, fqdn string, currentTime time.Time, waitCh chan error) {
	f.onDNSResponse(fqdn, map[string]ipWithExpiration{
		"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(5 * time.Second)},
	}, waitCh)
}

// recordDirtyRulesForTest makes f record the rules reported as dirty into the
// returned slice. The state which the ruleSyncTracker accumulated so far is reset
// first: no test runs it, so the dirty rules of the previous responses would
// otherwise be reported as dirty again by any subsequent blocking sync, and the
// rules these responses were held on would still be subscribed to, regardless of
// what the test exercises.
func recordDirtyRulesForTest(f *fqdnController) *[]string {
	f.ruleSyncTracker.dirtyRules = sets.New[string]()
	f.ruleSyncTracker.ruleToSubscribers = map[string][]*subscriber{}
	dirtyRules := &[]string{}
	f.dirtyRuleHandler = func(rule string) { *dirtyRules = append(*dirtyRules, rule) }
	return dirtyRules
}

// TestOnDNSResponseWildcardSelectorCap verifies that the number of distinct FQDNs tracked for a
// single wildcard fqdnSelectorItem is bounded. A Pod selected by a wildcard toFQDN rule can resolve
// arbitrarily many distinct matching names; without a cap, every distinct name would add a permanent
// entry to the FQDN tracking state, growing memory without bound.
func TestOnDNSResponseWildcardSelectorCap(t *testing.T) {
	currentTime := time.Now()
	wildcardSelector := fqdnToSelectorItem("*.wildcard-cap.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	// Resolve more distinct matching names than the per-selector cap allows.
	for i := 0; i < expectedCap+100; i++ {
		onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.wildcard-cap.example", i), currentTime)
	}

	// Growth of all per-selector state must plateau at the cap, not at the number of names resolved.
	assert.Len(t, f.fqdnCache.fqdnsFor(wildcardSelector), expectedCap,
		"FQDNs tracked for the wildcard selector must be capped")
	assert.Equal(t, expectedCap, f.fqdnCache.size(), "the FQDN cache must be capped")
	// Evicting a FQDN also cancels the DNS query which was scheduled for it, so the
	// schedule cannot grow past the cache either.
	assert.Equal(t, expectedCap, scheduledCountForTest(f), "the DNS query schedule must be capped")
}

// TestOnDNSResponseGlobalCap verifies that the total number of tracked FQDNs is bounded across
// selectors. The per-selector cap alone bounds the tracking state at the number of selectors times
// maxFQDNsPerSelector, so a cluster with many wildcard rules could still grow the memory used by
// the Agent well beyond what it should use.
func TestOnDNSResponseGlobalCap(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	// 3 selectors of 4 FQDNs each would need 12 entries, 2 more than the global cap.
	const maxEntries, maxPerSelector = 10, 4
	shrinkFQDNCacheForTest(f, maxEntries, maxPerSelector)

	selectors := map[string]fqdnSelectorItem{}
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{}
	for _, domain := range []string{"a", "b", "c"} {
		selectorItem := fqdnToSelectorItem(fmt.Sprintf("*.%s.example", domain))
		selectors[domain] = selectorItem
		f.selectorItemToRuleIDs[selectorItem] = sets.New[string]("mockRule-" + domain)
	}
	for _, domain := range []string{"a", "b"} {
		for i := 0; i < maxPerSelector; i++ {
			onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.%s.example", i, domain), currentTime)
		}
	}
	// Only the rules reported as dirty while resolving names for the third selector
	// are of interest: the rules of the first two were already resynced as their own
	// names were resolved.
	dirtyRules := recordDirtyRulesForTest(f)
	for i := 0; i < maxPerSelector; i++ {
		onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.c.example", i), currentTime)
	}

	assert.Equal(t, maxEntries, f.fqdnCache.size(), "the FQDN cache must be capped globally")
	assert.Equal(t, maxEntries, scheduledCountForTest(f), "the DNS query schedule must be capped globally")
	// The two least-recently-resolved names overall are the first two resolved for the
	// first selector, so that selector is the one which loses them.
	assert.ElementsMatch(t, []string{"h2.a.example", "h3.a.example"}, f.fqdnCache.fqdnsFor(selectors["a"]),
		"the globally least-recently-used FQDNs must be the ones evicted")
	assert.Len(t, f.fqdnCache.fqdnsFor(selectors["b"]), maxPerSelector)
	assert.Len(t, f.fqdnCache.fqdnsFor(selectors["c"]), maxPerSelector)
	// Evicting a FQDN of one selector while resolving a name for another one must
	// still re-realize the rules of the selector which lost it, as their addresses
	// changed even though the FQDN being resolved does not concern them.
	assert.Contains(t, *dirtyRules, "mockRule-a",
		"the rules of the selector which lost a FQDN to the global cap must be resynced")
	// The DNS response of the client Pod is only held until the rules which select the
	// FQDN it resolved are realized. Holding it until the rules of the selector which
	// lost a FQDN are realized too would make every DNS response for a new name wait
	// for the realization of unrelated rules, as an eviction happens for every new name
	// once the cache is at its limit.
	assert.NotContains(t, subscribedRulesForTest(f), "mockRule-a",
		"the DNS response must not be held on the rules of the selector which lost a FQDN")
	assert.Contains(t, subscribedRulesForTest(f), "mockRule-c",
		"the DNS response must be held on the rules which select the FQDN which was resolved")
}

// TestOnDNSResponseGlobalCapKeepsExactNames verifies that a FQDN which a policy names explicitly is
// never evicted to honor the global cap. Exact names are bounded by the number of selectors which
// the cluster admin creates, while evicting one would stop a rule from matching a name it lists,
// and nothing would re-track it until a selected Pod resolves it again.
func TestOnDNSResponseGlobalCapKeepsExactNames(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	const maxEntries, maxPerSelector = 2, 4
	shrinkFQDNCacheForTest(f, maxEntries, maxPerSelector)

	// The exact name is tracked first, hence it would be the least recently used FQDN
	// if it were subject to the global cap at all.
	f.addFQDNSelector("mockExactRule", []string{"pinned.example"})
	wildcardSelector := fqdnToSelectorItem("*.w.example")
	f.selectorItemToRuleIDs[wildcardSelector] = sets.New[string]("mockWildcardRule")
	for i := 0; i < maxEntries+1; i++ {
		onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.w.example", i), currentTime)
	}

	assert.True(t, f.fqdnCache.isTracked("pinned.example"),
		"a FQDN selected by exact name must not be evicted to honor the global cap")
	assert.False(t, f.fqdnCache.isTracked("h0.w.example"),
		"the least-recently-used FQDN which no selector names explicitly must be evicted instead")
	// The exact name does not count against the cap, hence one more entry than it.
	assert.Equal(t, maxEntries+1, f.fqdnCache.size())
}

// TestGlobalCapAppliesAgainWhenExactSelectorGoesAway verifies that a FQDN which was exempt from the
// global cap because a policy named it explicitly stops being exempt once that policy is deleted, so
// that a name which is only matched by a wildcard expression cannot stay tracked forever.
func TestGlobalCapAppliesAgainWhenExactSelectorGoesAway(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	const maxEntries, maxPerSelector = 2, 4
	shrinkFQDNCacheForTest(f, maxEntries, maxPerSelector)

	// h0 is selected both by exact name and by the wildcard expression.
	f.addFQDNSelector("mockExactRule", []string{"h0.w.example"})
	wildcardSelector := fqdnToSelectorItem("*.w.example")
	f.selectorItemToRuleIDs[wildcardSelector] = sets.New[string]("mockWildcardRule")
	for i := 0; i < maxEntries+1; i++ {
		onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.w.example", i), currentTime)
	}
	require.True(t, f.fqdnCache.isTracked("h0.w.example"))

	f.deleteFQDNSelector("mockExactRule", []string{"h0.w.example"})
	// h0 is now only selected by the wildcard expression, so resolving one more name
	// must be able to evict it as the least recently used one.
	onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.w.example", maxEntries+1), currentTime)

	assert.False(t, f.fqdnCache.isTracked("h0.w.example"),
		"a FQDN which no selector names explicitly anymore must be subject to the global cap")
	assert.Equal(t, maxEntries, f.fqdnCache.size())
}

// TestOnDNSResponseWildcardSelectorLRUEviction verifies that when a wildcard selector is at its cap,
// resolving a new name evicts the least-recently-used name rather than the new one, and that a name
// which a Pod is still resolving is kept (its recency is refreshed) instead of being evicted.
func TestOnDNSResponseWildcardSelectorLRUEviction(t *testing.T) {
	currentTime := time.Now()
	wildcardSelector := fqdnToSelectorItem("*.wildcard-lru.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	name := func(i int) string { return fmt.Sprintf("h%d.wildcard-lru.example", i) }

	// Fill the selector to its cap; recency order is now h0 (oldest) .. h1023 (newest).
	for i := 0; i < expectedCap; i++ {
		onDNSResponseFromPodForTest(f, name(i), currentTime)
	}
	require.Equal(t, expectedCap, f.fqdnCache.size())

	// A Pod is still resolving h0, which refreshes its recency and makes h1 the oldest.
	onDNSResponseFromPodForTest(f, name(0), currentTime)

	// Resolving a brand new name must evict the least-recently-used name (h1), not the new one.
	onDNSResponseFromPodForTest(f, name(expectedCap), currentTime)

	assert.Equal(t, expectedCap, f.fqdnCache.size(), "cache must stay at the cap")
	assert.True(t, f.fqdnCache.isTracked(name(expectedCap)), "the newly resolved name must be tracked")
	assert.True(t, f.fqdnCache.isTracked(name(0)), "a name which a Pod is still resolving must not be evicted")
	assert.False(t, f.fqdnCache.isTracked(name(1)), "the least-recently-used name must be evicted")
	assert.True(t, f.fqdnCache.isSelectedBy(name(0), wildcardSelector), "selector must still track the hot name")
	assert.False(t, f.fqdnCache.isSelectedBy(name(1), wildcardSelector), "selector must drop the evicted name")
}

// TestOnDNSResponseRequeryDoesNotRefreshRecency verifies that the DNS queries which the
// fqdnController makes itself, to refresh the FQDNs it tracks when their TTLs expire, do not refresh
// the recency of these FQDNs. Every tracked FQDN is re-queried, whether any Pod still uses it or
// not: if these re-queries refreshed recency, a FQDN which no Pod resolves anymore would keep itself
// tracked, and re-queried, indefinitely, and the eviction order would follow the TTL length of the
// records rather than actual usage.
func TestOnDNSResponseRequeryDoesNotRefreshRecency(t *testing.T) {
	currentTime := time.Now()
	wildcardSelector := fqdnToSelectorItem("*.wildcard-requery-recency.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	name := func(i int) string { return fmt.Sprintf("h%d.wildcard-requery-recency.example", i) }

	// Fill the selector to its cap; recency order is now h0 (oldest) .. h1023 (newest).
	for i := 0; i < expectedCap; i++ {
		onDNSResponseFromPodForTest(f, name(i), currentTime)
	}
	require.Equal(t, expectedCap, f.fqdnCache.size())

	// No Pod resolves h0 anymore; the fqdnController re-queries it on its own, which must not save
	// it from being evicted as the least-recently-used name.
	onDNSResponseFromRequeryForTest(f, name(0), currentTime)
	onDNSResponseFromPodForTest(f, name(expectedCap), currentTime)

	assert.Equal(t, expectedCap, f.fqdnCache.size(), "cache must stay at the cap")
	assert.False(t, f.fqdnCache.isTracked(name(0)), "a name which only the fqdnController resolves must be evicted")
	assert.True(t, f.fqdnCache.isTracked(name(1)), "a name which is not the least-recently-used one must be kept")
}

// TestOnDNSResponseReTracksFQDNEvictedFromOneSelector verifies that a fqdnSelectorItem starts
// tracking a FQDN again when a Pod resolves it after it was evicted. A FQDN evicted from one
// selector remains tracked if another selector still selects it, in which case all its subsequent
// resolutions are handled as updates of the existing entry: unless the selectors matching it are
// evaluated again on that path, the first selector would never track it again, and the rules using
// that selector would permanently stop matching a FQDN they select.
func TestOnDNSResponseReTracksFQDNEvictedFromOneSelector(t *testing.T) {
	currentTime := time.Now()
	name := func(i int) string { return fmt.Sprintf("h%d.wildcard-retrack.example", i) }
	wildcardSelector := fqdnToSelectorItem("*.wildcard-retrack.example")
	// A selector matching a single name by definition never reaches maxFQDNsPerSelector, so it
	// keeps h0 in the cache after the wildcard selector evicts it.
	exactSelector := fqdnToSelectorItem(name(0))

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockWildcardRule"),
		exactSelector:    sets.New[string]("mockExactRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	// h0 is resolved first, hence it is the least-recently-used name for the wildcard selector.
	onDNSResponseFromPodForTest(f, name(0), currentTime)
	// Resolving maxFQDNsPerSelector more names evicts h0 from the wildcard selector.
	for i := 1; i <= expectedCap; i++ {
		onDNSResponseFromPodForTest(f, name(i), currentTime)
	}
	require.False(t, f.fqdnCache.isSelectedBy(name(0), wildcardSelector))
	require.True(t, f.fqdnCache.isTracked(name(0)))

	dirtyRules := recordDirtyRulesForTest(f)

	// A Pod resolves h0 again: the wildcard selector still matches it, so it must be tracked again,
	// and the least-recently-used name must be evicted to make room for it.
	onDNSResponseFromPodForTest(f, name(0), currentTime)

	assert.True(t, f.fqdnCache.isSelectedBy(name(0), wildcardSelector), "the wildcard selector must track the FQDN again")
	assert.ElementsMatch(t, []fqdnSelectorItem{wildcardSelector, exactSelector}, f.fqdnCache.selectorsFor(name(0)))
	assert.Len(t, f.fqdnCache.fqdnsFor(wildcardSelector), expectedCap, "FQDNs tracked for the wildcard selector must stay capped")
	assert.False(t, f.fqdnCache.isTracked(name(1)), "the least-recently-used name must be evicted to make room")
	// The rules using the wildcard selector must be realized again, so that the addresses of the
	// FQDN are added back to them.
	assert.Contains(t, *dirtyRules, "mockWildcardRule", "the rules using the selector must be resynced")
}

// TestOnDNSResponseTrackedFQDNDoesNotDirtyRules verifies that a Pod re-resolving a FQDN which is
// already tracked, and whose IPs did not change, does not report any rule as dirty. Every DNS
// response of a cached FQDN goes through the re-tracking path, so reporting the rules of every
// matching selector as dirty there would re-realize them continuously and block the DNS responses
// on their realization.
func TestOnDNSResponseTrackedFQDNDoesNotDirtyRules(t *testing.T) {
	currentTime := time.Now()
	wildcardSelector := fqdnToSelectorItem("*.wildcard-stable.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}
	onDNSResponseFromPodForTest(f, "h0.wildcard-stable.example", currentTime)

	dirtyRules := recordDirtyRulesForTest(f)
	onDNSResponseFromPodForTest(f, "h0.wildcard-stable.example", currentTime)

	assert.Empty(t, *dirtyRules, "re-resolving a tracked FQDN with unchanged IPs must not report any dirty rule")
}

// TestOnDNSResponseEvictionKeepsFQDNSelectedByAnotherSelector verifies that a FQDN evicted from one
// fqdnSelectorItem stops being tracked only if no other fqdnSelectorItem selects it. If it were
// dropped unconditionally, rules using the other selectors would lose the IPs of a FQDN which they
// are still meant to match.
func TestOnDNSResponseEvictionKeepsFQDNSelectedByAnotherSelector(t *testing.T) {
	currentTime := time.Now()
	name := func(i int) string { return fmt.Sprintf("h%d.wildcard-shared.example", i) }
	wildcardSelector := fqdnToSelectorItem("*.wildcard-shared.example")
	// A selector matching a single name by definition never reaches maxFQDNsPerSelector.
	exactSelector := fqdnToSelectorItem(name(0))

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockWildcardRule"),
		exactSelector:    sets.New[string]("mockExactRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	// h0 is resolved first, hence it is the least-recently-used name for the wildcard selector,
	// and it is selected by both selectors.
	onDNSResponseFromPodForTest(f, name(0), currentTime)
	require.ElementsMatch(t, []fqdnSelectorItem{wildcardSelector, exactSelector}, f.fqdnCache.selectorsFor(name(0)))

	// Resolving maxFQDNsPerSelector more names evicts h0 from the wildcard selector.
	for i := 1; i <= expectedCap; i++ {
		onDNSResponseFromPodForTest(f, name(i), currentTime)
	}

	assert.False(t, f.fqdnCache.isSelectedBy(name(0), wildcardSelector), "the wildcard selector must drop the evicted name")
	assert.Len(t, f.fqdnCache.fqdnsFor(wildcardSelector), expectedCap, "FQDNs tracked for the wildcard selector must be capped")
	assert.True(t, f.fqdnCache.isSelectedBy(name(0), exactSelector), "the exact-name selector must still track the name")
	assert.ElementsMatch(t, []fqdnSelectorItem{exactSelector}, f.fqdnCache.selectorsFor(name(0)))
	assert.True(t, f.fqdnCache.isTracked(name(0)), "a FQDN selected by another selector must stay tracked")
	assert.Equal(t, expectedCap+1, f.fqdnCache.size())
}

// TestEvictionCancelsScheduledDNSQuery verifies that evicting a FQDN also cancels the DNS query
// scheduled for it. This is what bounds the schedule: were the query kept, making it would track the
// FQDN again (a selector still matches it), evicting another FQDN whose own scheduled query would
// track it back in turn, keeping every FQDN ever resolved in rotation forever. The schedule would
// then keep growing, and the Agent would keep re-querying all these names and rewriting the
// corresponding flows.
func TestEvictionCancelsScheduledDNSQuery(t *testing.T) {
	currentTime := time.Now()
	wildcardSelector := fqdnToSelectorItem("*.wildcard-requery.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	name := func(i int) string { return fmt.Sprintf("h%d.wildcard-requery.example", i) }

	for i := 0; i < expectedCap; i++ {
		onDNSResponseFromPodForTest(f, name(i), currentTime)
	}
	_, scheduled := requeryAtForTest(f, name(0))
	require.True(t, scheduled, "a DNS query must be scheduled for a tracked FQDN")

	// Resolving one more name than the cap allows evicts h0, the least-recently-used name.
	onDNSResponseFromPodForTest(f, name(expectedCap), currentTime)

	require.False(t, f.fqdnCache.isTracked(name(0)), "the least-recently-used name must be evicted")
	_, scheduled = requeryAtForTest(f, name(0))
	assert.False(t, scheduled, "the DNS query scheduled for an evicted FQDN must be cancelled")
	assert.Equal(t, expectedCap, scheduledCountForTest(f), "the schedule must never cover more FQDNs than the cache")

	// No worker may be handed the evicted FQDN: the only FQDNs which nextDue can return
	// are the ones still tracked.
	for _, fqdn := range scheduledFQDNsForTest(f) {
		assert.True(t, f.fqdnCache.isTracked(fqdn), "only tracked FQDNs may have a DNS query scheduled")
	}
}

// TestNextDueHandsOutDueFQDNOnce verifies that a FQDN whose records expired is handed to a worker,
// and to a single one: making the same DNS query from several workers at once would be wasteful, and
// their responses would race to update the same entry.
func TestNextDueHandsOutDueFQDNOnce(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)

	f.addFQDNSelector("mockRule", []string{"test.antrea.io"})

	entry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)
	assert.Equal(t, "test.antrea.io", entry.fqdn)
	// The FQDN is unscheduled while the query is in flight, so it is not handed out again.
	assert.Empty(t, scheduledFQDNsForTest(f), "a FQDN being queried must not be scheduled")

	// A successful query which resolved no address leaves the FQDN unscheduled, as it did
	// before the fqdnCache existed.
	f.fqdnCache.doneQuerying(entry, nil)
	assert.Empty(t, scheduledFQDNsForTest(f))
}

// TestDoneQueryingRetriesWithBackoff verifies that a failed DNS query is retried, with the same
// exponential backoff which the rate limiting workqueue used to provide.
func TestDoneQueryingRetriesWithBackoff(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.addFQDNSelector("mockRule", []string{"test.antrea.io"})
	entry := entryForTest(f, "test.antrea.io")

	for _, expectedBackoff := range []time.Duration{minRetryDelay, 2 * minRetryDelay, 4 * minRetryDelay} {
		f.fqdnCache.doneQuerying(entry, fmt.Errorf("DNS request failed"))
		requeryAt, scheduled := requeryAtForTest(f, "test.antrea.io")
		require.True(t, scheduled, "a failed DNS query must be retried")
		assert.Equal(t, currentTime.Add(expectedBackoff), requeryAt)
	}

	// A successful query resets the backoff.
	f.fqdnCache.doneQuerying(entry, nil)
	f.fqdnCache.doneQuerying(entry, fmt.Errorf("DNS request failed"))
	requeryAt, _ := requeryAtForTest(f, "test.antrea.io")
	assert.Equal(t, currentTime.Add(minRetryDelay), requeryAt)
}

// TestDoneQueryingKeepsRefreshScheduledByPartialResponse verifies that retrying a failed DNS query
// does not push back the refresh which the response of the same query already scheduled. A query
// can fail for one IP family after succeeding for the other, in which case the records it did
// resolve would be used in the datapath past their TTL for the whole retry backoff, which grows up
// to maxRetryDelay while the other family keeps failing.
func TestDoneQueryingKeepsRefreshScheduledByPartialResponse(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)

	f.addFQDNSelector("mockRule", []string{"test.antrea.io"})
	entry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)

	// The A query succeeded, and its records expire before the retry backoff elapses.
	const ttl = time.Second
	require.Less(t, ttl, minRetryDelay)
	f.onDNSResponse(entry.fqdn, map[string]ipWithExpiration{
		"192.1.1.1": {ip: net.ParseIP("192.1.1.1"), expirationTime: currentTime.Add(ttl)},
	}, nil)
	// The AAAA query failed, so makeDNSRequest reports the whole query as failed.
	f.fqdnCache.doneQuerying(entry, fmt.Errorf("DNS request failed for IPv6"))

	requeryAt, scheduled := requeryAtForTest(f, entry.fqdn)
	require.True(t, scheduled)
	assert.Equal(t, currentTime.Add(ttl), requeryAt,
		"the refresh scheduled for the records which were resolved must not be pushed back by the retry")
}

// TestNextDueSkipsFQDNBeingQueried verifies that a FQDN whose DNS query is in flight is not handed
// to a second worker, even if a DNS response schedules a query for it in the meantime. Querying the
// same name from two workers at once is wasteful, and their responses would race to update the same
// entry.
func TestNextDueSkipsFQDNBeingQueried(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)

	f.addFQDNSelector("mockRule", []string{"test.antrea.io"})
	entry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)

	// A DNS query is scheduled for the FQDN, as adding a selector which matches it by
	// exact name does, while the first query is still in flight.
	f.fqdnCache.scheduleNow(entry.fqdn)
	assert.Empty(t, dueFQDNsForTest(f), "a FQDN being queried must not be handed to another worker")

	// Once the query completes, the schedule requested meanwhile is applied.
	f.fqdnCache.doneQuerying(entry, nil)
	assert.Equal(t, []string{"test.antrea.io"}, dueFQDNsForTest(f),
		"the query scheduled while the FQDN was being queried must be made once the first one completed")
}

// TestDoneQueryingDropsUntrackedFQDN verifies that a FQDN which stopped being tracked while its DNS
// query was in flight is not scheduled again, not even to retry a failed query.
func TestDoneQueryingDropsUntrackedFQDN(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)

	f.addFQDNSelector("mockRule", []string{"test.antrea.io"})
	entry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)
	f.deleteFQDNSelector("mockRule", []string{"test.antrea.io"})

	f.fqdnCache.doneQuerying(entry, fmt.Errorf("DNS request failed"))
	assert.Empty(t, scheduledFQDNsForTest(f), "no DNS query must be scheduled for a FQDN which is no longer tracked")
	assert.Zero(t, f.fqdnCache.size())
}

// TestDoneQueryingDropsReplacedEntry verifies that the outcome of a DNS query is not applied to the
// FQDN it was made for if that FQDN was evicted and started being tracked again, by a new entry,
// while the query was in flight. The new entry has its own schedule, its own retry backoff, and
// possibly a worker of its own querying it: applying the outcome of the previous query to it would
// clear the flag which keeps a second worker from querying the same name at the same time, and a
// failure would pull its refresh forward to the retry backoff.
func TestDoneQueryingDropsReplacedEntry(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)
	// A single FQDN can be tracked, so that resolving another name evicts the first one.
	shrinkFQDNCacheForTest(f, 1, 1)

	wildcardSelector := fqdnToSelectorItem("*.wildcard-replaced.example")
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}
	onDNSResponseFromPodForTest(f, "h0.wildcard-replaced.example", currentTime)
	// The FQDN is due for a refresh and a worker starts querying it.
	fakeClock.Step(5 * time.Second)
	staleEntry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)
	require.Equal(t, "h0.wildcard-replaced.example", staleEntry.fqdn)

	// While that query is in flight, the FQDN is evicted, and then resolved again by a
	// Pod, which tracks it again as a brand new entry with a refresh of its own.
	onDNSResponseFromPodForTest(f, "h1.wildcard-replaced.example", currentTime)
	require.False(t, f.fqdnCache.isTracked("h0.wildcard-replaced.example"))
	onDNSResponseFromPodForTest(f, "h0.wildcard-replaced.example", currentTime)
	newEntry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)
	require.Equal(t, "h0.wildcard-replaced.example", newEntry.fqdn)
	require.NotSame(t, staleEntry, newEntry, "the FQDN must be tracked by a new entry")

	// The query which was in flight for the evicted entry now fails.
	f.fqdnCache.doneQuerying(staleEntry, fmt.Errorf("DNS request failed"))

	assert.Empty(t, scheduledFQDNsForTest(f),
		"the retry of a query made for an evicted entry must not schedule a query for the entry which replaced it")
	assert.True(t, isQueryingForTest(f, newEntry),
		"the entry which replaced the evicted one must stay marked as being queried by its own worker")
}

// TestOnDNSResponseDiscardsRequeryForEvictedFQDN verifies that the response to a DNS query which the
// fqdnController made itself is discarded when the FQDN was evicted while that query was in flight.
// Tracking the FQDN again would resurrect a name which no Pod resolved: the fqdnController would
// keep re-querying it, and it would displace a name which is actually in use, as tracking it
// refreshes its recency while the name it evicts keeps the recency it had.
func TestOnDNSResponseDiscardsRequeryForEvictedFQDN(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)
	// A single FQDN can be tracked, so that resolving another name evicts the first one.
	shrinkFQDNCacheForTest(f, 1, 1)

	inFlightFQDN, podFQDN := "h0.wildcard-inflight.example", "h1.wildcard-inflight.example"
	wildcardSelector := fqdnToSelectorItem("*.wildcard-inflight.example")
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		wildcardSelector: sets.New[string]("mockRule"),
	}
	onDNSResponseFromPodForTest(f, inFlightFQDN, currentTime)
	// The FQDN is due for a refresh and a worker starts querying it.
	fakeClock.Step(5 * time.Second)
	entry, ok := f.fqdnCache.nextDue(stopCh)
	require.True(t, ok)
	require.Equal(t, inFlightFQDN, entry.fqdn)

	// While that query is in flight, a Pod resolves another name, which evicts the FQDN.
	onDNSResponseFromPodForTest(f, podFQDN, currentTime)
	require.False(t, f.fqdnCache.isTracked(inFlightFQDN))

	dirtyRules := recordDirtyRulesForTest(f)
	// The query which the fqdnController had in flight for the evicted FQDN now completes.
	onDNSResponseFromRequeryForTest(f, inFlightFQDN, currentTime)

	assert.False(t, f.fqdnCache.isTracked(inFlightFQDN),
		"a FQDN evicted while the DNS query the fqdnController made for it was in flight must stay evicted")
	assert.True(t, f.fqdnCache.isTracked(podFQDN),
		"the FQDN which a Pod resolved must not be displaced by the response of an evicted FQDN")
	assert.Equal(t, []string{podFQDN}, scheduledFQDNsForTest(f),
		"no DNS query must be scheduled for a FQDN which is no longer tracked")
	assert.Empty(t, *dirtyRules, "discarding the response must not report any rule as dirty")
}

// gaugeValueForTest returns the current value of a gauge metric.
func gaugeValueForTest(t *testing.T, gauge *kmetrics.Gauge) float64 {
	value, err := testutil.GetGaugeMetricValue(gauge.GaugeMetric)
	require.NoError(t, err)
	return value
}

// evictionCountForTest returns the number of FQDNs which were evicted to honor the given limit
// since the Agent started, which is the value of the antrea_agent_fqdn_cache_eviction_count metric
// for that limit.
func evictionCountForTest(t *testing.T, reason string) int {
	value, err := testutil.GetCounterMetricValue(metrics.FQDNCacheEvictionCount.WithLabelValues(reason))
	require.NoError(t, err)
	return int(value)
}

// TestFQDNCacheMetrics verifies that the number of tracked FQDNs and the number of FQDNs evicted to
// honor each of the two limits are reported. Evicting a FQDN stops a rule from matching a name it
// selects until a selected Pod resolves it again, which is hard to attribute to the limits without
// these metrics, as nothing in the datapath records that a name was ever tracked.
func TestFQDNCacheMetrics(t *testing.T) {
	// A metric is only recorded once it has been registered.
	metrics.InitializeNetworkPolicyMetrics()

	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	// 3 selectors of 2 FQDNs each would need 6 entries, 2 more than the total limit.
	const maxEntries, maxPerSelector = 4, 2
	shrinkFQDNCacheForTest(f, maxEntries, maxPerSelector)

	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{}
	for _, domain := range []string{"a", "b", "c"} {
		f.selectorItemToRuleIDs[fqdnToSelectorItem("*."+domain+".example")] = sets.New[string]("mockRule-" + domain)
	}

	selectorEvictions := evictionCountForTest(t, metrics.LabelFQDNCacheSelectorLimit)
	totalEvictions := evictionCountForTest(t, metrics.LabelFQDNCacheTotalLimit)

	// Two names for each of the first two selectors fill both of them to the
	// per-selector limit, and the cache to the total limit.
	for _, domain := range []string{"a", "b"} {
		for i := 0; i < maxPerSelector; i++ {
			onDNSResponseFromPodForTest(f, fmt.Sprintf("h%d.%s.example", i, domain), currentTime)
		}
	}
	require.Equal(t, maxEntries, f.fqdnCache.size())
	assert.Equal(t, float64(maxEntries), gaugeValueForTest(t, metrics.FQDNCacheSize),
		"the number of tracked FQDNs must be reported")
	assert.Equal(t, selectorEvictions, evictionCountForTest(t, metrics.LabelFQDNCacheSelectorLimit),
		"no FQDN was evicted to honor the per-selector limit yet")
	assert.Equal(t, totalEvictions, evictionCountForTest(t, metrics.LabelFQDNCacheTotalLimit),
		"no FQDN was evicted to honor the total limit yet")

	// A name for the third selector must evict the globally least recently used one,
	// which belongs to a selector below its own limit.
	onDNSResponseFromPodForTest(f, "h0.c.example", currentTime)
	assert.Equal(t, totalEvictions+1, evictionCountForTest(t, metrics.LabelFQDNCacheTotalLimit),
		"the FQDN evicted to honor the total limit must be counted")
	assert.Equal(t, selectorEvictions, evictionCountForTest(t, metrics.LabelFQDNCacheSelectorLimit))

	// A second name for the third selector evicts one more name to honor the total
	// limit, and a third name evicts one to honor the per-selector limit instead, as
	// the third selector has reached it.
	onDNSResponseFromPodForTest(f, "h1.c.example", currentTime)
	onDNSResponseFromPodForTest(f, "h2.c.example", currentTime)
	assert.Equal(t, totalEvictions+2, evictionCountForTest(t, metrics.LabelFQDNCacheTotalLimit))
	assert.Equal(t, selectorEvictions+1, evictionCountForTest(t, metrics.LabelFQDNCacheSelectorLimit),
		"the FQDN evicted to honor the per-selector limit must be counted")
	require.Equal(t, maxEntries, f.fqdnCache.size())

	// Deleting the rules which use a selector stops the FQDNs it was the last selector
	// of from being tracked, which the reported number must follow.
	f.deleteFQDNSelector("mockRule-b", []string{"*.b.example"})
	require.Less(t, f.fqdnCache.size(), maxEntries)
	assert.Equal(t, float64(f.fqdnCache.size()), gaugeValueForTest(t, metrics.FQDNCacheSize),
		"the number of tracked FQDNs must be updated when a FQDN selector is deleted")
}

// TestFQDNCacheEvictionLogIsRateLimited verifies that the eviction of a FQDN is not logged every
// time one happens. Once the cache is at one of its limits, an eviction happens for every new
// domain name a Pod resolves, so logging each one would flood the log of the Agent.
func TestFQDNCacheEvictionLogIsRateLimited(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	cache := newFQDNCache(fakeClock, 1, 1)

	evictions, log := cache.recordEvictionLocked(&cache.totalLimitEvictions)
	assert.True(t, log, "the first eviction must be logged")
	assert.Equal(t, 1, evictions)

	fakeClock.Step(evictionLogInterval - time.Second)
	_, log = cache.recordEvictionLocked(&cache.totalLimitEvictions)
	assert.False(t, log, "an eviction must not be logged less than evictionLogInterval after the last one was")

	fakeClock.Step(time.Second)
	evictions, log = cache.recordEvictionLocked(&cache.totalLimitEvictions)
	require.True(t, log, "an eviction must be logged again once evictionLogInterval has elapsed")
	assert.Equal(t, 2, evictions, "the log must account for the evictions which were not logged")

	// The two limits are rate-limited independently, as reaching one says nothing
	// about the other.
	evictions, log = cache.recordEvictionLocked(&cache.selectorLimitEvictions)
	assert.True(t, log, "the first eviction made to honor the other limit must be logged")
	assert.Equal(t, 1, evictions)
}

// TestAddFQDNSelectorDoesNotRefreshRecency verifies that adding a wildcard selector does not make
// the FQDNs it matches the most recently used ones. Adding a policy is not a use of the names it
// selects, and treating it as one would let a new expression displace, from the global order, the
// names which the Pods are actually resolving.
func TestAddFQDNSelectorDoesNotRefreshRecency(t *testing.T) {
	currentTime := time.Now()
	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	// Only the global cap is exercised here, hence the per-selector one is left slack.
	const maxEntries, maxPerSelector = 4, 10
	shrinkFQDNCacheForTest(f, maxEntries, maxPerSelector)

	// This selector matches a superset of the names matched by the selector added below.
	initialSelector := fqdnToSelectorItem("*.example")
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		initialSelector: sets.New[string]("mockInitialRule"),
	}
	// The cache is filled to the global cap; h0.b is the least recently used name.
	for _, fqdn := range []string{"h0.b.example", "h1.b.example", "h0.a.example", "h1.a.example"} {
		onDNSResponseFromPodForTest(f, fqdn, currentTime)
	}
	require.Equal(t, maxEntries, f.fqdnCache.size())

	// The selector being added matches the two least recently used names.
	f.addFQDNSelector("mockAddedRule", []string{"*.b.example"})
	// Resolving one more name must evict a name for which the selector was added, and
	// not one which a Pod resolved more recently.
	onDNSResponseFromPodForTest(f, "h2.a.example", currentTime)

	assert.Equal(t, maxEntries, f.fqdnCache.size())
	assert.False(t, f.fqdnCache.isTracked("h0.b.example"),
		"the least recently used name must still be the one evicted after a selector matching it was added")
	assert.True(t, f.fqdnCache.isTracked("h0.a.example"),
		"a name which a Pod resolved more recently must not be displaced by a newly added selector")
}

// TestAddFQDNSelectorMatchingMoreFQDNsThanCap verifies that when a new wildcard selector is added
// and more existing FQDNs than the cap allows match it, the selector only starts tracking
// maxFQDNsPerSelector of them, and that none of these FQDNs stops being tracked, as they are all
// still selected by the selector they were originally resolved for.
func TestAddFQDNSelectorMatchingMoreFQDNsThanCap(t *testing.T) {
	currentTime := time.Now()
	name := func(i int) string { return fmt.Sprintf("h%d.wildcard-add.example", i) }
	// The FQDNs are first resolved for this selector, which matches a superset of the names matched
	// by the selector added afterwards.
	initialSelector := fqdnToSelectorItem("*.example")
	addedSelector := fqdnToSelectorItem("*.wildcard-add.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)
	f.selectorItemToRuleIDs = map[fqdnSelectorItem]sets.Set[string]{
		initialSelector: sets.New[string]("mockInitialRule"),
	}

	const expectedCap = expectedFQDNsPerSelectorCap
	for i := 0; i < expectedCap; i++ {
		onDNSResponseFromPodForTest(f, name(i), currentTime)
	}
	require.Equal(t, expectedCap, f.fqdnCache.size())

	f.addFQDNSelector("mockAddedRule", []string{"*.wildcard-add.example"})

	assert.Len(t, f.fqdnCache.fqdnsFor(addedSelector), expectedCap,
		"FQDNs tracked for the selector being added must be capped")
	assert.Equal(t, expectedCap, f.fqdnCache.size(),
		"no FQDN must stop being tracked, as they are all still selected by the initial selector")
	assert.Len(t, f.fqdnCache.fqdnsFor(initialSelector), expectedCap,
		"the initial selector must still track all the FQDNs")
}

// TestCleanupFQDNSelectorItemStopsTracking verifies that deleting a fqdnSelectorItem drops all the
// state kept for it: the FQDNs it was the last selector of stop being tracked, their scheduled DNS
// queries are cancelled, and its compiled regex is dropped, so that selectors coming and going do
// not leak.
func TestCleanupFQDNSelectorItemStopsTracking(t *testing.T) {
	currentTime := time.Now()
	wildcardSelector := fqdnToSelectorItem("*.wildcard-cleanup.example")

	fakeClock := newFakeClock(currentTime)
	controller := gomock.NewController(t)
	f, _ := newMockFQDNController(t, controller, nil, fakeClock, 0)

	f.addFQDNSelector("mockRule", []string{"*.wildcard-cleanup.example"})
	onDNSResponseFromPodForTest(f, "h0.wildcard-cleanup.example", currentTime)
	require.Contains(t, f.selectorItemToRegex, wildcardSelector)
	require.Equal(t, 1, scheduledCountForTest(f))

	f.deleteFQDNSelector("mockRule", []string{"*.wildcard-cleanup.example"})

	assert.NotContains(t, f.selectorItemToRegex, wildcardSelector, "the compiled regex of the selector must be deleted")
	assert.Empty(t, f.fqdnCache.fqdnsFor(wildcardSelector))
	assert.Zero(t, f.fqdnCache.size())
	assert.Zero(t, scheduledCountForTest(f), "the DNS queries scheduled for the FQDNs must be cancelled")
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
