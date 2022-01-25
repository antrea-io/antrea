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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
)

func newMockFQDNController(t *testing.T, controller *gomock.Controller, dnsServer *string) (*fqdnController, *openflowtest.MockClient) {
	mockOFClient := openflowtest.NewMockClient(controller)
	mockOFClient.EXPECT().NewDNSpacketInConjunction(gomock.Any()).Return(nil).AnyTimes()
	dirtyRuleHandler := func(rule string) {}
	dnsServerAddr := "8.8.8.8:53" // dummy DNS server, will not be used since we don't send any request in these tests
	if dnsServer != nil {
		dnsServerAddr = *dnsServer
	}
	f, err := newFQDNController(
		mockOFClient,
		newIDAllocator(testAsyncDeleteInterval),
		dnsServerAddr,
		dirtyRuleHandler,
		true,
		false,
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
		existingSelectorToRuleIDs  map[fqdnSelectorItem]sets.String
		existingDNSCache           map[string]dnsMeta
		existingFQDNToSelectorItem map[string]map[fqdnSelectorItem]struct{}
		ruleID                     string
		fqdns                      []string
		podAddrs                   sets.Int32
		finalSelectorToRuleIDs     map[fqdnSelectorItem]sets.String
		finalFQDNToSelectorItem    map[string]map[fqdnSelectorItem]struct{}
		addressAdded               bool
		addressRemoved             bool
	}{
		{
			"addNewFQDNSelector",
			nil,
			nil,
			nil,
			"mockRule1",
			[]string{"test.antrea.io"},
			sets.NewInt32(1),
			map[fqdnSelectorItem]sets.String{
				selectorItem1: sets.NewString("mockRule1"),
			},
			map[string]map[fqdnSelectorItem]struct{}{
				"test.antrea.io": {selectorItem1: struct{}{}},
			},
			true,
			false,
		},
		{
			"addNewFQDNSelectorMatchExisting",
			map[fqdnSelectorItem]sets.String{
				selectorItem1: sets.NewString("mockRule1"),
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			map[string]map[fqdnSelectorItem]struct{}{
				"test.antrea.io": {
					selectorItem1: struct{}{},
				},
			},
			"mockRule2",
			[]string{"*antrea.io"},
			sets.NewInt32(2),
			map[fqdnSelectorItem]sets.String{
				selectorItem1: sets.NewString("mockRule1"),
				selectorItem2: sets.NewString("mockRule2")},
			map[string]map[fqdnSelectorItem]struct{}{
				"test.antrea.io": {
					selectorItem1: struct{}{},
					selectorItem2: struct{}{},
				},
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			f, c := newMockFQDNController(t, controller, nil)
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
			if tt.existingDNSCache != nil {
				f.dnsEntryCache = tt.existingDNSCache
			}
			require.NoError(t, f.addFQDNRule(tt.ruleID, tt.fqdns, tt.podAddrs), "Error when adding FQDN rule")
			assert.Equal(t, tt.finalSelectorToRuleIDs, f.selectorItemToRuleIDs)
			assert.Equal(t, tt.finalFQDNToSelectorItem, f.fqdnToSelectorItem)
		})
	}
}

type fqdnRuleAddArgs struct {
	ruleID         string
	fqdns          []string
	podOFAddresses sets.Int32
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
		finalSelectorToRuleIDs  map[fqdnSelectorItem]sets.String
		finalFQDNToSelectorItem map[string]map[fqdnSelectorItem]struct{}
		addressRemoved          bool
	}{
		{
			"test-1",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"test.antrea.io"},
					sets.NewInt32(1),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			"mockRule1",
			[]string{"test.antrea.io"},
			map[fqdnSelectorItem]sets.String{},
			map[string]map[fqdnSelectorItem]struct{}{},
			true,
		},
		{
			"test-2",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"test.antrea.io"},
					sets.NewInt32(1),
				},
				{
					"mockRule2",
					[]string{"test.antrea.io"},
					sets.NewInt32(2),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			"mockRule1",
			[]string{"test.antrea.io"},
			map[fqdnSelectorItem]sets.String{
				selectorItem1: sets.NewString("mockRule2"),
			},
			map[string]map[fqdnSelectorItem]struct{}{
				"test.antrea.io": {
					selectorItem1: struct{}{},
				},
			},
			true,
		},
		{
			"test-3",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"test.antrea.io"},
					sets.NewInt32(1),
				},
				{
					"mockRule2",
					[]string{"*antrea.io"},
					sets.NewInt32(2),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io": {},
			},
			"mockRule1",
			[]string{"test.antrea.io"},
			map[fqdnSelectorItem]sets.String{
				selectorItem2: sets.NewString("mockRule2"),
			},
			map[string]map[fqdnSelectorItem]struct{}{
				"test.antrea.io": {
					selectorItem2: struct{}{},
				},
			},
			true,
		},
		{
			"test-4",
			[]fqdnRuleAddArgs{
				{
					"mockRule1",
					[]string{"maps.google.com"},
					sets.NewInt32(1),
				},
				{
					"mockRule2",
					[]string{"*antrea.io"},
					sets.NewInt32(2),
				},
			},
			map[string]dnsMeta{
				"test.antrea.io":  {},
				"maps.google.com": {},
			},
			"mockRule2",
			[]string{"*antrea.io"},
			map[fqdnSelectorItem]sets.String{
				selectorItem3: sets.NewString("mockRule1"),
			},
			map[string]map[fqdnSelectorItem]struct{}{
				"maps.google.com": {
					selectorItem3: struct{}{},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			f, c := newMockFQDNController(t, controller, nil)
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
	defer controller.Finish()
	dnsServer := "" // force a fallback to local resolver
	f, _ := newMockFQDNController(t, controller, &dnsServer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// not ideal as a unit test because it requires the ability to resolve
	// DNS names, but we don't expect this to be an actual problem.
	err := f.lookupIP(ctx, "www.google.com")
	require.NoError(t, err, "Error when resolving name")
}
