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

package labelidentity

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/controller/types"
)

var (
	pSelWeb = &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "web"},
	}
	pSelDB = &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "db"},
	}
	nsSelTest = &metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test"},
	}
	selectorA     = types.NewGroupSelector("", pSelWeb, nil, nil, nil)
	selectorB     = types.NewGroupSelector("", pSelWeb, nsSelTest, nil, nil)
	selectorC     = types.NewGroupSelector("", pSelDB, nil, nil, nil)
	selectorD     = types.NewGroupSelector("testing", pSelDB, nil, nil, nil)
	selectorE     = types.NewGroupSelector("random", pSelDB, nil, nil, nil)
	selectorF     = types.NewGroupSelector("", nil, nsSelTest, nil, nil)
	selectorG     = types.NewGroupSelector("testing", nil, nil, nil, nil)
	selectorItemA = &selectorItem{
		selector: selectorA,
	}
	selectorItemB = &selectorItem{
		selector: selectorB,
	}
	selectorItemC = &selectorItem{
		selector: selectorC,
	}
	selectorItemD = &selectorItem{
		selector: selectorD,
	}
	selectorItemE = &selectorItem{
		selector: selectorE,
	}
	selectorItemF = &selectorItem{
		selector: selectorF,
	}
	selectorItemG = &selectorItem{
		selector: selectorG,
	}
	labelA     = "ns:kubernetes.io/metadata.name=testing,purpose=test&pod:app=web"
	labelB     = "ns:kubernetes.io/metadata.name=testing,purpose=test&pod:app=db"
	labelC     = "ns:kubernetes.io/metadata.name=nomatch,purpose=nomatch&pod:app=db"
	labelD     = "ns:kubernetes.io/metadata.name=testing,purpose=test&pod:"
	labelStale = "ns:kubernetes.io/metadata.name=testing,purpose=test&pod:<none>"
)

func TestLabelIdentityMatch(t *testing.T) {
	tests := []struct {
		label       string
		selector    *selectorItem
		expectMatch bool
	}{
		{
			label:       labelA,
			selector:    selectorItemA,
			expectMatch: true,
		},
		{
			label:       labelA,
			selector:    selectorItemB,
			expectMatch: true,
		},
		{
			label:       labelA,
			selector:    selectorItemC,
			expectMatch: false,
		},
		{
			label:       labelA,
			selector:    selectorItemD,
			expectMatch: false,
		},
		{
			label:       labelB,
			selector:    selectorItemB,
			expectMatch: false,
		},
		{
			label:       labelB,
			selector:    selectorItemC,
			expectMatch: true,
		},
		{
			label:       labelB,
			selector:    selectorItemD,
			expectMatch: true,
		},
		{
			label:       labelB,
			selector:    selectorItemE,
			expectMatch: false,
		},
		{
			label:       labelC,
			selector:    selectorItemB,
			expectMatch: false,
		},
		{
			label:       labelC,
			selector:    selectorItemC,
			expectMatch: true,
		},
		{
			label:       labelC,
			selector:    selectorItemD,
			expectMatch: false,
		},
		{
			label:       labelC,
			selector:    selectorItemE,
			expectMatch: false,
		},
		{
			label:       labelD,
			selector:    selectorItemA,
			expectMatch: false,
		},
		{
			label:       labelD,
			selector:    selectorItemB,
			expectMatch: false,
		},
		{
			label:       labelD,
			selector:    selectorItemD,
			expectMatch: false,
		},
		{
			label:       labelD,
			selector:    selectorItemF,
			expectMatch: true,
		},
		{
			label:       labelA,
			selector:    selectorItemG,
			expectMatch: true,
		},
		{
			label:       labelC,
			selector:    selectorItemG,
			expectMatch: false,
		},
		{
			label:       labelD,
			selector:    selectorItemG,
			expectMatch: true,
		},
		{
			label:       labelStale,
			selector:    selectorItemA,
			expectMatch: false,
		},
	}
	for _, tt := range tests {
		labelMatch := newLabelIdentityMatch(tt.label, 1)
		matched := labelMatch.matches(tt.selector)
		assert.Equalf(t, tt.expectMatch, matched, "Unexpected matching status for %s and %s.", tt.label, tt.selector.getKey())
	}
}

func TestAddSelector(t *testing.T) {
	tests := []struct {
		name                 string
		selectorToAdd        *types.GroupSelector
		existingPolicyKey    string
		policyKey            string
		expMatchedIDs        []uint32
		expLabelIdentityKeys sets.Set[string]
		expPolicyKeys        sets.Set[string]
	}{
		{
			name:                 "cluster-wide app=web",
			selectorToAdd:        types.NewGroupSelector("", pSelWeb, nil, nil, nil),
			policyKey:            "policyA",
			expMatchedIDs:        []uint32{1},
			expLabelIdentityKeys: sets.New[string](labelA),
			expPolicyKeys:        sets.New[string]("policyA"),
		},
		{
			name:                 "cluster-wide app=web another policy",
			selectorToAdd:        types.NewGroupSelector("", pSelWeb, nil, nil, nil),
			existingPolicyKey:    "policyA",
			policyKey:            "policyB",
			expMatchedIDs:        []uint32{1},
			expLabelIdentityKeys: sets.New[string](labelA),
			expPolicyKeys:        sets.New[string]("policyA", "policyB"),
		},
		{
			name:                 "pod app=web and ns purpose=test",
			selectorToAdd:        types.NewGroupSelector("", pSelWeb, nsSelTest, nil, nil),
			policyKey:            "policyB",
			expMatchedIDs:        []uint32{1},
			expLabelIdentityKeys: sets.New[string](labelA),
			expPolicyKeys:        sets.New[string]("policyB"),
		},
		{
			name:                 "cluster-wide app=db",
			selectorToAdd:        types.NewGroupSelector("", pSelDB, nil, nil, nil),
			policyKey:            "policyC",
			expMatchedIDs:        []uint32{2, 3},
			expLabelIdentityKeys: sets.New[string](labelB, labelC),
			expPolicyKeys:        sets.New[string]("policyC"),
		},
		{
			name:                 "app=db in ns testing",
			selectorToAdd:        types.NewGroupSelector("testing", pSelDB, nil, nil, nil),
			policyKey:            "policyD",
			expMatchedIDs:        []uint32{2},
			expLabelIdentityKeys: sets.New[string](labelB),
			expPolicyKeys:        sets.New[string]("policyD"),
		},
		{
			name:                 "app=db in ns random",
			selectorToAdd:        types.NewGroupSelector("random", pSelDB, nil, nil, nil),
			policyKey:            "policyE",
			expMatchedIDs:        []uint32{},
			expLabelIdentityKeys: sets.New[string](),
			expPolicyKeys:        sets.New[string]("policyE"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := NewLabelIdentityIndex()
			i.AddLabelIdentity(labelA, 1)
			i.AddLabelIdentity(labelB, 2)
			i.AddLabelIdentity(labelC, 3)
			if tt.existingPolicyKey != "" {
				i.AddSelector(tt.selectorToAdd, tt.existingPolicyKey)
			}
			idsMatched := i.AddSelector(tt.selectorToAdd, tt.policyKey)
			assert.ElementsMatch(t, tt.expMatchedIDs, idsMatched)
			s, exists, _ := i.selectorItems.GetByKey(tt.selectorToAdd.NormalizedName)
			require.True(t, exists, "Failed to add selector %s to the LabelIdentityIndex", tt.name)
			sItem := s.(*selectorItem)
			assert.Equalf(t, tt.expLabelIdentityKeys, sItem.labelIdentityKeys, "Unexpected label identity keys for selectorItem")
			assert.Equalf(t, tt.expPolicyKeys, sItem.policyKeys, "Unexpected policy keys for selectorItem")
		})
	}
}

func TestDeletePolicySelectors(t *testing.T) {
	tests := []struct {
		policyKey     string
		staleSelector string
	}{
		{
			policyKey:     "policyA",
			staleSelector: selectorItemD.getKey(),
		},
		{
			policyKey:     "policyB",
			staleSelector: selectorItemC.getKey(),
		},
	}
	i := NewLabelIdentityIndex()
	i.AddLabelIdentity(labelB, 2)
	i.AddLabelIdentity(labelC, 3)
	i.AddSelector(selectorItemD.selector, "policyA")
	i.AddSelector(selectorItemC.selector, "policyB")
	for _, tt := range tests {
		i.DeletePolicySelectors(tt.policyKey)
		for k, l := range i.labelIdentities {
			if l.selectorItemKeys.Has(tt.staleSelector) {
				t.Errorf("Stale selector %s is not deleted from labelMatch %s", tt.staleSelector, k)
			}
		}
		if _, exists, _ := i.selectorItems.GetByKey(tt.staleSelector); exists {
			t.Errorf("Stale selector %s is not deleted from selectorItem cache", tt.staleSelector)
		}
	}
}

func TestSetPolicySelectors(t *testing.T) {
	tests := []struct {
		name             string
		selectors        []*types.GroupSelector
		policyKey        string
		prevSelAdded     []*types.GroupSelector
		prevPolicyAdded  string
		expIDs           []uint32
		expSelectorItems map[string]selectorItem
	}{
		{
			name: "new selector for policyA",
			selectors: []*types.GroupSelector{
				types.NewGroupSelector("", pSelWeb, nil, nil, nil),
			},
			policyKey: "policyA",
			expIDs:    []uint32{1},
			expSelectorItems: map[string]selectorItem{
				selectorItemA.selector.NormalizedName: {
					labelIdentityKeys: sets.New[string](labelA),
					policyKeys:        sets.New[string]("policyA"),
				},
			},
		},
		{
			name: "updated selectors for policyA",
			selectors: []*types.GroupSelector{
				types.NewGroupSelector("", pSelWeb, nsSelTest, nil, nil),
				types.NewGroupSelector("", pSelDB, nil, nil, nil),
			},
			policyKey:       "policyA",
			prevPolicyAdded: "policyA",
			prevSelAdded: []*types.GroupSelector{
				types.NewGroupSelector("", pSelWeb, nil, nil, nil),
			},
			expIDs: []uint32{1, 2, 3},
			expSelectorItems: map[string]selectorItem{
				selectorItemB.selector.NormalizedName: {
					labelIdentityKeys: sets.New[string](labelA),
					policyKeys:        sets.New[string]("policyA"),
				},
				selectorItemC.selector.NormalizedName: {
					labelIdentityKeys: sets.New[string](labelB, labelC),
					policyKeys:        sets.New[string]("policyA"),
				},
			},
		},
		{
			name: "existing selector and new selector for policyB",
			selectors: []*types.GroupSelector{
				types.NewGroupSelector("", pSelWeb, nil, nil, nil),
				types.NewGroupSelector("", pSelWeb, nsSelTest, nil, nil),
			},
			policyKey:       "policyB",
			prevPolicyAdded: "policyA",
			prevSelAdded: []*types.GroupSelector{
				types.NewGroupSelector("", pSelWeb, nsSelTest, nil, nil),
				types.NewGroupSelector("", pSelDB, nil, nil, nil),
			},
			expIDs: []uint32{1},
			expSelectorItems: map[string]selectorItem{
				selectorItemA.selector.NormalizedName: {
					labelIdentityKeys: sets.New[string](labelA),
					policyKeys:        sets.New[string]("policyB"),
				},
				selectorItemB.selector.NormalizedName: {
					labelIdentityKeys: sets.New[string](labelA),
					policyKeys:        sets.New[string]("policyA", "policyB"),
				},
				selectorItemC.selector.NormalizedName: {
					labelIdentityKeys: sets.New[string](labelB, labelC),
					policyKeys:        sets.New[string]("policyA"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := NewLabelIdentityIndex()
			i.AddLabelIdentity(labelA, 1)
			i.AddLabelIdentity(labelB, 2)
			i.AddLabelIdentity(labelC, 3)
			if tt.prevPolicyAdded != "" {
				for _, sel := range tt.prevSelAdded {
					i.AddSelector(sel, tt.prevPolicyAdded)
				}
			}
			var labelIDs []uint32
			selectorKeys := sets.New[string]()
			for _, sel := range tt.selectors {
				labelIDs = append(labelIDs, i.AddSelector(sel, tt.policyKey)...)
				selectorKeys.Insert(sel.NormalizedName)
			}
			i.RemoveStalePolicySelectors(selectorKeys, tt.policyKey)
			assert.ElementsMatch(t, tt.expIDs, dedupLabelIdentites(labelIDs))
			assert.Equalf(t, len(tt.expSelectorItems), len(i.selectorItems.List()), "Unexpected number of cached selectorItems")
			for selKey, expSelItem := range tt.expSelectorItems {
				s, exists, _ := i.selectorItems.GetByKey(selKey)
				if !exists {
					t.Errorf("Selector %s is not added", selKey)
				}
				sItem := s.(*selectorItem)
				assert.Truef(t, sItem.policyKeys.Equal(expSelItem.policyKeys), "Unexpected policy keys for selectorItem %s", selKey)
				assert.Truef(t, sItem.labelIdentityKeys.Equal(expSelItem.labelIdentityKeys), "Unexpected labelIdentity keys for selectorItem %s", selKey)
			}
		})
	}
}

// Dedup LabelIdentity IDs in-place.
func dedupLabelIdentites(labelIdentityIDs []uint32) []uint32 {
	seen := map[uint32]struct{}{}
	idx := 0
	for _, id := range labelIdentityIDs {
		if _, exists := seen[id]; !exists {
			seen[id] = struct{}{}
			labelIdentityIDs[idx] = id
			idx++
		}
	}
	return labelIdentityIDs[:idx]
}

func TestAddLabelIdentity(t *testing.T) {
	labelIdentityAOriginalID := uint32(1)
	tests := []struct {
		name              string
		normalizedLabel   string
		id                uint32
		originalID        *uint32
		expPolicyCalled   []string
		expLabelIdenities map[string]*labelIdentityMatch
	}{
		{
			name:            "Add label identity A",
			normalizedLabel: labelA,
			id:              1,
			expPolicyCalled: []string{"policyA", "policyB"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelA: {
					id:               1,
					selectorItemKeys: sets.New[string](selectorItemA.getKey(), selectorItemB.getKey()),
				},
			},
		},
		{
			name:            "Update label identity A",
			normalizedLabel: labelA,
			id:              4,
			originalID:      &labelIdentityAOriginalID,
			expPolicyCalled: []string{"policyA", "policyB", "policyA", "policyB"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelA: {
					id:               4,
					selectorItemKeys: sets.New[string](selectorItemA.getKey(), selectorItemB.getKey()),
				},
			},
		},
		{
			name:            "Add label identity B",
			normalizedLabel: labelB,
			id:              2,
			expPolicyCalled: []string{"policyA", "policyB", "policyD"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelB: {
					id:               2,
					selectorItemKeys: sets.New[string](selectorItemC.getKey(), selectorItemD.getKey()),
				},
			},
		},
		{
			name:            "Add label identity C",
			normalizedLabel: labelC,
			id:              3,
			expPolicyCalled: []string{"policyA", "policyB"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelC: {
					id:               3,
					selectorItemKeys: sets.New[string](selectorItemC.getKey()),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := NewLabelIdentityIndex()
			i.AddSelector(selectorA, "policyA")
			i.AddSelector(selectorC, "policyA")
			i.AddSelector(selectorB, "policyB")
			i.AddSelector(selectorC, "policyB")
			i.AddSelector(selectorD, "policyD")
			i.AddSelector(selectorE, "policyE")
			stopCh := make(chan struct{})
			defer close(stopCh)

			go i.Run(stopCh)
			var lock sync.Mutex
			var actualPoliciesCalled []string
			i.AddEventHandler(func(policyKey string) {
				lock.Lock()
				defer lock.Unlock()
				actualPoliciesCalled = append(actualPoliciesCalled, policyKey)
			})

			if tt.originalID != nil {
				i.AddLabelIdentity(tt.normalizedLabel, *tt.originalID)
			}
			i.AddLabelIdentity(tt.normalizedLabel, tt.id)
			// Wait for event handler to handle label add event
			time.Sleep(10 * time.Millisecond)
			lock.Lock()
			defer lock.Unlock()
			assert.ElementsMatchf(t, actualPoliciesCalled, tt.expPolicyCalled, "Unexpected policy sync calls")
			for key, l := range tt.expLabelIdenities {
				actLabelMatch := i.labelIdentities[key]
				assert.Equalf(t, actLabelMatch.id, l.id, "Unexpected id cached for label")
				if !actLabelMatch.selectorItemKeys.Equal(l.selectorItemKeys) {
					t.Errorf("Unexpected matched selectorItems for label %s in step %s", tt.normalizedLabel, tt.name)
				}
			}
		})
	}
}

func TestDeleteLabelIdentity(t *testing.T) {
	tests := []struct {
		name              string
		labelToDelete     string
		expPolicyCalled   []string
		expLabelIdenities map[string]*labelIdentityMatch
	}{
		{
			name:            "Delete label identity A",
			labelToDelete:   labelA,
			expPolicyCalled: []string{"policyA", "policyB"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelB: {
					id:               2,
					selectorItemKeys: sets.New[string](selectorItemC.getKey(), selectorItemD.getKey()),
				},
				labelC: {
					id:               3,
					selectorItemKeys: sets.New[string](selectorItemC.getKey()),
				},
			},
		},
		{
			name:            "Delete label identity B",
			labelToDelete:   labelB,
			expPolicyCalled: []string{"policyA", "policyB", "policyD"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelA: {
					id:               1,
					selectorItemKeys: sets.New[string](selectorItemA.getKey(), selectorItemB.getKey()),
				},
				labelC: {
					id:               3,
					selectorItemKeys: sets.New[string](selectorItemC.getKey()),
				},
			},
		},
		{
			name:            "Delete label identity C",
			labelToDelete:   labelC,
			expPolicyCalled: []string{"policyA", "policyB"},
			expLabelIdenities: map[string]*labelIdentityMatch{
				labelA: {
					id:               1,
					selectorItemKeys: sets.New[string](selectorItemA.getKey(), selectorItemB.getKey()),
				},
				labelB: {
					id:               2,
					selectorItemKeys: sets.New[string](selectorItemC.getKey(), selectorItemD.getKey()),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := NewLabelIdentityIndex()
			i.AddSelector(selectorA, "policyA")
			i.AddSelector(selectorC, "policyA")
			i.AddSelector(selectorB, "policyB")
			i.AddSelector(selectorC, "policyB")
			i.AddSelector(selectorD, "policyD")
			i.AddSelector(selectorE, "policyE")
			stopCh := make(chan struct{})
			defer close(stopCh)

			go i.Run(stopCh)
			var lock sync.Mutex
			var actualPoliciesCalled []string
			i.AddEventHandler(func(policyKey string) {
				lock.Lock()
				defer lock.Unlock()
				actualPoliciesCalled = append(actualPoliciesCalled, policyKey)
			})
			// Preload the index with label identities to be deleted
			i.AddLabelIdentity(labelA, 1)
			i.AddLabelIdentity(labelB, 2)
			i.AddLabelIdentity(labelC, 3)
			// Reset the actualPoliciesCalled slice. Otherwise, the list will be filled with extra items
			// in the channel from preloading label identities.
			time.Sleep(10 * time.Millisecond)
			lock.Lock()
			actualPoliciesCalled = []string{}
			lock.Unlock()

			i.DeleteLabelIdentity(tt.labelToDelete)
			time.Sleep(10 * time.Millisecond)
			lock.Lock()
			defer lock.Unlock()
			assert.ElementsMatchf(t, actualPoliciesCalled, tt.expPolicyCalled, "Unexpected policy sync calls")
			for key, l := range tt.expLabelIdenities {
				actLabelMatch := i.labelIdentities[key]
				assert.Equalf(t, actLabelMatch.id, l.id, "Unexpected id cached for label")
				if !actLabelMatch.selectorItemKeys.Equal(l.selectorItemKeys) {
					t.Errorf("Unexpected matched selectorItems for label %s in step %s", tt.labelToDelete, tt.name)
				}
			}
		})
	}
}
