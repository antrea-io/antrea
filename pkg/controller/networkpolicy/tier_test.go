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

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

func TestAddTier(t *testing.T) {
	tests := []struct {
		name                   string
		inputTiers             []*secv1alpha1.Tier
		expectedPrioritySetLen int
	}{
		{
			name: "empty-set",
			inputTiers: []*secv1alpha1.Tier{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
					Spec: secv1alpha1.TierSpec{
						Priority:    1,
						Description: "tier-A",
					},
				},
			},
			expectedPrioritySetLen: 1,
		},
		{
			name: "multiple-tiers",
			inputTiers: []*secv1alpha1.Tier{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
					Spec: secv1alpha1.TierSpec{
						Priority:    1,
						Description: "tier-A",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tB", UID: "uidB"},
					Spec: secv1alpha1.TierSpec{
						Priority:    2,
						Description: "tier-B",
					},
				},
			},
			expectedPrioritySetLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			for _, tier := range tt.inputTiers {
				npc.addTier(tier)
				assert.True(t, npc.tierPrioritySet.Has(tier.Spec.Priority), "tier priority missing from set")
			}
			assert.Equal(t, tt.expectedPrioritySetLen, len(npc.tierPrioritySet), "number of tier priorities in set do not match")
		})
	}
}

func TestUpdateTier(t *testing.T) {
	tests := []struct {
		name                   string
		inputTier              *secv1alpha1.Tier
		inputUpdateTier        *secv1alpha1.Tier
		expectedPrioritySetLen int
	}{
		{
			name: "new-desc",
			inputTier: &secv1alpha1.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
				Spec: secv1alpha1.TierSpec{
					Priority:    1,
					Description: "tier-A",
				},
			},
			inputUpdateTier: &secv1alpha1.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
				Spec: secv1alpha1.TierSpec{
					Priority:    1,
					Description: "newTier-A",
				},
			},
			expectedPrioritySetLen: 1,
		},
		{
			name: "empty-desc",
			inputTier: &secv1alpha1.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
				Spec: secv1alpha1.TierSpec{
					Priority:    1,
					Description: "tier-A",
				},
			},
			inputUpdateTier: &secv1alpha1.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
				Spec: secv1alpha1.TierSpec{
					Priority:    1,
					Description: "",
				},
			},
			expectedPrioritySetLen: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addTier(tt.inputTier)
			npc.updateTier(tt.inputTier, tt.inputUpdateTier)
			assert.True(t, npc.tierPrioritySet.Has(tt.inputTier.Spec.Priority), "tier priority missing from set")
			assert.Equal(t, tt.expectedPrioritySetLen, len(npc.tierPrioritySet), "number of tier priorities in set do not match")
		})
	}
}

func TestDeleteTier(t *testing.T) {
	tests := []struct {
		name                   string
		inputAddTiers          []*secv1alpha1.Tier
		inputDelTiers          []*secv1alpha1.Tier
		expectedPrioritySetLen int
	}{
		{
			name: "empty-set",
			inputAddTiers: []*secv1alpha1.Tier{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
					Spec: secv1alpha1.TierSpec{
						Priority:    1,
						Description: "tier-A",
					},
				},
			},
			inputDelTiers: []*secv1alpha1.Tier{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
					Spec: secv1alpha1.TierSpec{
						Priority:    1,
						Description: "tier-A",
					},
				},
			},
			expectedPrioritySetLen: 0,
		},
		{
			name: "delete-A",
			inputAddTiers: []*secv1alpha1.Tier{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
					Spec: secv1alpha1.TierSpec{
						Priority:    1,
						Description: "tier-A",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tB", UID: "uidB"},
					Spec: secv1alpha1.TierSpec{
						Priority:    2,
						Description: "tier-B",
					},
				},
			},
			inputDelTiers: []*secv1alpha1.Tier{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "tA", UID: "uidA"},
					Spec: secv1alpha1.TierSpec{
						Priority:    1,
						Description: "tier-A",
					},
				},
			},
			expectedPrioritySetLen: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			for _, tier := range tt.inputAddTiers {
				npc.addTier(tier)
			}
			for _, tier := range tt.inputDelTiers {
				npc.deleteTier(tier)
				assert.False(t, npc.tierPrioritySet.Has(tier.Spec.Priority), "tier priority still present in set")
			}
			assert.Equal(t, tt.expectedPrioritySetLen, len(npc.tierPrioritySet), "number of tier priorities in set do not match")
		})
	}
}
