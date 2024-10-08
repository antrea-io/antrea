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

package networkpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

func TestInitializeTier(t *testing.T) {
	makeTestTier := func(priority int32) *secv1beta1.Tier {
		return &secv1beta1.Tier{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: secv1beta1.TierSpec{
				Priority: priority,
			},
		}
	}
	testTier := makeTestTier(10)

	tests := []struct {
		name                string
		createReactor       k8stesting.ReactionFunc
		updateReactor       k8stesting.ReactionFunc
		existingTier        *secv1beta1.Tier
		createExpectedCalls int
		updateExpectedCalls int
	}{
		{
			name:                "create successful",
			createExpectedCalls: 1,
		},
		{
			name: "create error",
			createReactor: func() k8stesting.ReactionFunc {
				curFailureCount := 0
				return func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					if curFailureCount < 1 {
						curFailureCount += 1
						return true, nil, errors.NewServiceUnavailable("unknown reason")
					}
					return false, nil, nil
				}
			}(),
			createExpectedCalls: 2,
		},
		{
			name:                "update successful",
			existingTier:        makeTestTier(5),
			updateExpectedCalls: 1,
		},
		{
			name: "update error",
			updateReactor: func() k8stesting.ReactionFunc {
				curFailureCount := 0
				return func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					if curFailureCount < 1 {
						curFailureCount += 1
						return true, nil, errors.NewServiceUnavailable("unknown reason")
					}
					return false, nil, nil
				}
			}(),
			existingTier:        makeTestTier(5),
			updateExpectedCalls: 2,
		},
		{
			name:         "no change needed",
			existingTier: makeTestTier(10),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			crdObjects := []runtime.Object{}
			if tc.existingTier != nil {
				crdObjects = append(crdObjects, tc.existingTier)
			}
			_, c := newController(nil, crdObjects)
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)

			if tc.createReactor != nil {
				c.crdClient.(*fake.Clientset).PrependReactor("create", "tiers", tc.createReactor)
			}
			if tc.updateReactor != nil {
				c.crdClient.(*fake.Clientset).PrependReactor("update", "tiers", tc.updateReactor)
			}
			createCalls := 0
			c.crdClient.(*fake.Clientset).PrependReactor("create", "tiers", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createCalls += 1
				return false, nil, nil
			})
			updateCalls := 0
			c.crdClient.(*fake.Clientset).PrependReactor("update", "tiers", func(action k8stesting.Action) (bool, runtime.Object, error) {
				updateCalls += 1
				return false, nil, nil
			})
			// Prevent test from hanging in case of issue.
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			require.NoError(t, c.initializeTier(ctx, testTier))
			assert.Equal(t, tc.createExpectedCalls, createCalls)
			assert.Equal(t, tc.updateExpectedCalls, updateCalls)
		})
	}

}

func TestInitializeTiers(t *testing.T) {
	ctx := context.Background()

	_, c := newController(nil, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)

	// All system Tiers should be created on the first try, so we can use a small timeout.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	require.NoError(t, c.InitializeTiers(ctx))
	tiers, err := c.crdClient.CrdV1beta1().Tiers().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, tiers.Items, len(systemGeneratedTiers))
}
