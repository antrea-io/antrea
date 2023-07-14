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
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

func TestInitTier(t *testing.T) {
	testTier := &secv1beta1.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: secv1beta1.TierSpec{
			Priority: 10,
		},
	}
	tests := []struct {
		name           string
		reactor        k8stesting.ReactionFunc
		expectedCalled int
	}{
		{
			name:           "create successfully",
			expectedCalled: 1,
		},
		{
			name: "tier already exists",
			reactor: func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, errors.NewAlreadyExists(action.GetResource().GroupResource(), testTier.Name)
			},
			expectedCalled: 1,
		},
		{
			name: "transient error",
			reactor: func() k8stesting.ReactionFunc {
				curFailureCount := 0
				maxFailureCount := 1
				return func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					if curFailureCount < maxFailureCount {
						curFailureCount += 1
						return true, nil, errors.NewServiceUnavailable("unknown reason")
					}
					return false, nil, nil
				}
			}(),
			expectedCalled: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			if tc.reactor != nil {
				c.crdClient.(*fake.Clientset).PrependReactor("create", "tiers", tc.reactor)
			}
			createCalled := 0
			c.crdClient.(*fake.Clientset).PrependReactor("create", "tiers", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createCalled += 1
				return false, nil, nil
			})
			c.initTier(testTier)
			assert.Equal(t, tc.expectedCalled, createCalled)
		})
	}

}
