// Copyright 2026 Antrea Authors.
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

package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/v2/pkg/antctl/raw/check"
)

func runControlPlaneTest(ctx context.Context, client kubernetes.Interface) error {
	testContext := &testContext{
		Logger: check.NewLogger("[check-control-plane-nodes-availability] "),
		client: client,
	}
	return (&checkControlPlaneAvailability{}).Run(ctx, testContext)
}

func TestCheckControlPlaneAvailabilityRun(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name          string
		nodes         []runtime.Object
		expectedErr   string
		isUncertain   bool
	}{
		{
			name: "passes when control-plane labeled node exists",
			nodes: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "control-plane-node",
						Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
					},
				},
			},
		},
		{
			name: "passes when master labeled node exists",
			nodes: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "master-node",
						Labels: map[string]string{"node-role.kubernetes.io/master": ""},
					},
				},
			},
		},
		{
			name: "warns with uncertainError when only worker nodes exist",
			nodes: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "worker-node",
						Labels: map[string]string{"node-role.kubernetes.io/worker": ""},
					},
				},
			},
			expectedErr: "no control-plane Nodes were found",
			isUncertain: true,
		},
		{
			name:        "warns with uncertainError when no nodes exist in cluster",
			nodes:       []runtime.Object{},
			expectedErr: "no control-plane Nodes were found",
			isUncertain: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tc.nodes...)
			err := runControlPlaneTest(ctx, client)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expectedErr)
				if tc.isUncertain {
					var uErr uncertainError
					assert.ErrorAs(t, err, &uErr)
				}
			}
		})
	}
}
