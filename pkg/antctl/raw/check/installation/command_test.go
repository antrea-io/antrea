// Copyright 2024 Antrea Authors.
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

package installation

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/antctl/raw/check"
)

func overrideTestsRegistry(t *testing.T, registry map[string]Test) {
	oldRegistry := testsRegistry
	testsRegistry = registry
	t.Cleanup(func() {
		testsRegistry = oldRegistry
	})
}

type notRunnableTest struct{}

func (t *notRunnableTest) Run(ctx context.Context, testContext *testContext) error {
	return newNotRunnableError("not runnable")
}

type failedTest struct{}

func (t *failedTest) Run(ctx context.Context, testContext *testContext) error {
	return fmt.Errorf("failed")
}

type successfulTest struct{}

func (t *successfulTest) Run(ctx context.Context, testContext *testContext) error {
	return nil
}

func TestRun(t *testing.T) {
	ctx := context.Background()

	registry := map[string]Test{
		"not-runnable": &notRunnableTest{},
		"failure":      &failedTest{},
		"success":      &successfulTest{},
	}

	testCases := []struct {
		name             string
		registry         map[string]Test
		runFilter        string
		expectedStats    testStats
		expectedNumTotal int
	}{
		{
			name:             "no test in registry",
			expectedStats:    testStats{},
			expectedNumTotal: 0,
		},
		{
			name:     "run all tests",
			registry: registry,
			expectedStats: testStats{
				numSuccess: 1,
				numFailure: 1,
				numSkipped: 1,
			},
			expectedNumTotal: 3,
		},
		{
			name:      "run single test",
			registry:  registry,
			runFilter: "success",
			expectedStats: testStats{
				numSuccess: 1,
			},
			expectedNumTotal: 1,
		},
		{
			name:             "no matching test",
			registry:         registry,
			runFilter:        "my-test",
			expectedStats:    testStats{},
			expectedNumTotal: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			overrideTestsRegistry(t, tc.registry)
			runFilterRegex, err := compileRunFilter(tc.runFilter)
			require.NoError(t, err)
			testContext := NewTestContext(nil, nil, "test-cluster", "kube-system", runFilterRegex, check.DefaultTestImage)
			stats := testContext.runTests(ctx)
			assert.Equal(t, tc.expectedStats, stats)
		})
	}
}
