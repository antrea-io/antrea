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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	testNode1 = "node1"
)

type fakeNetworkPolicyControl struct {
	sync.Mutex
	status *v1beta2.NetworkPolicyStatus
}

func (c *fakeNetworkPolicyControl) UpdateNetworkPolicyStatus(name string, status *v1beta2.NetworkPolicyStatus) error {
	c.Lock()
	defer c.Unlock()
	c.status = status
	return nil
}

func (c *fakeNetworkPolicyControl) getNetworkPolicyStatus() *v1beta2.NetworkPolicyStatus {
	c.Lock()
	defer c.Unlock()
	return c.status
}

func newTestStatusController() (*StatusController, *ruleCache, *fakeNetworkPolicyControl) {
	ruleCache := newRuleCache(func(s string) {}, make(<-chan v1beta2.PodReference))
	statusControl := &fakeNetworkPolicyControl{}
	statusController := newStatusController(nil, testNode1, ruleCache)
	statusController.statusControlInterface = statusControl
	return statusController, ruleCache, statusControl
}

func TestSyncStatusForNewPolicy(t *testing.T) {
	policyWithSingleRule := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, nil)
	policyWithSingleRule.Generation = 1
	policyWithMultipleRules := newNetworkPolicyWithMultipleRules("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, nil)
	policyWithMultipleRules.Generation = 1
	tests := []struct {
		name           string
		policy         *v1beta2.NetworkPolicy
		realizedRules  int
		expectedStatus *v1beta2.NetworkPolicyStatus
	}{
		{
			name:           "no rules realized",
			policy:         policyWithSingleRule,
			realizedRules:  0,
			expectedStatus: nil,
		},
		{
			name:           "some rules realized",
			policy:         policyWithMultipleRules,
			realizedRules:  1,
			expectedStatus: nil,
		},
		{
			name:          "all rules realized",
			policy:        policyWithMultipleRules,
			realizedRules: 2,
			expectedStatus: &v1beta2.NetworkPolicyStatus{
				ObjectMeta: v1.ObjectMeta{
					Name: policyWithMultipleRules.Name,
				},
				Nodes: []v1beta2.NetworkPolicyNodeStatus{
					{
						NodeName:   testNode1,
						Generation: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusController, ruleCache, statusControl := newTestStatusController()
			stopCh := make(chan struct{})
			defer close(stopCh)
			go statusController.Run(stopCh)

			ruleCache.AddNetworkPolicy(tt.policy)
			rules := ruleCache.getRulesByNetworkPolicy(string(tt.policy.UID))
			for i, rule := range rules {
				// Only make specified number of rules realized.
				if i >= tt.realizedRules {
					break
				}
				statusController.SetRuleRealization(rule.ID, tt.policy.UID)
			}
			// TODO: Use a determinate mechanism.
			time.Sleep(500 * time.Millisecond)
			assert.Equal(t, tt.expectedStatus, statusControl.getNetworkPolicyStatus())
		})
	}
}

func TestSyncStatusUpForUpdatedPolicy(t *testing.T) {
	statusController, ruleCache, statusControl := newTestStatusController()
	stopCh := make(chan struct{})
	defer close(stopCh)
	go statusController.Run(stopCh)

	policy := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, nil)
	policy.Generation = 1
	ruleCache.AddNetworkPolicy(policy)
	rule1 := ruleCache.getRulesByNetworkPolicy(string(policy.UID))[0]
	statusController.SetRuleRealization(rule1.ID, policy.UID)

	matchGeneration := func(generation int64) error {
		return wait.PollImmediate(100*time.Millisecond, 1*time.Second, func() (done bool, err error) {
			status := statusControl.getNetworkPolicyStatus()
			if status == nil {
				return false, nil
			}
			return status.Nodes[0].Generation == generation, nil
		})
	}
	assert.NoError(t, matchGeneration(policy.Generation), "The generation should be updated to %v but was not updated", policy.Generation)

	// Add a new rule to the policy.
	policy.Rules = append(policy.Rules, newPolicyRule(v1beta2.DirectionOut, nil, []string{"addressGroup2"}, nil))
	policy.Generation = 2
	ruleCache.UpdateNetworkPolicy(policy)
	assert.Error(t, matchGeneration(policy.Generation), "The generation should not be updated to %v but was updated", policy.Generation)

	rules := ruleCache.getRulesByNetworkPolicy(string(policy.UID))
	for _, rule := range rules {
		// Only call SetRuleRealization for new rule.
		if rule.ID != rule1.ID {
			statusController.SetRuleRealization(rule.ID, policy.UID)
		}
	}
	assert.NoError(t, matchGeneration(policy.Generation), "The generation should be updated to %v but was not updated", policy.Generation)

	// Remove the above new rule from the policy.
	policy.Rules = policy.Rules[0:1]
	policy.Generation = 3
	ruleCache.UpdateNetworkPolicy(policy)
	assert.Error(t, matchGeneration(policy.Generation), "The generation should not be updated to %v but was updated", policy.Generation)

	for _, rule := range rules {
		// Only call SetRuleRealization for new rule.
		if rule.ID != rule1.ID {
			statusController.DeleteRuleRealization(rule.ID)
		}
	}
	assert.NoError(t, matchGeneration(policy.Generation), "The generation should be updated to %v but was not updated", policy.Generation)
}

// BenchmarkSyncHandler benchmarks syncHandler when the policy has 100 rules. Its current result is:
// 47754 ns/op           15320 B/op         23 allocs/op
func BenchmarkSyncHandler(b *testing.B) {
	statusController, ruleCache, _ := newTestStatusController()

	policy := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, nil)
	policy.Generation = 1
	for i := 1; i < 100; i++ {
		policy.Rules = append(policy.Rules, newPolicyRule(v1beta2.DirectionOut, nil, []string{fmt.Sprintf("addressGroup%d", i)}, nil))
	}
	ruleCache.AddNetworkPolicy(policy)
	rules := ruleCache.getRulesByNetworkPolicy(string(policy.UID))
	for _, rule := range rules {
		statusController.SetRuleRealization(rule.ID, policy.UID)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statusController.syncHandler(policy.UID)
	}
}
