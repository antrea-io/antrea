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
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/v2/pkg/util/channel"
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
	ruleCache := newRuleCache(func(s string) {}, channel.NewSubscribableChannel("PodUpdate", 100), nil, make(chan string, 100), config.K8sNode)
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
						NodeName:           testNode1,
						Generation:         1,
						RealizationFailure: false,
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
			ruleCache.AddAppliedToGroup(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
			rules := ruleCache.getEffectiveRulesByNetworkPolicy(string(tt.policy.UID))
			for i, rule := range rules {
				// Only make specified number of rules realized.
				if i >= tt.realizedRules {
					break
				}
				statusController.SetRuleRealization(rule.ID, tt.policy.UID, nil)
			}
			// TODO: Use a determinate mechanism.
			time.Sleep(500 * time.Millisecond)
			assert.Equal(t, tt.expectedStatus, statusControl.getNetworkPolicyStatus())
		})
	}
}

func TestRuleRealizationFailureLifecycle(t *testing.T) {
	c, ruleCache, statusControl := newTestStatusController()
	t.Cleanup(c.queue.ShutDown)
	policy := newNetworkPolicyWithMultipleRules("policy1", "uid1", []string{"addressGroup1"}, nil, []string{"appliedToGroup1"}, nil)
	policy.Generation = 1
	ruleCache.AddNetworkPolicy(policy)
	require.NoError(t, ruleCache.AddAppliedToGroup(newAppliedToGroup("appliedToGroup1", nil)))
	rules := ruleCache.getEffectiveRulesByNetworkPolicy(string(policy.UID))
	require.Len(t, rules, 2)

	checkStatus := func(generation int64, messages ...string) {
		t.Helper()
		require.Equal(t, 1, c.queue.Len(), "a changed realization result must enqueue the policy")
		require.True(t, c.processNextWorkItem())
		sort.Strings(messages)
		require.Equal(t, &v1beta2.NetworkPolicyStatus{
			ObjectMeta: v1.ObjectMeta{Name: policy.Name},
			Nodes: []v1beta2.NetworkPolicyNodeStatus{{
				NodeName:           testNode1,
				Generation:         generation,
				RealizationFailure: len(messages) > 0,
				Message:            strings.Join(messages, "; "),
			}},
		}, statusControl.getNetworkPolicyStatus())
	}
	for _, rule := range rules {
		c.SetRuleRealization(rule.ID, policy.UID, nil)
	}
	checkStatus(1)
	c.SetRuleRealization(rules[0].ID, policy.UID, nil)
	assert.Zero(t, c.queue.Len(), "successful group updates must not enqueue an unchanged status")

	// A group update can fail without changing the policy's generation or rule IDs.
	updateErr := errors.New("conjunctive match flow action limit exceeded")
	message0 := fmt.Sprintf("rule %s: %s", rules[0].ID, updateErr)
	c.SetRuleRealization(rules[0].ID, policy.UID, updateErr)
	checkStatus(1, message0)
	c.SetRuleRealization(rules[0].ID, policy.UID, errors.New(updateErr.Error()))
	assert.Zero(t, c.queue.Len(), "repeated failures must not enqueue an unchanged status")

	updateErr = errors.New("OVS update failed")
	message0 = fmt.Sprintf("rule %s: %s", rules[0].ID, updateErr)
	c.SetRuleRealization(rules[0].ID, policy.UID, updateErr)
	checkStatus(1, message0)
	message1 := fmt.Sprintf("rule %s: %s", rules[1].ID, updateErr)
	c.SetRuleRealization(rules[1].ID, policy.UID, updateErr)
	checkStatus(1, message0, message1)

	// A successful retry clears only that rule's failure.
	c.SetRuleRealization(rules[0].ID, policy.UID, nil)
	checkStatus(1, message1)
	c.SetRuleRealization(rules[1].ID, policy.UID, nil)
	checkStatus(1)

	// A failed rule must remain tracked until it has been removed from the dataplane.
	c.SetRuleRealization(rules[1].ID, policy.UID, updateErr)
	checkStatus(1, message1)
	updatedPolicy := policy.DeepCopy()
	updatedPolicy.Generation++
	for i := range updatedPolicy.Rules {
		if updatedPolicy.Rules[i].Direction == rules[1].Direction {
			updatedPolicy.Rules = append(updatedPolicy.Rules[:i], updatedPolicy.Rules[i+1:]...)
			break
		}
	}
	ruleCache.UpdateNetworkPolicy(updatedPolicy)
	c.Resync(policy.UID)
	checkStatus(1, message1)
	c.DeleteRuleRealization(rules[1].ID)
	checkStatus(2)
	c.DeleteRuleRealization(rules[1].ID)
	assert.Zero(t, c.queue.Len(), "deleting an unknown result must not enqueue the policy")
}

func TestSyncStatusFailureWithPendingRules(t *testing.T) {
	tests := []struct {
		name              string
		failedDesiredRule bool
		obsoleteRule      bool
	}{
		{"successful rule and pending rule", false, false},
		{"failed rule and pending rule", true, false},
		{"obsolete failure and pending rule", false, true},
		{"desired failure with obsolete and pending rules", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ruleCache, statusControl := newTestStatusController()
			t.Cleanup(c.queue.ShutDown)
			policy := newNetworkPolicyWithMultipleRules("policy1", "uid1", nil, nil, []string{"appliedToGroup1"}, nil)
			policy.Generation = 1
			ruleCache.AddNetworkPolicy(policy)
			require.NoError(t, ruleCache.AddAppliedToGroup(newAppliedToGroup("appliedToGroup1", nil)))
			rules := ruleCache.getEffectiveRulesByNetworkPolicy(string(policy.UID))
			require.Len(t, rules, 2)
			// The second desired rule is still pending. An obsolete failure must not affect its status.
			if tt.obsoleteRule {
				c.SetRuleRealization("obsolete-rule", policy.UID, errors.New("obsolete failure"))
			}
			var realizationErr error
			if tt.failedDesiredRule {
				realizationErr = errors.New("address update failed")
			}
			c.SetRuleRealization(rules[0].ID, policy.UID, realizationErr)
			require.NoError(t, c.syncHandler(policy.UID))
			status := statusControl.getNetworkPolicyStatus()
			if !tt.failedDesiredRule {
				assert.Nil(t, status, "an obsolete failure must not be reported for the desired policy")
				return
			}
			require.NotNil(t, status, "a desired rule failure must be reported even when other rules are pending")
			assert.True(t, status.Nodes[0].RealizationFailure)
			assert.Equal(t, fmt.Sprintf("rule %s: %s", rules[0].ID, realizationErr), status.Nodes[0].Message)
		})
	}
}

func TestSyncStatusUpForUpdatedPolicy(t *testing.T) {
	statusController, ruleCache, statusControl := newTestStatusController()
	stopCh := make(chan struct{})
	defer close(stopCh)
	go statusController.Run(stopCh)

	ruleCache.AddAppliedToGroup(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
	policy := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, nil)
	policy.Generation = 1
	ruleCache.AddNetworkPolicy(policy)
	rule1 := ruleCache.getEffectiveRulesByNetworkPolicy(string(policy.UID))[0]
	statusController.SetRuleRealization(rule1.ID, policy.UID, nil)

	matchGeneration := func(generation int64) error {
		return wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 1*time.Second, true,
			func(ctx context.Context) (done bool, err error) {
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

	rules := ruleCache.getEffectiveRulesByNetworkPolicy(string(policy.UID))
	for _, rule := range rules {
		// Only call SetRuleRealization for new rule.
		if rule.ID != rule1.ID {
			statusController.SetRuleRealization(rule.ID, policy.UID, nil)
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
	rules := ruleCache.getEffectiveRulesByNetworkPolicy(string(policy.UID))
	for _, rule := range rules {
		statusController.SetRuleRealization(rule.ID, policy.UID, nil)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statusController.syncHandler(policy.UID)
	}
}
