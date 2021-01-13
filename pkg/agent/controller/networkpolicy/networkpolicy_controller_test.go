// Copyright 2019 Antrea Authors
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/component-base/metrics/testutil"

	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	agenttypes "github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/fake"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

const testNamespace = "ns1"

type antreaClientGetter struct {
	clientset versioned.Interface
}

func (g *antreaClientGetter) GetAntreaClient() (versioned.Interface, error) {
	return g.clientset, nil
}

func newTestController() (*Controller, *fake.Clientset, *mockReconciler) {
	clientset := &fake.Clientset{}
	ch := make(chan v1beta2.PodReference, 100)
	controller, _ := NewNetworkPolicyController(&antreaClientGetter{clientset}, nil, nil, "node1", ch,
		true, true, true, false, testAsyncDeleteInterval)
	reconciler := newMockReconciler()
	controller.reconciler = reconciler
	return controller, clientset, reconciler
}

// mockReconciler implements Reconciler. It simply records the latest states of rules
// it has been asked to reconcile, and provides two channels to receive its notifications
// for testing.
type mockReconciler struct {
	sync.Mutex
	lastRealized map[string]*CompletedRule
	updated      chan string
	deleted      chan string
}

func newMockReconciler() *mockReconciler {
	return &mockReconciler{
		lastRealized: map[string]*CompletedRule{},
		updated:      make(chan string, 10),
		deleted:      make(chan string, 10),
	}
}

func (r *mockReconciler) Reconcile(rule *CompletedRule) error {
	r.Lock()
	defer r.Unlock()
	r.lastRealized[rule.ID] = rule
	r.updated <- rule.ID
	return nil
}

func (r *mockReconciler) BatchReconcile(rules []*CompletedRule) error {
	r.Lock()
	defer r.Unlock()
	for _, rule := range rules {
		r.lastRealized[rule.ID] = rule
		r.updated <- rule.ID
	}
	return nil
}

func (r *mockReconciler) Forget(ruleID string) error {
	r.Lock()
	defer r.Unlock()
	delete(r.lastRealized, ruleID)
	r.deleted <- ruleID
	return nil
}

func (r *mockReconciler) RunIDAllocatorWorker(_ <-chan struct{}) {
	return
}

func (r *mockReconciler) GetRuleByFlowID(_ uint32) (*agenttypes.PolicyRule, bool, error) {
	return nil, false, nil
}

func (r *mockReconciler) getLastRealized(ruleID string) (*CompletedRule, bool) {
	r.Lock()
	defer r.Unlock()
	lastRealized, exists := r.lastRealized[ruleID]
	return lastRealized, exists
}

var _ Reconciler = &mockReconciler{}

func newAddressGroup(name string, addresses []v1beta2.GroupMember) *v1beta2.AddressGroup {
	return &v1beta2.AddressGroup{
		ObjectMeta:   v1.ObjectMeta{Name: name},
		GroupMembers: addresses,
	}
}

func newAppliedToGroup(name string, pods []v1beta2.GroupMember) *v1beta2.AppliedToGroup {
	return &v1beta2.AppliedToGroup{
		ObjectMeta:   v1.ObjectMeta{Name: name},
		GroupMembers: pods,
	}
}

func newNetworkPolicy(name string, uid types.UID, from, to, appliedTo []string, services []v1beta2.Service) *v1beta2.NetworkPolicy {
	networkPolicyRule1 := newPolicyRule(v1beta2.DirectionIn, from, to, services)
	return &v1beta2.NetworkPolicy{
		ObjectMeta:      v1.ObjectMeta{UID: uid, Name: string(uid)},
		Rules:           []v1beta2.NetworkPolicyRule{networkPolicyRule1},
		AppliedToGroups: appliedTo,
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: testNamespace,
			Name:      name,
			UID:       uid,
		},
	}
}

func newPolicyRule(direction v1beta2.Direction, from []string, to []string, services []v1beta2.Service) v1beta2.NetworkPolicyRule {
	return v1beta2.NetworkPolicyRule{
		Direction: direction,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: from},
		To:        v1beta2.NetworkPolicyPeer{AddressGroups: to},
		Services:  services,
	}
}

func newNetworkPolicyWithMultipleRules(name string, uid types.UID, from, to, appliedTo []string, services []v1beta2.Service) *v1beta2.NetworkPolicy {
	networkPolicyRule1 := v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: from},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  services,
	}
	networkPolicyRule2 := v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      v1beta2.NetworkPolicyPeer{},
		To:        v1beta2.NetworkPolicyPeer{AddressGroups: to},
		Services:  services,
	}
	return &v1beta2.NetworkPolicy{
		ObjectMeta:      v1.ObjectMeta{UID: uid, Name: string(uid)},
		Rules:           []v1beta2.NetworkPolicyRule{networkPolicyRule1, networkPolicyRule2},
		AppliedToGroups: appliedTo,
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: testNamespace,
			Name:      name,
			UID:       uid,
		},
	}
}

func TestAddSingleGroupRule(t *testing.T) {
	controller, clientset, reconciler := newTestController()
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	desiredRule := &CompletedRule{
		rule:          &rule{Direction: v1beta2.DirectionIn, Services: services},
		FromAddresses: v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")),
		ToAddresses:   v1beta2.NewGroupMemberSet(),
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// policy1 comes first, no rule will be synced due to missing addressGroup1 and appliedToGroup1.
	policy1 := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, services)
	networkPolicyWatcher.Add(policy1)
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	networkPolicies := controller.GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{SourceName: policy1.SourceRef.Name, Namespace: policy1.SourceRef.Namespace})
	require.Equal(t, 1, len(networkPolicies))
	assert.Equal(t, policy1, &networkPolicies[0])
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 0, controller.GetAddressGroupNum())
	assert.Equal(t, 0, controller.GetAppliedToGroupNum())

	// addressGroup1 comes, no rule will be synced due to missing appliedToGroup1 data.
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 1, controller.GetAddressGroupNum())
	assert.Equal(t, 0, controller.GetAppliedToGroupNum())

	// appliedToGroup1 comes, policy1 will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	select {
	case ruleID := <-reconciler.updated:
		actualRule, _ := reconciler.getLastRealized(ruleID)
		if actualRule.Direction != desiredRule.Direction {
			t.Errorf("Expected Direction %v, got %v", actualRule.Direction, desiredRule.Direction)
		}
		if !assert.ElementsMatch(t, actualRule.Services, desiredRule.Services) {
			t.Errorf("Expected Services %v, got %v", actualRule.Services, desiredRule.Services)
		}
		if !actualRule.FromAddresses.Equal(desiredRule.FromAddresses) {
			t.Errorf("Expected FromAddresses %v, got %v", actualRule.FromAddresses, desiredRule.FromAddresses)
		}
		if !actualRule.ToAddresses.Equal(desiredRule.ToAddresses) {
			t.Errorf("Expected ToAddresses %v, got %v", actualRule.ToAddresses, desiredRule.ToAddresses)
		}
		if !actualRule.TargetMembers.Equal(desiredRule.TargetMembers) {
			t.Errorf("Expected Pods %v, got %v", actualRule.TargetMembers, desiredRule.TargetMembers)
		}
	case <-time.After(time.Millisecond * 100):
		t.Fatal("Expected one update, got none")
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 1, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())
}

func TestAddMultipleGroupsRule(t *testing.T) {
	controller, clientset, reconciler := newTestController()
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	desiredRule := &CompletedRule{
		rule:          &rule{Direction: v1beta2.DirectionIn, Services: services},
		FromAddresses: v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2"), newAddressGroupMember("3.3.3.3")),
		ToAddresses:   v1beta2.NewGroupMemberSet(),
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns2")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// addressGroup1 comes, no rule will be synced.
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	// appliedToGroup1 comes, no rule will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	// policy1 comes first, no rule will be synced due to missing addressGroup2 and appliedToGroup2.
	policy1 := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1", "addressGroup2"}, []string{}, []string{"appliedToGroup1", "appliedToGroup2"}, services)
	networkPolicyWatcher.Add(policy1)
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	networkPolicies := controller.GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{SourceName: policy1.SourceRef.Name, Namespace: policy1.SourceRef.Namespace})
	require.Equal(t, 1, len(networkPolicies))
	assert.Equal(t, policy1, &networkPolicies[0])
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 1, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())

	// addressGroup2 comes, no rule will be synced due to missing appliedToGroup2 data.
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("3.3.3.3")}))
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())

	// appliedToGroup2 comes, policy1 will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup2", []v1beta2.GroupMember{*newAppliedToGroupMember("pod2", "ns2")}))
	select {
	case ruleID := <-reconciler.updated:
		actualRule, _ := reconciler.getLastRealized(ruleID)
		if actualRule.Direction != desiredRule.Direction {
			t.Errorf("Expected Direction %v, got %v", actualRule.Direction, desiredRule.Direction)
		}
		if !assert.ElementsMatch(t, actualRule.Services, desiredRule.Services) {
			t.Errorf("Expected Services %v, got %v", actualRule.Services, desiredRule.Services)
		}
		if !actualRule.FromAddresses.Equal(desiredRule.FromAddresses) {
			t.Errorf("Expected FromAddresses %v, got %v", actualRule.FromAddresses, desiredRule.FromAddresses)
		}
		if !actualRule.ToAddresses.Equal(desiredRule.ToAddresses) {
			t.Errorf("Expected ToAddresses %v, got %v", actualRule.ToAddresses, desiredRule.ToAddresses)
		}
		if !actualRule.TargetMembers.Equal(desiredRule.TargetMembers) {
			t.Errorf("Expected Pods %v, got %v", actualRule.TargetMembers, desiredRule.TargetMembers)
		}
	case <-time.After(time.Millisecond * 100):
		t.Fatal("Expected one update, got none")
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 2, controller.GetAppliedToGroupNum())
}

func TestDeleteRule(t *testing.T) {
	controller, clientset, reconciler := newTestController()
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	networkPolicyWatcher.Add(newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, services))
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	select {
	case ruleID := <-reconciler.updated:
		_, exists := reconciler.getLastRealized(ruleID)
		if !exists {
			t.Fatalf("Expected rule %s, got none", ruleID)
		}
	case <-time.After(time.Millisecond * 100):
		t.Fatal("Expected one update, got none")
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 1, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())

	networkPolicyWatcher.Delete(newNetworkPolicy("policy1", "uid1", []string{}, []string{}, []string{}, nil))
	select {
	case ruleID := <-reconciler.deleted:
		actualRule, exists := reconciler.getLastRealized(ruleID)
		if exists {
			t.Errorf("Expected no rule, got %v", actualRule)
		}
	case <-time.After(time.Millisecond * 100):
		t.Fatal("Expected one update, got none")
	}
}

func TestAddNetworkPolicyWithMultipleRules(t *testing.T) {
	controller, clientset, reconciler := newTestController()
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	desiredRule1 := &CompletedRule{
		rule:          &rule{Direction: v1beta2.DirectionIn, Services: services},
		FromAddresses: v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")),
		ToAddresses:   v1beta2.NewGroupMemberSet(),
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1")),
	}
	desiredRule2 := &CompletedRule{
		rule:          &rule{Direction: v1beta2.DirectionOut, Services: services},
		FromAddresses: v1beta2.NewGroupMemberSet(),
		ToAddresses:   v1beta2.NewGroupMemberSet(newAddressGroupMember("3.3.3.3"), newAddressGroupMember("4.4.4.4")),
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// Test NetworkPolicyInfoQuerier functions when the NetworkPolicy has multiple rules.
	policy1 := newNetworkPolicyWithMultipleRules("policy1", "uid1", []string{"addressGroup1"}, []string{"addressGroup2"}, []string{"appliedToGroup1"}, services)
	networkPolicyWatcher.Add(policy1)
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta2.GroupMember{*newAddressGroupMember("3.3.3.3"), *newAddressGroupMember("4.4.4.4")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	for i := 0; i < 2; i++ {
		select {
		case ruleID := <-reconciler.updated:
			actualRule, _ := reconciler.getLastRealized(ruleID)
			if actualRule.Direction == v1beta2.DirectionIn {
				if !assert.ElementsMatch(t, actualRule.Services, desiredRule1.Services) {
					t.Errorf("Expected Services %v, got %v", actualRule.Services, desiredRule1.Services)
				}
				if !actualRule.FromAddresses.Equal(desiredRule1.FromAddresses) {
					t.Errorf("Expected FromAddresses %v, got %v", actualRule.FromAddresses, desiredRule1.FromAddresses)
				}
				if !actualRule.ToAddresses.Equal(desiredRule1.ToAddresses) {
					t.Errorf("Expected ToAddresses %v, got %v", actualRule.ToAddresses, desiredRule1.ToAddresses)
				}
				if !actualRule.TargetMembers.Equal(desiredRule1.TargetMembers) {
					t.Errorf("Expected Pods %v, got %v", actualRule.TargetMembers, desiredRule1.TargetMembers)
				}
			}
			if actualRule.Direction == v1beta2.DirectionOut {
				if !assert.ElementsMatch(t, actualRule.Services, desiredRule2.Services) {
					t.Errorf("Expected Services %v, got %v", actualRule.Services, desiredRule2.Services)
				}
				if !actualRule.FromAddresses.Equal(desiredRule2.FromAddresses) {
					t.Errorf("Expected FromAddresses %v, got %v", actualRule.FromAddresses, desiredRule2.FromAddresses)
				}
				if !actualRule.ToAddresses.Equal(desiredRule2.ToAddresses) {
					t.Errorf("Expected ToAddresses %v, got %v", actualRule.ToAddresses, desiredRule2.ToAddresses)
				}
				if !actualRule.TargetMembers.Equal(desiredRule2.TargetMembers) {
					t.Errorf("Expected Pods %v, got %v", actualRule.TargetMembers, desiredRule2.TargetMembers)
				}
			}

		case <-time.After(time.Millisecond * 100):
			t.Fatal("Expected two rule updates, got timeout")
		}
	}
	networkPolicies := controller.GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{SourceName: policy1.SourceRef.Name, Namespace: policy1.SourceRef.Namespace})
	require.Equal(t, 1, len(networkPolicies))
	assert.ElementsMatch(t, policy1.Rules, networkPolicies[0].Rules)
	assert.ElementsMatch(t, policy1.AppliedToGroups, networkPolicies[0].AppliedToGroups)
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())
}

func TestNetworkPolicyMetrics(t *testing.T) {
	// Initialize NetworkPolicy metrics (prometheus)
	metrics.InitializeNetworkPolicyMetrics()
	controller, clientset, reconciler := newTestController()

	// Define functions to wait for a message from reconciler
	waitForReconcilerUpdated := func() {
		select {
		case ruleID := <-reconciler.updated:
			_, exists := reconciler.getLastRealized(ruleID)
			if !exists {
				t.Fatalf("Expected rule %s, got none", ruleID)
			}
		case <-time.After(time.Millisecond * 100):
			t.Fatal("Expected one update, got none")
		}
	}
	waitForReconcilerDeleted := func() {
		select {
		case ruleID := <-reconciler.deleted:
			actualRule, exists := reconciler.getLastRealized(ruleID)
			if exists {
				t.Fatalf("Expected no rule, got %v", actualRule)
			}
		case <-time.After(time.Millisecond * 100):
			t.Fatal("Expected one update, got none")
		}
	}

	// Define a function to check networkpolicy metrics
	checkNetworkPolicyMetrics := func() {
		expectedEgressNetworkPolicyRuleCount := `
		# HELP antrea_agent_egress_networkpolicy_rule_count [STABLE] Number of egress networkpolicy rules on local node which are managed by the Antrea Agent.
		# TYPE antrea_agent_egress_networkpolicy_rule_count gauge
		`

		expectedIngressNetworkPolicyRuleCount := `
		# HELP antrea_agent_ingress_networkpolicy_rule_count [STABLE] Number of ingress networkpolicy rules on local node which are managed by the Antrea Agent.
		# TYPE antrea_agent_ingress_networkpolicy_rule_count gauge
		`

		expectedNetworkPolicyCount := `
		# HELP antrea_agent_networkpolicy_count [STABLE] Number of networkpolicies on local node which are managed by the Antrea Agent.
		# TYPE antrea_agent_networkpolicy_count gauge
		`

		ingressRuleCount := 0
		egressRuleCount := 0

		// Get all networkpolicies
		networkpolicies := controller.GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{})
		for _, networkpolicy := range networkpolicies {
			for _, rule := range networkpolicy.Rules {
				if rule.Direction == v1beta2.DirectionIn {
					ingressRuleCount++
				} else {
					egressRuleCount++
				}
			}
		}

		expectedEgressNetworkPolicyRuleCount = expectedEgressNetworkPolicyRuleCount + fmt.Sprintf("antrea_agent_egress_networkpolicy_rule_count %d\n", egressRuleCount)
		expectedIngressNetworkPolicyRuleCount = expectedIngressNetworkPolicyRuleCount + fmt.Sprintf("antrea_agent_ingress_networkpolicy_rule_count %d\n", ingressRuleCount)
		expectedNetworkPolicyCount = expectedNetworkPolicyCount + fmt.Sprintf("antrea_agent_networkpolicy_count %d\n", controller.GetNetworkPolicyNum())

		assert.NoError(t, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedEgressNetworkPolicyRuleCount), "antrea_agent_egress_networkpolicy_rule_count"))
		assert.NoError(t, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedIngressNetworkPolicyRuleCount), "antrea_agent_ingress_networkpolicy_rule_count"))
		assert.NoError(t, testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedNetworkPolicyCount), "antrea_agent_networkpolicy_count"))
	}

	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// Test adding policy1 with a single rule
	policy1 := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, services)
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	networkPolicyWatcher.Add(policy1)
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	waitForReconcilerUpdated()
	checkNetworkPolicyMetrics()

	// Test adding policy2 with multiple rules
	policy2 := newNetworkPolicyWithMultipleRules("policy2", "uid2", []string{"addressGroup2"}, []string{"addressGroup2"}, []string{"appliedToGroup2"}, services)
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta2.GroupMember{*newAddressGroupMember("3.3.3.3"), *newAddressGroupMember("4.4.4.4")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup2", []v1beta2.GroupMember{*newAppliedToGroupMember("pod2", "ns2")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	networkPolicyWatcher.Add(policy2)
	waitForReconcilerUpdated()
	checkNetworkPolicyMetrics()

	// Test deleting policy1
	networkPolicyWatcher.Delete(newNetworkPolicy("policy1", "uid1", []string{}, []string{}, []string{}, nil))
	waitForReconcilerDeleted()
	checkNetworkPolicyMetrics()

	// Test deleting policy2
	networkPolicyWatcher.Delete(newNetworkPolicy("policy2", "uid2", []string{}, []string{}, []string{}, nil))
	waitForReconcilerDeleted()
	checkNetworkPolicyMetrics()
}
