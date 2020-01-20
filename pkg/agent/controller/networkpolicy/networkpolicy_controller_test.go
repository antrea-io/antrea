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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/fake"
)

func newTestController() (*Controller, *fake.Clientset, *mockReconciler) {
	clientset := &fake.Clientset{}
	ch := make(chan v1beta1.PodReference, 100)
	controller := NewNetworkPolicyController(clientset, nil, nil, "node1", ch)
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

func (r *mockReconciler) Forget(ruleID string) error {
	r.Lock()
	defer r.Unlock()
	delete(r.lastRealized, ruleID)
	r.deleted <- ruleID
	return nil
}

func (r *mockReconciler) getLastRealized(ruleID string) (*CompletedRule, bool) {
	r.Lock()
	defer r.Unlock()
	lastRealized, exists := r.lastRealized[ruleID]
	return lastRealized, exists
}

var _ Reconciler = &mockReconciler{}

func newAddressGroup(name string, addresses []v1beta1.GroupMemberPod) *v1beta1.AddressGroup {
	return &v1beta1.AddressGroup{
		ObjectMeta: v1.ObjectMeta{Name: name},
		Pods:       addresses,
	}
}

func newAppliedToGroup(name string, pods []v1beta1.GroupMemberPod) *v1beta1.AppliedToGroup {
	return &v1beta1.AppliedToGroup{
		ObjectMeta: v1.ObjectMeta{Name: name},
		Pods:       pods,
	}
}

func newNetworkPolicy(uid string, from, to, appliedTo []string, services []v1beta1.Service) *v1beta1.NetworkPolicy {
	networkPolicyRule1 := v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      v1beta1.NetworkPolicyPeer{AddressGroups: from},
		To:        v1beta1.NetworkPolicyPeer{AddressGroups: to},
		Services:  services,
	}
	return &v1beta1.NetworkPolicy{
		ObjectMeta:      v1.ObjectMeta{UID: types.UID(uid)},
		Rules:           []v1beta1.NetworkPolicyRule{networkPolicyRule1},
		AppliedToGroups: appliedTo,
	}
}

func getNetworkPolicyWithMultipleRules(uid string, from, to, appliedTo []string, services []v1beta1.Service) *v1beta1.NetworkPolicy {
	networkPolicyRule1 := v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      v1beta1.NetworkPolicyPeer{AddressGroups: from},
		To:        v1beta1.NetworkPolicyPeer{},
		Services:  services,
	}
	networkPolicyRule2 := v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionOut,
		From:      v1beta1.NetworkPolicyPeer{},
		To:        v1beta1.NetworkPolicyPeer{AddressGroups: to},
		Services:  services,
	}
	return &v1beta1.NetworkPolicy{
		ObjectMeta:      v1.ObjectMeta{UID: types.UID(uid)},
		Rules:           []v1beta1.NetworkPolicyRule{networkPolicyRule1, networkPolicyRule2},
		AppliedToGroups: appliedTo,
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

	protocolTCP := v1beta1.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta1.Service{{Protocol: &protocolTCP, Port: &port}}
	desiredRule := &CompletedRule{
		rule:          &rule{Direction: v1beta1.DirectionIn, Services: services},
		FromAddresses: v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")),
		ToAddresses:   v1beta1.NewGroupMemberPodSet(),
		Pods:          v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// policy1 comes first, no rule will be synced due to missing addressGroup1 and appliedToGroup1.
	networkPolicyWatcher.Add(newNetworkPolicy("policy1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, services))
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 0, controller.GetAddressGroupNum())
	assert.Equal(t, 0, controller.GetAppliedToGroupNum())

	// addressGroup1 comes, no rule will be synced due to missing appliedToGroup1 data.
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 1, controller.GetAddressGroupNum())
	assert.Equal(t, 0, controller.GetAppliedToGroupNum())

	// appliedToGroup1 comes, policy1 will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")}))
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
		if !actualRule.Pods.Equal(desiredRule.Pods) {
			t.Errorf("Expected Pods %v, got %v", actualRule.Pods, desiredRule.Pods)
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

	protocolTCP := v1beta1.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta1.Service{{Protocol: &protocolTCP, Port: &port}}
	desiredRule := &CompletedRule{
		rule:          &rule{Direction: v1beta1.DirectionIn, Services: services},
		FromAddresses: v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2"), newAddressGroupMember("3.3.3.3")),
		ToAddresses:   v1beta1.NewGroupMemberPodSet(),
		Pods:          v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns2")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// addressGroup1 comes, no rule will be synced.
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	// appliedToGroup1 comes, no rule will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")}))
	// policy1 comes first, no rule will be synced due to missing addressGroup2 and appliedToGroup2.
	networkPolicyWatcher.Add(newNetworkPolicy("policy1", []string{"addressGroup1", "addressGroup2"}, []string{}, []string{"appliedToGroup1", "appliedToGroup2"}, services))
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 1, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())

	// addressGroup2 comes, no rule will be synced due to missing appliedToGroup2 data.
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("3.3.3.3")}))
	select {
	case ruleID := <-reconciler.updated:
		t.Fatalf("Expected no update, got %v", ruleID)
	case <-time.After(time.Millisecond * 100):
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())

	// appliedToGroup2 comes, policy1 will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup2", []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod2", "ns2")}))
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
		if !actualRule.Pods.Equal(desiredRule.Pods) {
			t.Errorf("Expected Pods %v, got %v", actualRule.Pods, desiredRule.Pods)
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

	protocolTCP := v1beta1.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta1.Service{{Protocol: &protocolTCP, Port: &port}}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")}))
	networkPolicyWatcher.Add(newNetworkPolicy("policy1", []string{"addressGroup1"}, []string{}, []string{"appliedToGroup1"}, services))
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

	networkPolicyWatcher.Delete(newNetworkPolicy("policy1", []string{}, []string{}, []string{}, nil))
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

	protocolTCP := v1beta1.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta1.Service{{Protocol: &protocolTCP, Port: &port}}
	desiredRule1 := &CompletedRule{
		rule:          &rule{Direction: v1beta1.DirectionIn, Services: services},
		FromAddresses: v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")),
		ToAddresses:   v1beta1.NewGroupMemberPodSet(),
		Pods:          v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1")),
	}
	desiredRule2 := &CompletedRule{
		rule:          &rule{Direction: v1beta1.DirectionOut, Services: services},
		FromAddresses: v1beta1.NewGroupMemberPodSet(),
		ToAddresses:   v1beta1.NewGroupMemberPodSet(newAddressGroupMember("3.3.3.3"), newAddressGroupMember("4.4.4.4")),
		Pods:          v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// Test NetworkPolicyInfoQuerier functions when the NetworkPolicy has multiple rules.
	networkPolicyWatcher.Add(getNetworkPolicyWithMultipleRules("policy1", []string{"addressGroup1"}, []string{"addressGroup2"}, []string{"appliedToGroup1"}, services))
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta1.GroupMemberPod{*newAddressGroupMember("3.3.3.3"), *newAddressGroupMember("4.4.4.4")}))
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")}))
	for i := 0; i < 2; i++ {
		select {
		case ruleID := <-reconciler.updated:
			actualRule, _ := reconciler.getLastRealized(ruleID)
			if actualRule.Direction == v1beta1.DirectionIn {
				if !assert.ElementsMatch(t, actualRule.Services, desiredRule1.Services) {
					t.Errorf("Expected Services %v, got %v", actualRule.Services, desiredRule1.Services)
				}
				if !actualRule.FromAddresses.Equal(desiredRule1.FromAddresses) {
					t.Errorf("Expected FromAddresses %v, got %v", actualRule.FromAddresses, desiredRule1.FromAddresses)
				}
				if !actualRule.ToAddresses.Equal(desiredRule1.ToAddresses) {
					t.Errorf("Expected ToAddresses %v, got %v", actualRule.ToAddresses, desiredRule1.ToAddresses)
				}
				if !actualRule.Pods.Equal(desiredRule1.Pods) {
					t.Errorf("Expected Pods %v, got %v", actualRule.Pods, desiredRule1.Pods)
				}
			}
			if actualRule.Direction == v1beta1.DirectionOut {
				if !assert.ElementsMatch(t, actualRule.Services, desiredRule2.Services) {
					t.Errorf("Expected Services %v, got %v", actualRule.Services, desiredRule2.Services)
				}
				if !actualRule.FromAddresses.Equal(desiredRule2.FromAddresses) {
					t.Errorf("Expected FromAddresses %v, got %v", actualRule.FromAddresses, desiredRule2.FromAddresses)
				}
				if !actualRule.ToAddresses.Equal(desiredRule2.ToAddresses) {
					t.Errorf("Expected ToAddresses %v, got %v", actualRule.ToAddresses, desiredRule2.ToAddresses)
				}
				if !actualRule.Pods.Equal(desiredRule2.Pods) {
					t.Errorf("Expected Pods %v, got %v", actualRule.Pods, desiredRule2.Pods)
				}
			}

		case <-time.After(time.Millisecond * 100):
			t.Fatal("Expected two rule updates, got timeout")
		}
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())
}
