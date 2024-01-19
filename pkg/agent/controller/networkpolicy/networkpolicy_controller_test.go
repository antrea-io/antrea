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
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy/l7engine"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/wait"
)

const testNamespace = "ns1"

var mockOFTables = map[*openflow.Table]uint8{
	openflow.AntreaPolicyEgressRuleTable:  uint8(5),
	openflow.EgressRuleTable:              uint8(6),
	openflow.EgressDefaultTable:           uint8(7),
	openflow.AntreaPolicyIngressRuleTable: uint8(12),
	openflow.IngressRuleTable:             uint8(13),
	openflow.IngressDefaultTable:          uint8(14),
	openflow.OutputTable:                  uint8(28),
}

type antreaClientGetter struct {
	clientset versioned.Interface
}

func (g *antreaClientGetter) GetAntreaClient() (versioned.Interface, error) {
	return g.clientset, nil
}

func newTestController() (*Controller, *fake.Clientset, *mockReconciler) {
	clientset := &fake.Clientset{}
	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	ch2 := make(chan string, 100)
	groupIDAllocator := openflow.NewGroupAllocator()
	groupCounters := []proxytypes.GroupCounter{proxytypes.NewGroupCounter(groupIDAllocator, ch2)}
	fs := afero.NewMemMapFs()
	l7reconciler := l7engine.NewReconciler()
	controller, _ := NewNetworkPolicyController(&antreaClientGetter{clientset},
		nil,
		nil,
		nil,
		fs,
		"node1",
		podUpdateChannel,
		nil,
		groupCounters,
		ch2,
		true,
		true,
		false,
		true,
		true,
		false,
		nil,
		testAsyncDeleteInterval,
		"8.8.8.8:53",
		config.K8sNode,
		true,
		false,
		config.HostGatewayOFPort,
		config.DefaultTunOFPort,
		&config.NodeConfig{},
		wait.NewGroup(),
		l7reconciler)
	reconciler := newMockReconciler()
	controller.podReconciler = reconciler
	controller.auditLogger = nil
	return controller, clientset, reconciler
}

// mockReconciler implements Reconciler. It simply records the latest states of rules
// it has been asked to reconcile, and provides two channels to receive its notifications
// for testing.
type mockReconciler struct {
	sync.Mutex
	lastRealized   map[string]*CompletedRule
	updated        chan string
	deleted        chan string
	fqdnController *fqdnController
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

func (r *mockReconciler) RegisterFQDNController(fc *fqdnController) {
	r.fqdnController = fc
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
		TypeMeta:     v1.TypeMeta{Kind: "AddressGroup", APIVersion: "controlplane.antrea.io/v1beta2"},
		ObjectMeta:   v1.ObjectMeta{Name: name, UID: types.UID(name)},
		GroupMembers: addresses,
	}
}

func newAppliedToGroup(name string, pods []v1beta2.GroupMember) *v1beta2.AppliedToGroup {
	return &v1beta2.AppliedToGroup{
		TypeMeta:     v1.TypeMeta{Kind: "AppliedToGroup", APIVersion: "controlplane.antrea.io/v1beta2"},
		ObjectMeta:   v1.ObjectMeta{Name: name, UID: types.UID(name)},
		GroupMembers: pods,
	}
}

func newNetworkPolicy(name string, uid types.UID, from, to, appliedTo []string, services []v1beta2.Service) *v1beta2.NetworkPolicy {
	dir := v1beta2.DirectionIn
	if len(from) == 0 && len(to) > 0 {
		dir = v1beta2.DirectionOut
	}
	networkPolicyRule1 := newPolicyRule(dir, from, to, services)
	return &v1beta2.NetworkPolicy{
		TypeMeta:        v1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "controlplane.antrea.io/v1beta2"},
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

func prepareMockTables() {
	openflow.InitMockTables(mockOFTables)
}

func TestAddSingleGroupRule(t *testing.T) {
	prepareMockTables()
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
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")),
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
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
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
	prepareMockTables()
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
		ToAddresses:   nil,
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"), newAppliedToGroupMemberPod("pod2", "ns2")),
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	// addressGroup1 comes, no rule will be synced.
	addressGroupWatcher.Add(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	// appliedToGroup1 comes, no rule will be synced.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
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

	// addressGroup2 comes, policy1 will be synced with the TargetMembers populated from appliedToGroup1.
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("3.3.3.3")}))
	select {
	case ruleID := <-reconciler.updated:
		actualRule, _ := reconciler.getLastRealized(ruleID)
		assert.Equal(t, actualRule.Direction, desiredRule.Direction)
		assert.ElementsMatch(t, actualRule.Services, desiredRule.Services)
		assert.Equal(t, actualRule.FromAddresses, desiredRule.FromAddresses)
		assert.Equal(t, actualRule.ToAddresses, desiredRule.ToAddresses)
		assert.Equal(t, actualRule.TargetMembers, v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")))
	case <-time.After(time.Millisecond * 100):
		t.Fatal("Expected one update, got none")
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 1, controller.GetAppliedToGroupNum())

	// appliedToGroup2 comes, policy1 will be synced with the TargetMembers populated from appliedToGroup1 and appliedToGroup2.
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup2", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod2", "ns2")}))
	select {
	case ruleID := <-reconciler.updated:
		actualRule, _ := reconciler.getLastRealized(ruleID)
		assert.Equal(t, actualRule.Direction, desiredRule.Direction)
		assert.ElementsMatch(t, actualRule.Services, desiredRule.Services)
		assert.Equal(t, actualRule.FromAddresses, desiredRule.FromAddresses)
		assert.Equal(t, actualRule.ToAddresses, desiredRule.ToAddresses)
		assert.Equal(t, actualRule.TargetMembers, desiredRule.TargetMembers)
	case <-time.After(time.Millisecond * 100):
		t.Fatal("Expected one update, got none")
	}
	assert.Equal(t, 1, controller.GetNetworkPolicyNum())
	assert.Equal(t, 2, controller.GetAddressGroupNum())
	assert.Equal(t, 2, controller.GetAppliedToGroupNum())
}

func TestDeleteRule(t *testing.T) {
	prepareMockTables()
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
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
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
	prepareMockTables()
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
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")),
	}
	desiredRule2 := &CompletedRule{
		rule:          &rule{Direction: v1beta2.DirectionOut, Services: services},
		FromAddresses: v1beta2.NewGroupMemberSet(),
		ToAddresses:   v1beta2.NewGroupMemberSet(newAddressGroupMember("3.3.3.3"), newAddressGroupMember("4.4.4.4")),
		TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")),
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
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	for i := 0; i < 2; i++ {
		select {
		case ruleID := <-reconciler.updated:
			actualRule, _ := reconciler.getLastRealized(ruleID)
			if actualRule.Direction == v1beta2.DirectionIn {
				if !assert.ElementsMatch(t, actualRule.Services, desiredRule1.Services) {
					t.Errorf("Expected Services %v, got %v", desiredRule1.Services, actualRule.Services)
				}
				if !actualRule.FromAddresses.Equal(desiredRule1.FromAddresses) {
					t.Errorf("Expected FromAddresses %v, got %v", desiredRule1.FromAddresses, actualRule.FromAddresses)
				}
				if !actualRule.ToAddresses.Equal(desiredRule1.ToAddresses) {
					t.Errorf("Expected ToAddresses %v, got %v", desiredRule1.ToAddresses, actualRule.ToAddresses)
				}
				if !actualRule.TargetMembers.Equal(desiredRule1.TargetMembers) {
					t.Errorf("Expected Pods %v, got %v", desiredRule1.TargetMembers, actualRule.TargetMembers)
				}
			}
			if actualRule.Direction == v1beta2.DirectionOut {
				if !assert.ElementsMatch(t, actualRule.Services, desiredRule2.Services) {
					t.Errorf("Expected Services %v, got %v", desiredRule2.Services, actualRule.Services)
				}
				if !actualRule.FromAddresses.Equal(desiredRule2.FromAddresses) {
					t.Errorf("Expected FromAddresses %v, got %v", desiredRule2.FromAddresses, actualRule.FromAddresses)
				}
				if !actualRule.ToAddresses.Equal(desiredRule2.ToAddresses) {
					t.Errorf("Expected ToAddresses %v, got %v", desiredRule2.ToAddresses, actualRule.ToAddresses)
				}
				if !actualRule.TargetMembers.Equal(desiredRule2.TargetMembers) {
					t.Errorf("Expected Pods %v, got %v", desiredRule2.TargetMembers, actualRule.TargetMembers)
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

func writeToFile(t *testing.T, fs afero.Fs, dir, file string, base64Str string) {
	data, err := base64.StdEncoding.DecodeString(base64Str)
	require.NoError(t, err)
	f, err := fs.OpenFile(dir+"/"+file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(data)
	require.NoError(t, err)
}

func TestFallbackToFileStore(t *testing.T) {
	prepareMockTables()
	tests := []struct {
		name          string
		initFileStore func(networkPolicyStore, appliedToGroupStore, addressGroupStore *fileStore)
		expectedRule  *CompletedRule
	}{
		{
			name: "same storage version",
			initFileStore: func(networkPolicyStore, appliedToGroupStore, addressGroupStore *fileStore) {
				networkPolicyStore.save(newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, nil, []string{"appliedToGroup1"}, nil))
				appliedToGroupStore.save(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "namespace")}))
				addressGroupStore.save(newAddressGroup("addressGroup1", []v1beta2.GroupMember{*newAddressGroupPodMember("pod2", "namespace", "192.168.0.1")}))
			},
			expectedRule: &CompletedRule{
				rule: &rule{
					Direction:       v1beta2.DirectionIn,
					From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
					MaxPriority:     -1,
					AppliedToGroups: []string{"appliedToGroup1"},
					PolicyUID:       "uid1",
					PolicyName:      "uid1",
					SourceRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.K8sNetworkPolicy,
						Namespace: testNamespace,
						Name:      "policy1",
						UID:       "uid1",
					},
				},
				FromAddresses: v1beta2.NewGroupMemberSet(newAddressGroupPodMember("pod2", "namespace", "192.168.0.1")),
				TargetMembers: v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "namespace")),
			},
		},
		{
			// The test is to ensure compatibility with v1beta2 storage version if one day the used version is upgraded.
			name: "compatible with v1beta2",
			initFileStore: func(networkPolicyStore, appliedToGroupStore, addressGroupStore *fileStore) {
				// The bytes of v1beta2 objects serialized in protobuf.
				// They are not supposed to be updated when bumping up the used version.
				base64EncodedPolicy := "azhzAAovCh5jb250cm9scGxhbmUuYW50cmVhLmlvL3YxYmV0YTISDU5ldHdvcmtQb2xpY3kSdAoYCgR1aWQxEgAaACIAKgR1aWQxMgA4AEIAEh8KAkluEg8KDWFkZHJlc3NHcm91cDEaACgAOABKAFoAGg9hcHBsaWVkVG9Hcm91cDEyJgoQSzhzTmV0d29ya1BvbGljeRIDbnMxGgdwb2xpY3kxIgR1aWQxGgAiAA=="
				base64EncodedAppliedToGroup := "azhzAAowCh5jb250cm9scGxhbmUuYW50cmVhLmlvL3YxYmV0YTISDkFwcGxpZWRUb0dyb3VwEkUKLgoPYXBwbGllZFRvR3JvdXAxEgAaACIAKg9hcHBsaWVkVG9Hcm91cDEyADgAQgASEwoRCgRwb2QxEgluYW1lc3BhY2UaACIA"
				base64EncodedAddressGroup := "azhzAAouCh5jb250cm9scGxhbmUuYW50cmVhLmlvL3YxYmV0YTISDEFkZHJlc3NHcm91cBJTCioKDWFkZHJlc3NHcm91cDESABoAIgAqDWFkZHJlc3NHcm91cDEyADgAQgASJQoRCgRwb2QyEgluYW1lc3BhY2UaEAAAAAAAAAAAAAD//8CoAAEaACIA"
				writeToFile(t, networkPolicyStore.fs, networkPoliciesDir, "uid1", base64EncodedPolicy)
				writeToFile(t, appliedToGroupStore.fs, appliedToGroupsDir, "appliedToGroup1", base64EncodedAppliedToGroup)
				writeToFile(t, addressGroupStore.fs, addressGroupsDir, "addressGroup1", base64EncodedAddressGroup)
			},
			expectedRule: &CompletedRule{
				rule: &rule{
					Direction:       v1beta2.DirectionIn,
					From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
					MaxPriority:     -1,
					AppliedToGroups: []string{"appliedToGroup1"},
					PolicyUID:       "uid1",
					PolicyName:      "uid1",
					SourceRef: &v1beta2.NetworkPolicyReference{
						Type:      v1beta2.K8sNetworkPolicy,
						Namespace: testNamespace,
						Name:      "policy1",
						UID:       "uid1",
					},
				},
				FromAddresses: v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						Pod: &v1beta2.PodReference{Name: "pod2", Namespace: "namespace"},
						IPs: []v1beta2.IPAddress{v1beta2.IPAddress(net.ParseIP("192.168.0.1"))},
					},
				),
				TargetMembers: v1beta2.NewGroupMemberSet(
					&v1beta2.GroupMember{
						Pod: &v1beta2.PodReference{Name: "pod1", Namespace: "namespace"},
					},
				),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, clientset, reconciler := newTestController()
			addressGroupWatcher := watch.NewFake()
			appliedToGroupWatcher := watch.NewFake()
			networkPolicyWatcher := watch.NewFake()
			clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, fmt.Errorf("network unavailable")))
			clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, fmt.Errorf("network unavailable")))
			clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, fmt.Errorf("network unavailable")))

			tt.initFileStore(controller.networkPolicyStore, controller.appliedToGroupStore, controller.addressGroupStore)

			stopCh := make(chan struct{})
			defer close(stopCh)
			go controller.Run(stopCh)

			select {
			case ruleID := <-reconciler.updated:
				actualRule, _ := reconciler.getLastRealized(ruleID)
				// Rule ID is a hash value, we don't care about its exact value.
				actualRule.ID = ""
				assert.Equal(t, tt.expectedRule, actualRule)
			case <-time.After(time.Second):
				t.Fatal("Expected one rule update, got timeout")
			}
		})
	}
}

func TestOverrideFileStore(t *testing.T) {
	prepareMockTables()
	controller, clientset, reconciler := newTestController()
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	clientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	clientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	clientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	policy1 := newNetworkPolicy("policy1", "uid1", []string{"addressGroup1"}, nil, []string{"appliedToGroup1"}, nil)
	policy2 := newNetworkPolicy("policy2", "uid2", []string{"addressGroup2"}, nil, []string{"appliedToGroup2"}, nil)
	atgMember1 := newAppliedToGroupMemberPod("pod1", "namespace")
	atgMember2 := newAppliedToGroupMemberPod("pod2", "namespace")
	agMember1 := newAddressGroupPodMember("pod3", "namespace", "192.168.0.1")
	agMember2 := newAddressGroupPodMember("pod4", "namespace", "192.168.0.2")
	atg1 := newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*atgMember1})
	atg2 := newAppliedToGroup("appliedToGroup2", []v1beta2.GroupMember{*atgMember2})
	ag1 := newAddressGroup("addressGroup1", []v1beta2.GroupMember{*agMember1})
	ag2 := newAddressGroup("addressGroup2", []v1beta2.GroupMember{*agMember2})
	controller.networkPolicyStore.save(policy1)
	controller.appliedToGroupStore.save(atg1)
	controller.addressGroupStore.save(ag1)

	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.Run(stopCh)

	networkPolicyWatcher.Add(policy2)
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	addressGroupWatcher.Add(ag2)
	addressGroupWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Add(atg2)
	appliedToGroupWatcher.Action(watch.Bookmark, nil)

	select {
	case ruleID := <-reconciler.updated:
		actualRule, _ := reconciler.getLastRealized(ruleID)
		assert.Equal(t, v1beta2.NewGroupMemberSet(atgMember2), actualRule.TargetMembers)
		assert.Equal(t, v1beta2.NewGroupMemberSet(agMember2), actualRule.FromAddresses)
		assert.Equal(t, policy2.SourceRef, actualRule.SourceRef)
	case <-time.After(time.Second):
		t.Fatal("Expected one rule update, got timeout")
	}

	objects, err := controller.appliedToGroupStore.loadAll()
	require.NoError(t, err)
	assert.Equal(t, []runtime.Object{atg2}, objects)
	objects, err = controller.addressGroupStore.loadAll()
	require.NoError(t, err)
	assert.Equal(t, []runtime.Object{ag2}, objects)
	objects, err = controller.networkPolicyStore.loadAll()
	require.NoError(t, err)
	assert.Equal(t, []runtime.Object{policy2}, objects)
}

func TestNetworkPolicyMetrics(t *testing.T) {
	prepareMockTables()
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
		# HELP antrea_agent_egress_networkpolicy_rule_count [STABLE] Number of egress NetworkPolicy rules on local Node which are managed by the Antrea Agent.
		# TYPE antrea_agent_egress_networkpolicy_rule_count gauge
		`

		expectedIngressNetworkPolicyRuleCount := `
		# HELP antrea_agent_ingress_networkpolicy_rule_count [STABLE] Number of ingress NetworkPolicy rules on local Node which are managed by the Antrea Agent.
		# TYPE antrea_agent_ingress_networkpolicy_rule_count gauge
		`

		expectedNetworkPolicyCount := `
		# HELP antrea_agent_networkpolicy_count [STABLE] Number of NetworkPolicies on local Node which are managed by the Antrea Agent.
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
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")}))
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	networkPolicyWatcher.Add(policy1)
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	waitForReconcilerUpdated()
	checkNetworkPolicyMetrics()

	// Test adding policy2 with multiple rules
	policy2 := newNetworkPolicyWithMultipleRules("policy2", "uid2", []string{"addressGroup2"}, []string{"addressGroup2"}, []string{"appliedToGroup2"}, services)
	addressGroupWatcher.Add(newAddressGroup("addressGroup2", []v1beta2.GroupMember{*newAddressGroupMember("3.3.3.3"), *newAddressGroupMember("4.4.4.4")}))
	addressGroupWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup2", []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod2", "ns2")}))
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

func TestValidate(t *testing.T) {
	controller, _, _ := newTestController()
	igmpType := int32(0x12)
	actionAllow, actionDrop := v1beta1.RuleActionAllow, v1beta1.RuleActionDrop
	appliedToGroup := v1beta2.NewGroupMemberSet()
	appliedToGroup.Insert()
	tierPriority01 := int32(100)
	policyPriority01 := float64(10)
	proto := v1beta2.ProtocolIGMP
	rule1 := &rule{
		ID:   "rule1",
		Name: "rule01",
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type: v1beta2.AntreaClusterNetworkPolicy,
		},
		Services: []v1beta2.Service{
			{
				Protocol:     &proto,
				IGMPType:     &igmpType,
				GroupAddress: "225.1.2.3",
			},
		},
		Action:          &actionAllow,
		AppliedToGroups: []string{"appliedToGroup01"},
		Priority:        0,
		TierPriority:    &tierPriority01,
		PolicyPriority:  &policyPriority01,
		Direction:       v1beta2.DirectionOut,
	}
	rule2 := &rule{
		ID:   "rule2",
		Name: "rule02",
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type: v1beta2.AntreaClusterNetworkPolicy,
		},
		Services: []v1beta2.Service{
			{
				Protocol:     &proto,
				IGMPType:     &igmpType,
				GroupAddress: "",
			},
		},
		Action:          &actionDrop,
		AppliedToGroups: []string{"appliedToGroup01"},
		Priority:        1,
		TierPriority:    &tierPriority01,
		PolicyPriority:  &policyPriority01,
		Direction:       v1beta2.DirectionOut,
	}
	groups := v1beta2.GroupMemberSet{}
	groupAddress1, groupAddress2 := "225.1.2.3", "225.1.2.4"

	groups["Pod:ns1/pod1"] = newAppliedToGroupMemberPod("pod1", "ns1")
	controller.ruleCache.appliedToSetByGroup["appliedToGroup01"] = groups
	controller.ruleCache.rules.Add(rule1)
	controller.ruleCache.rules.Add(rule2)
	item, err := controller.GetIGMPNPRuleInfo("pod1", "ns1", net.ParseIP(groupAddress1), 0x12)
	if err != nil {
		t.Fatalf("failed to validate group %s %v", groupAddress1, err)
	}
	if item.RuleAction != v1beta1.RuleActionAllow {
		t.Fatalf("groupAddress %s expect %v, but got %v", groupAddress1, v1beta1.RuleActionAllow, item.RuleAction)
	}
	item, err = controller.GetIGMPNPRuleInfo("pod1", "ns1", net.ParseIP(groupAddress2), 0x12)
	if err != nil {
		t.Fatalf("failed to validate group %s %+v", groupAddress2, err)
	}
	if item.RuleAction != v1beta1.RuleActionDrop {
		t.Fatalf("groupAddress %s expect %v, but got %v", groupAddress2, v1beta1.RuleActionDrop, item.RuleAction)
	}
}
