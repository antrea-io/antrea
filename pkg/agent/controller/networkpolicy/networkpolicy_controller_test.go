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
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	coreinformers "k8s.io/client-go/informers/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/lazy"
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

type fakeController struct {
	*Controller
	mockCRDClientset *fake.Clientset
	mockK8sClientset *k8sfake.Clientset
	mockOFClient     *openflowtest.MockClient
	mockReconciler   *mockReconciler
}

func newTestController(t *testing.T, objs ...runtime.Object) *fakeController {
	ctrl := gomock.NewController(t)
	clientset := &fake.Clientset{}
	k8sClientset := k8sfake.NewSimpleClientset(objs...)
	localPodInformer := lazy.New[cache.SharedIndexInformer](func() cache.SharedIndexInformer {
		return coreinformers.NewPodInformer(k8sClientset, v1.NamespaceAll, 0*time.Second, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	})
	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	ch2 := make(chan string, 100)
	groupIDAllocator := openflow.NewGroupAllocator()
	groupCounters := []proxytypes.GroupCounter{proxytypes.NewGroupCounter(groupIDAllocator, ch2)}
	ofClient := openflowtest.NewMockClient(ctrl)
	ofClient.EXPECT().NewDNSPacketInConjunction(dnsInterceptRuleID)
	ofClient.EXPECT().RegisterPacketInHandler(uint8(openflow.PacketInCategoryDNS), gomock.Any())
	ofClient.EXPECT().RegisterPacketInHandler(uint8(openflow.PacketInCategoryNP), gomock.Any())
	ifaceStore := interfacestore.NewInterfaceStore()
	controller, _ := NewNetworkPolicyController(&antreaClientGetter{clientset}, localPodInformer, ofClient, ifaceStore, "node1", podUpdateChannel, nil, groupCounters, ch2, true, true, true, true, false, nil, testAsyncDeleteInterval, "8.8.8.8:53", config.K8sNode, true, false, config.HostGatewayOFPort, config.DefaultTunOFPort, &config.NodeConfig{})
	reconciler := newMockReconciler()
	controller.reconciler = reconciler
	controller.auditLogger = nil
	return &fakeController{
		Controller:       controller,
		mockCRDClientset: clientset,
		mockK8sClientset: k8sClientset,
		mockOFClient:     ofClient,
		mockReconciler:   reconciler,
	}
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
	reconcileErr   error
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
	return r.reconcileErr
}

func (r *mockReconciler) BatchReconcile(rules []*CompletedRule) error {
	r.Lock()
	defer r.Unlock()
	for _, rule := range rules {
		r.lastRealized[rule.ID] = rule
		r.updated <- rule.ID
	}
	return r.reconcileErr
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

type fakeStatusManager struct {
	realizedPods sets.Set[v1beta2.PodReference]
}

func newFakeStatusManager(pods ...v1beta2.PodReference) *fakeStatusManager {
	return &fakeStatusManager{realizedPods: sets.New[v1beta2.PodReference](pods...)}
}

func (m *fakeStatusManager) SetRuleRealization(ruleID string, policyID types.UID) {}

func (m *fakeStatusManager) DeleteRuleRealization(ruleID string) {}

func (m *fakeStatusManager) GetPodRealization(pod v1beta2.PodReference) bool {
	return m.realizedPods.Has(pod)
}

func (m *fakeStatusManager) Resync(policyID types.UID) {}

func (m *fakeStatusManager) Run(stopCh <-chan struct{}) {}

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
	dir := v1beta2.DirectionIn
	if len(from) == 0 && len(to) > 0 {
		dir = v1beta2.DirectionOut
	}
	networkPolicyRule1 := newPolicyRule(dir, from, to, services)
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

func prepareMockTables() {
	openflow.InitMockTables(mockOFTables)
}

func TestAddSingleGroupRule(t *testing.T) {
	prepareMockTables()
	controller := newTestController(t)
	reconciler := controller.mockReconciler
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	controller.mockCRDClientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

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
	go controller.podInformer.Run(stopCh)
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
	controller := newTestController(t)
	reconciler := controller.mockReconciler
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	pod1 := &corev1.Pod{ObjectMeta: v1.ObjectMeta{Namespace: "ns1", Name: "pod1"}}
	pod2 := &corev1.Pod{ObjectMeta: v1.ObjectMeta{Namespace: "ns2", Name: "pod2"}}
	controller.mockCRDClientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))
	controller.ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod1", "ns1", "c1"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod1", PodNamespace: "ns1", ContainerID: "c1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 10},
	})
	controller.ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName("pod2", "ns2", "c2"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod2", PodNamespace: "ns2", ContainerID: "c2"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 11},
	})
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
	go controller.podInformer.Run(stopCh)
	go controller.Run(stopCh)

	assertPodNetworkPolicyAdmissionFlows := func(pod string, ofPort uint32) func() {
		synced := make(chan struct{})
		controller.mockOFClient.EXPECT().InstallPodNetworkPolicyAdmissionFlows(pod, []uint32{ofPort}).Do(func(string, []uint32) {
			close(synced)
		})
		return func() {
			select {
			case <-synced:
			case <-time.After(time.Millisecond * 100):
				t.Fatalf("Expected Pod %s to be synced", pod)
			}
		}
	}

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
	// At the moment no NetworkPolicies are applied to Pod2, its admission flows should be installed.
	assertFn := assertPodNetworkPolicyAdmissionFlows("ns2/pod2", 11)
	controller.mockK8sClientset.CoreV1().Pods(pod2.Namespace).Create(context.TODO(), pod2, v1.CreateOptions{})
	assertFn()

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
	// At the moment NetworkPolicies are fully applied to Pod1, its admission flows should be installed.
	assertFn = assertPodNetworkPolicyAdmissionFlows("ns1/pod1", 10)
	controller.mockK8sClientset.CoreV1().Pods(pod1.Namespace).Create(context.TODO(), pod1, v1.CreateOptions{})
	assertFn()

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
	controller := newTestController(t)
	reconciler := controller.mockReconciler
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	controller.mockCRDClientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.podInformer.Run(stopCh)
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
	controller := newTestController(t)
	reconciler := controller.mockReconciler
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	controller.mockCRDClientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

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
	go controller.podInformer.Run(stopCh)
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
		case <-time.After(time.Millisecond * 500):
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
	prepareMockTables()
	// Initialize NetworkPolicy metrics (prometheus)
	metrics.InitializeNetworkPolicyMetrics()
	controller := newTestController(t)
	reconciler := controller.mockReconciler

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
	controller.mockCRDClientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	protocolTCP := v1beta2.ProtocolTCP
	port := intstr.FromInt(80)
	services := []v1beta2.Service{{Protocol: &protocolTCP, Port: &port}}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.podInformer.Run(stopCh)
	go controller.Run(stopCh)

	controller.mockOFClient.EXPECT().UninstallPodNetworkPolicyAdmissionFlows(gomock.Any()).AnyTimes()
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
	controller := newTestController(t)
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

func TestSyncPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{Namespace: "foo", Name: "bar"},
		Spec:       corev1.PodSpec{NodeName: "node1"},
	}
	podRef := v1beta2.PodReference{Namespace: pod.Namespace, Name: pod.Name}
	interfaceConfig := &interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName(pod.Name, pod.Namespace, "c1"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: pod.Name, PodNamespace: pod.Namespace, ContainerID: "c1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 10},
	}
	tests := []struct {
		name                    string
		existingSyncedPod       *v1beta2.PodReference
		existingInterfaceConfig *interfacestore.InterfaceConfig
		existingPod             *corev1.Pod
		realizedPods            []v1beta2.PodReference
		expectedCall            func(recorder *openflowtest.MockClientMockRecorder)
		expectedSynced          bool
	}{
		{
			name:         "pod not exists",
			expectedCall: func(recorder *openflowtest.MockClientMockRecorder) {},
		},
		{
			name:              "synced pod not exists",
			existingSyncedPod: &podRef,
			expectedCall: func(recorder *openflowtest.MockClientMockRecorder) {
				recorder.UninstallPodNetworkPolicyAdmissionFlows("foo/bar")
			},
		},
		{
			name:         "interface not exists",
			existingPod:  pod,
			expectedCall: func(recorder *openflowtest.MockClientMockRecorder) {},
		},
		{
			name:                    "pod not realized",
			existingPod:             pod,
			existingInterfaceConfig: interfaceConfig,
			expectedCall:            func(recorder *openflowtest.MockClientMockRecorder) {},
		},
		{
			name:                    "pod realized",
			existingPod:             pod,
			existingInterfaceConfig: interfaceConfig,
			realizedPods:            []v1beta2.PodReference{podRef},
			expectedCall: func(recorder *openflowtest.MockClientMockRecorder) {
				recorder.InstallPodNetworkPolicyAdmissionFlows("foo/bar", []uint32{10})
			},
			expectedSynced: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prepareMockTables()
			controller := newTestController(t)
			controller.statusManager = newFakeStatusManager(tt.realizedPods...)
			if tt.existingSyncedPod != nil {
				controller.syncedPod.Store(*tt.existingSyncedPod, nil)
			}
			if tt.existingPod != nil {
				controller.podInformer.GetIndexer().Add(tt.existingPod)
			}
			if tt.existingInterfaceConfig != nil {
				controller.ifaceStore.AddInterface(tt.existingInterfaceConfig)
			}

			tt.expectedCall(controller.mockOFClient.EXPECT())
			controller.syncPod(podRef)
			_, ok := controller.syncedPod.Load(podRef)
			assert.Equal(t, tt.expectedSynced, ok)
		})
	}
}

func TestSyncPodWithReconcileErr(t *testing.T) {
	prepareMockTables()
	pod := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{Namespace: "foo", Name: "bar"},
		Spec:       corev1.PodSpec{NodeName: "node1"},
	}
	podRef := v1beta2.PodReference{Namespace: pod.Namespace, Name: pod.Name}
	controller := newTestController(t, pod)
	controller.mockReconciler.reconcileErr = fmt.Errorf("can't realize rule")
	controller.ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName(pod.Name, pod.Namespace, "c1"),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: pod.Name, PodNamespace: pod.Namespace, ContainerID: "c1"},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: 10},
	})
	addressGroupWatcher := watch.NewFake()
	appliedToGroupWatcher := watch.NewFake()
	networkPolicyWatcher := watch.NewFake()
	controller.mockCRDClientset.AddWatchReactor("addressgroups", k8stesting.DefaultWatchReactor(addressGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("appliedtogroups", k8stesting.DefaultWatchReactor(appliedToGroupWatcher, nil))
	controller.mockCRDClientset.AddWatchReactor("networkpolicies", k8stesting.DefaultWatchReactor(networkPolicyWatcher, nil))

	stopCh := make(chan struct{})
	defer close(stopCh)
	go controller.podInformer.Run(stopCh)
	go controller.Run(stopCh)

	// A NetworkPolicy is applied to the Pod, but it can't be reconciled successfully, the Pod shouldn't be unblocked.
	policy := newNetworkPolicy("policy1", "uid1", []string{}, []string{}, []string{"appliedToGroup1"}, nil)
	networkPolicyWatcher.Add(policy)
	appliedToGroupWatcher.Add(newAppliedToGroup("appliedToGroup1", []v1beta2.GroupMember{*newAppliedToGroupMemberPod(pod.Name, pod.Namespace)}))
	networkPolicyWatcher.Action(watch.Bookmark, nil)
	appliedToGroupWatcher.Action(watch.Bookmark, nil)
	addressGroupWatcher.Action(watch.Bookmark, nil)
	select {
	case <-controller.mockReconciler.updated:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Expected reconciler to be called")
	}
	_, ok := controller.syncedPod.Load(podRef)
	assert.False(t, ok)

	// After deleting the NetworkPolicy, the Pod should be unblocked.
	synced := make(chan struct{})
	controller.mockOFClient.EXPECT().InstallPodNetworkPolicyAdmissionFlows("foo/bar", []uint32{10}).Do(func(string, []uint32) {
		close(synced)
	})
	networkPolicyWatcher.Delete(policy)
	select {
	case <-synced:
	case <-time.After(time.Millisecond * 200):
		t.Fatalf("Expected Pod %s to be synced", klog.KObj(pod))
	}
	_, ok = controller.syncedPod.Load(podRef)
	assert.True(t, ok)
}
