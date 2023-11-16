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
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	k8sNPMaxPriority = int32(-1)
)

func TestAddressGroupIndexFunc(t *testing.T) {
	tests := []struct {
		name    string
		args    interface{}
		want    []string
		wantErr error
	}{
		{
			"zero-group",
			&rule{
				ID: "foo",
			},
			[]string{},
			nil,
		},
		{
			"two-groups",
			&rule{
				ID:   "foo",
				From: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
			},
			[]string{"group1", "group2"},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := addressGroupIndexFunc(tt.args)
			if err != tt.wantErr {
				t.Errorf("addressGroupIndexFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("addressGroupIndexFunc() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppliedToGroupIndexFunc(t *testing.T) {
	tests := []struct {
		name    string
		args    interface{}
		want    []string
		wantErr error
	}{
		{
			"zero-group",
			&rule{
				ID: "foo",
			},
			nil,
			nil,
		},
		{
			"two-groups",
			&rule{
				ID:              "foo",
				AppliedToGroups: []string{"group1", "group2"},
			},
			[]string{"group1", "group2"},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appliedToGroupIndexFunc(tt.args)
			if err != tt.wantErr {
				t.Errorf("appliedToGroupIndexFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("appliedToGroupIndexFunc() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetMaxPriority(t *testing.T) {
	networkPolicyRule1 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicyRule2 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup2"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
		Priority:  0,
	}
	networkPolicyRule3 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup3"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
		Priority:  1,
	}
	networkPolicyRule4 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionOut,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup4"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
		Priority:  0,
	}
	k8sNP := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	acnpPriority, acnpTier := 1.0, int32(250)
	antreaNP := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy2"},
		Priority:        &acnpPriority,
		TierPriority:    &acnpTier,
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule2, *networkPolicyRule3, *networkPolicyRule4},
		AppliedToGroups: []string{"addressGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type: v1beta2.AntreaClusterNetworkPolicy,
			Name: "acnp1",
			UID:  "policy-acnp",
		},
	}
	assert.Equal(t, int32(-1), getMaxPriority(k8sNP), "got unexpected maxPriority for K8s NetworkPolicy")
	assert.Equal(t, int32(1), getMaxPriority(antreaNP), "got unexpected maxPriority for AntreaPolicy")
}

type dirtyRuleRecorder struct {
	rules   sets.Set[string]
	eventCh chan string
}

func newDirtyRuleRecorder() *dirtyRuleRecorder {
	return &dirtyRuleRecorder{sets.New[string](), make(chan string, 100)}
}

func (r *dirtyRuleRecorder) Record(ruleID string) {
	r.rules.Insert(ruleID)
	r.eventCh <- ruleID
}

func newAppliedToGroupMemberPod(name, namespace string, containerPorts ...v1beta2.NamedPort) *v1beta2.GroupMember {
	return &v1beta2.GroupMember{Pod: &v1beta2.PodReference{Name: name, Namespace: namespace}, Ports: containerPorts}
}

func newAppliedToGroupMemberService(name, namespace string) *v1beta2.GroupMember {
	return &v1beta2.GroupMember{Service: &v1beta2.ServiceReference{Name: name, Namespace: namespace}}
}

func newAddressGroupMember(ips ...string) *v1beta2.GroupMember {
	ipAddrs := make([]v1beta2.IPAddress, len(ips))
	for idx, ip := range ips {
		ipAddrs[idx] = v1beta2.IPAddress(net.ParseIP(ip))
	}
	return &v1beta2.GroupMember{IPs: ipAddrs}
}

func newAddressGroupPodMember(name, namespace string, ips ...string) *v1beta2.GroupMember {
	ipAddrs := make([]v1beta2.IPAddress, len(ips))
	for idx, ip := range ips {
		ipAddrs[idx] = v1beta2.IPAddress(net.ParseIP(ip))
	}
	pod := &v1beta2.PodReference{
		Name:      name,
		Namespace: namespace,
	}
	return &v1beta2.GroupMember{Pod: pod, IPs: ipAddrs}
}

func TestRuleCacheAddAddressGroup(t *testing.T) {
	rule1 := &rule{
		ID:   "rule1",
		From: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1"}},
	}
	rule2 := &rule{
		ID:   "rule2",
		From: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
	}
	tests := []struct {
		name               string
		rules              []*rule
		args               *v1beta2.AddressGroup
		expectedAddresses  []*v1beta2.GroupMember
		expectedDirtyRules sets.Set[string]
	}{
		{
			"zero-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AddressGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group0"},
				GroupMembers: []v1beta2.GroupMember{},
			},
			nil,
			sets.New[string](),
		},
		{
			"one-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AddressGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
				GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1")},
			},
			[]*v1beta2.GroupMember{newAddressGroupMember("1.1.1.1")},
			sets.New[string]("rule2"),
		},
		{
			"two-rules",
			[]*rule{rule1, rule2},
			&v1beta2.AddressGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
				GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")},
			},
			[]*v1beta2.GroupMember{newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")},
			sets.New[string]("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.AddAddressGroup(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualAddresses, exists := c.addressSetByGroup[tt.args.Name]
			if !exists {
				t.Fatalf("AddressGroup %s not found", tt.args.Name)
			}
			assert.ElementsMatch(t, tt.expectedAddresses, actualAddresses.Items(), "stored addresses not equal")
		})
	}
}

func newFakeRuleCache() (*ruleCache, *dirtyRuleRecorder, *channel.SubscribableChannel, chan string) {
	recorder := newDirtyRuleRecorder()
	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	serviceGroupIDUpdateChannel := make(chan string, 100)
	c := newRuleCache(recorder.Record, podUpdateChannel, nil, serviceGroupIDUpdateChannel, config.K8sNode)
	return c, recorder, podUpdateChannel, serviceGroupIDUpdateChannel
}

func TestRuleCacheReplaceAppliedToGroups(t *testing.T) {
	rule1 := &rule{
		ID:              "rule1",
		AppliedToGroups: []string{"group1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		AppliedToGroups: []string{"group1", "group2"},
	}
	tests := []struct {
		name               string
		rules              []*rule
		preExistingGroups  map[string]v1beta2.GroupMemberSet
		args               []*v1beta2.AppliedToGroup
		expectedGroups     map[string]v1beta2.GroupMemberSet
		expectedDirtyRules sets.Set[string]
	}{
		{
			"stale-group-can-be-cleaned",
			[]*rule{},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			[]*v1beta2.AppliedToGroup{},
			map[string]v1beta2.GroupMemberSet{},
			sets.New[string](),
		},
		{
			"existing-group-can-be-updated",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			[]*v1beta2.AppliedToGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
					GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1"), *newAppliedToGroupMemberPod("pod2", "ns1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"), newAppliedToGroupMemberPod("pod2", "ns1"))},
			sets.New[string]("rule1", "rule2"),
		},
		{
			"unchanged-group-can-be-skipped",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			[]*v1beta2.AppliedToGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
					GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			sets.New[string](),
		},
		{
			"new-group-can-be-added",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{},
			[]*v1beta2.AppliedToGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
					GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1"), *newAppliedToGroupMemberPod("pod2", "ns1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"), newAppliedToGroupMemberPod("pod2", "ns1"))},
			sets.New[string]("rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.appliedToSetByGroup = tt.preExistingGroups
			c.ReplaceAppliedToGroups(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			if !reflect.DeepEqual(c.appliedToSetByGroup, tt.expectedGroups) {
				t.Errorf("Got appliedToSetByGroup %#v, expected %#v", c.appliedToSetByGroup, tt.expectedGroups)
			}
		})
	}
}

func TestRuleCacheReplaceAddressGroups(t *testing.T) {
	rule1 := &rule{
		ID:   "rule1",
		From: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1"}},
	}
	rule2 := &rule{
		ID:   "rule2",
		From: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
	}
	tests := []struct {
		name               string
		rules              []*rule
		preExistingGroups  map[string]v1beta2.GroupMemberSet
		args               []*v1beta2.AddressGroup
		expectedGroups     map[string]v1beta2.GroupMemberSet
		expectedDirtyRules sets.Set[string]
	}{
		{
			"stale-group-can-be-cleaned",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			[]*v1beta2.AddressGroup{},
			map[string]v1beta2.GroupMemberSet{},
			sets.New[string](),
		},
		{
			"existing-group-can-be-updated",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			[]*v1beta2.AddressGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
					GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.2"), *newAddressGroupMember("1.1.1.3")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.2"), newAddressGroupMember("1.1.1.3"))},
			sets.New[string]("rule1", "rule2"),
		},
		{
			"unchanged-group-can-be-skipped",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			[]*v1beta2.AddressGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
					GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			sets.New[string](),
		},
		{
			"new-group-can-be-added",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{},
			[]*v1beta2.AddressGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
					GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.2")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.2"))},
			sets.New[string]("rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.addressSetByGroup = tt.preExistingGroups
			c.ReplaceAddressGroups(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			if !reflect.DeepEqual(c.addressSetByGroup, tt.expectedGroups) {
				t.Errorf("Got addressSetByGroup %#v, expected %#v", c.addressSetByGroup, tt.expectedGroups)
			}
		})
	}
}

func TestRuleCacheReplaceNetworkPolicies(t *testing.T) {
	networkPolicyRule1 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicy1 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	networkPolicy2 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup2"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	rule1 := toRule(networkPolicyRule1, networkPolicy1, k8sNPMaxPriority)
	rule2 := toRule(networkPolicyRule1, networkPolicy2, k8sNPMaxPriority)
	tests := []struct {
		name               string
		rules              []*rule
		args               []*v1beta2.NetworkPolicy
		expectedRules      []*rule
		expectedDirtyRules sets.Set[string]
	}{
		{
			"stale-policy-can-be-cleaned",
			[]*rule{rule1},
			[]*v1beta2.NetworkPolicy{},
			[]*rule{},
			sets.New[string](rule1.ID),
		},
		{
			"existing-policy-can-be-updated",
			[]*rule{rule1},
			[]*v1beta2.NetworkPolicy{networkPolicy2},
			[]*rule{rule2},
			sets.New[string](rule1.ID, rule2.ID),
		},
		{
			"unchanged-policy-can-be-skipped",
			[]*rule{rule1},
			[]*v1beta2.NetworkPolicy{networkPolicy1},
			[]*rule{rule1},
			sets.New[string](),
		},
		{
			"new-policy-can-be-added",
			[]*rule{},
			[]*v1beta2.NetworkPolicy{networkPolicy1},
			[]*rule{rule1},
			sets.New[string](rule1.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
				c.policyMap[string(rule.PolicyUID)] = &v1beta2.NetworkPolicy{}
			}
			c.ReplaceNetworkPolicies(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			assert.ElementsMatch(t, tt.expectedRules, c.rules.List(), "rules not match")
		})
	}
}

func TestRuleCacheAddAppliedToGroup(t *testing.T) {
	rule1 := &rule{
		ID:              "rule1",
		AppliedToGroups: []string{"group1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		AppliedToGroups: []string{"group1", "group2"},
	}
	tests := []struct {
		name               string
		rules              []*rule
		args               *v1beta2.AppliedToGroup
		expectedPods       []*v1beta2.GroupMember
		expectedDirtyRules sets.Set[string]
	}{
		{
			"zero-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AppliedToGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group0"},
				GroupMembers: []v1beta2.GroupMember{},
			},
			nil,
			sets.New[string](),
		},
		{
			"one-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AppliedToGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
				GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMemberPod("pod1", "ns1")},
			sets.New[string]("rule2"),
		},
		{
			"two-rules",
			[]*rule{rule1, rule2},
			&v1beta2.AppliedToGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
				GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1"), *newAppliedToGroupMemberPod("pod2", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMemberPod("pod1", "ns1"), newAppliedToGroupMemberPod("pod2", "ns1")},
			sets.New[string]("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.AddAppliedToGroup(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualPods, exists := c.appliedToSetByGroup[tt.args.Name]
			if !exists {
				t.Fatalf("AppliedToGroup %s not found", tt.args.Name)
			}
			assert.ElementsMatch(t, tt.expectedPods, actualPods.Items(), "stored Pods not equal")
		})
	}
}

func TestRuleCacheAddNetworkPolicy(t *testing.T) {
	networkPolicyRule1 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicyRule2 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup2"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicyRule3 := &v1beta2.NetworkPolicyRule{
		Direction:       v1beta2.DirectionIn,
		AppliedToGroups: []string{"appliedToGroup1"},
		From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup3"}},
		To:              v1beta2.NetworkPolicyPeer{},
		Services:        nil,
		Priority:        0,
	}
	networkPolicyRule4 := &v1beta2.NetworkPolicyRule{
		Direction:       v1beta2.DirectionIn,
		AppliedToGroups: []string{"appliedToGroup1"},
		From:            v1beta2.NetworkPolicyPeer{LabelIdentities: []uint32{1}},
		To:              v1beta2.NetworkPolicyPeer{},
		Services:        nil,
		Priority:        0,
	}
	networkPolicy1 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1", Namespace: "ns1", Name: "name1"},
		Rules:           nil,
		AppliedToGroups: []string{"appliedToGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	networkPolicy2 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy2", Namespace: "ns2", Name: "name2"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1, *networkPolicyRule2},
		AppliedToGroups: []string{"appliedToGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns2",
			Name:      "name2",
			UID:       "policy2",
		},
	}
	networkPolicy3 := &v1beta2.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{UID: "policy3", Namespace: "ns3", Name: "name3"},
		Rules:      []v1beta2.NetworkPolicyRule{*networkPolicyRule3},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.AntreaNetworkPolicy,
			Namespace: "ns3",
			Name:      "name3",
			UID:       "policy3",
		},
	}
	networkPolicy4 := &v1beta2.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{UID: "policy4", Namespace: "ns4", Name: "name4"},
		Rules:      []v1beta2.NetworkPolicyRule{*networkPolicyRule4},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.AntreaNetworkPolicy,
			Namespace: "ns4",
			Name:      "name4",
			UID:       "policy4",
		},
	}
	rule1 := toRule(networkPolicyRule1, networkPolicy2, k8sNPMaxPriority)
	rule2 := toRule(networkPolicyRule2, networkPolicy2, k8sNPMaxPriority)
	rule3 := toRule(networkPolicyRule3, networkPolicy3, 0)
	rule4 := toRule(networkPolicyRule4, networkPolicy4, 0)
	tests := []struct {
		name               string
		args               *v1beta2.NetworkPolicy
		expectedRules      []*rule
		expectedDirtyRules sets.Set[string]
	}{
		{
			"zero-rule",
			networkPolicy1,
			[]*rule{},
			sets.New[string](),
		},
		{
			"two-rule",
			networkPolicy2,
			[]*rule{rule1, rule2},
			sets.New[string](rule1.ID, rule2.ID),
		},
		{
			"rule-with-appliedTo",
			networkPolicy3,
			[]*rule{rule3},
			sets.New[string](rule3.ID),
		},
		{
			"rule-with-label-identity",
			networkPolicy4,
			[]*rule{rule4},
			sets.New[string](rule4.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			c.AddNetworkPolicy(tt.args)
			actualRules := c.rules.List()
			if !assert.ElementsMatch(t, tt.expectedRules, actualRules) {
				t.Errorf("Got rules %v, expected %v", actualRules, tt.expectedRules)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
		})
	}
}

func TestRuleCacheDeleteNetworkPolicy(t *testing.T) {
	rule1 := &rule{
		ID:        "rule1",
		PolicyUID: "policy1",
	}
	rule2 := &rule{
		ID:        "rule2",
		PolicyUID: "policy2",
	}
	rule3 := &rule{
		ID:        "rule3",
		PolicyUID: "policy2",
	}
	tests := []struct {
		name               string
		rules              []*rule
		args               *v1beta2.NetworkPolicy
		expectedRules      []*rule
		expectedDirtyRules sets.Set[string]
	}{
		{
			"delete-zero-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy0", Namespace: "ns0", Name: "name0"},
			},
			[]*rule{rule1, rule2, rule3},
			sets.New[string](),
		},
		{
			"delete-one-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy1", Namespace: "ns1", Name: "name1"},
			},
			[]*rule{rule2, rule3},
			sets.New[string]("rule1"),
		},
		{
			"delete-two-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy2", Namespace: "ns2", Name: "name2"},
			},
			[]*rule{rule1},
			sets.New[string]("rule2", "rule3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.DeleteNetworkPolicy(tt.args)

			actualRules := c.rules.List()
			if !assert.ElementsMatch(t, tt.expectedRules, actualRules) {
				t.Errorf("Got rules %v, expected %v", actualRules, tt.expectedRules)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
		})
	}
}

func TestRuleCacheGetCompletedRule(t *testing.T) {
	addressGroup1 := v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("1.1.1.2"))
	addressGroup2 := v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.3"), newAddressGroupMember("1.1.1.2"))
	appliedToGroup1 := v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"), newAppliedToGroupMemberPod("pod2", "ns1"))
	appliedToGroup2 := v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod3", "ns1"), newAppliedToGroupMemberPod("pod2", "ns1"))
	appliedToGroupSvc1 := v1beta2.NewGroupMemberSet(newAppliedToGroupMemberService("svc1", "ns1"))
	appliedToGroupSvc2 := v1beta2.NewGroupMemberSet(newAppliedToGroupMemberService("svc2", "ns1"))
	rule1 := &rule{
		ID:              "rule1",
		Direction:       v1beta2.DirectionIn,
		From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		AppliedToGroups: []string{"appliedToGroup1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		Direction:       v1beta2.DirectionOut,
		To:              v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1", "addressGroup2"}},
		AppliedToGroups: []string{"appliedToGroup1", "appliedToGroup2"},
	}
	rule3 := &rule{
		ID:              "rule3",
		Direction:       v1beta2.DirectionIn,
		From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1", "addressGroup2", "addressGroup3"}},
		AppliedToGroups: []string{"appliedToGroup1", "appliedToGroup2"},
	}
	rule4 := &rule{
		ID:              "rule4",
		Direction:       v1beta2.DirectionIn,
		From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1", "addressGroup2"}},
		AppliedToGroups: []string{"appliedToGroup1", "appliedToGroup2", "appliedToGroup3"},
	}
	rule5 := &rule{
		ID:              "rule5",
		Direction:       v1beta2.DirectionIn,
		From:            v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1", "addressGroup2"}},
		AppliedToGroups: []string{"appliedToGroup3", "appliedToGroup4"},
	}
	rule6 := &rule{
		ID:        "rule6",
		Direction: v1beta2.DirectionIn,
		From: v1beta2.NetworkPolicyPeer{
			IPBlocks: []v1beta2.IPBlock{
				{
					CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(newCIDR("1.1.1.0/24").IP), PrefixLength: 24},
				},
			},
		},
		AppliedToGroups: []string{"appliedToGroupSvc1"},
	}
	rule7 := &rule{
		ID:        "rule7",
		Direction: v1beta2.DirectionIn,
		From: v1beta2.NetworkPolicyPeer{
			IPBlocks: []v1beta2.IPBlock{
				{
					CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(newCIDR("1.1.1.0/24").IP), PrefixLength: 24},
				},
			},
		},
		AppliedToGroups: []string{"appliedToGroupSvc1", "appliedToGroupSvc2"},
	}
	tests := []struct {
		name              string
		args              string
		wantCompletedRule *CompletedRule
		wantEffective     bool
		wantRealizable    bool
	}{
		{
			"one-group-rule",
			rule1.ID,
			&CompletedRule{
				rule:          rule1,
				FromAddresses: addressGroup1,
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1,
			},
			true,
			true,
		},
		{
			"two-groups-rule",
			rule2.ID,
			&CompletedRule{
				rule:          rule2,
				FromAddresses: nil,
				ToAddresses:   addressGroup1.Union(addressGroup2),
				TargetMembers: appliedToGroup1.Union(appliedToGroup2),
			},
			true,
			true,
		},
		{
			"missing-one-addressgroup-rule",
			rule3.ID,
			nil,
			true,
			false,
		},
		{
			"missing-one-appliedtogroup-rule",
			rule4.ID,
			&CompletedRule{
				rule:          rule4,
				FromAddresses: addressGroup1.Union(addressGroup2),
				ToAddresses:   nil,
				TargetMembers: appliedToGroup1.Union(appliedToGroup2),
			},
			true,
			true,
		},
		{
			"missing-all-appliedtogroups-rule",
			rule5.ID,
			nil,
			false,
			false,
		},
		{
			"applied-to-svc-rule",
			rule6.ID,
			&CompletedRule{
				rule:          rule6,
				FromAddresses: v1beta2.NewGroupMemberSet(),
				ToAddresses:   nil,
				TargetMembers: appliedToGroupSvc1,
			},
			true,
			true,
		},
		{
			"applied-to-multi-svc-rule",
			rule7.ID,
			&CompletedRule{
				rule:          rule7,
				FromAddresses: v1beta2.NewGroupMemberSet(),
				ToAddresses:   nil,
				TargetMembers: appliedToGroupSvc1.Union(appliedToGroupSvc2),
			},
			true,
			true,
		},
		{
			"non-existing-rule",
			"rule8",
			nil,
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _, _ := newFakeRuleCache()
			c.addressSetByGroup["addressGroup1"] = addressGroup1
			c.addressSetByGroup["addressGroup2"] = addressGroup2
			c.appliedToSetByGroup["appliedToGroup1"] = appliedToGroup1
			c.appliedToSetByGroup["appliedToGroup2"] = appliedToGroup2
			c.appliedToSetByGroup["appliedToGroupSvc1"] = appliedToGroupSvc1
			c.appliedToSetByGroup["appliedToGroupSvc2"] = appliedToGroupSvc2
			c.rules.Add(rule1)
			c.rules.Add(rule2)
			c.rules.Add(rule3)
			c.rules.Add(rule4)
			c.rules.Add(rule5)
			c.rules.Add(rule6)
			c.rules.Add(rule7)

			gotCompletedRule, gotEffective, gotRealizable := c.GetCompletedRule(tt.args)
			if !reflect.DeepEqual(gotCompletedRule, tt.wantCompletedRule) {
				t.Errorf("GetCompletedRule() gotCompletedRule = %v, want %v", gotCompletedRule, tt.wantCompletedRule)
			}
			if gotEffective != tt.wantEffective {
				t.Errorf("GetCompletedRule() gotEffective = %v, want %v", gotEffective, tt.wantEffective)
			}
			if gotRealizable != tt.wantRealizable {
				t.Errorf("GetCompletedRule() gotRealizable = %v, want %v", gotRealizable, tt.wantRealizable)
			}
		})
	}
}

func TestRuleCachePatchAppliedToGroup(t *testing.T) {
	rule1 := &rule{
		ID:              "rule1",
		AppliedToGroups: []string{"group1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		AppliedToGroups: []string{"group1", "group2"},
	}
	tests := []struct {
		name               string
		rules              []*rule
		podSetByGroup      map[string]v1beta2.GroupMemberSet
		args               *v1beta2.AppliedToGroupPatch
		expectedPods       []*v1beta2.GroupMember
		expectedDirtyRules sets.Set[string]
		expectedErr        bool
	}{
		{
			"non-existing-group",
			nil,
			nil,
			&v1beta2.AppliedToGroupPatch{
				ObjectMeta:        metav1.ObjectMeta{Name: "group0"},
				AddedGroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")},
			},
			nil,
			sets.New[string](),
			true,
		},
		{
			"add-and-remove-pods-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			&v1beta2.AppliedToGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group2"},
				AddedGroupMembers:   []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod2", "ns1"), *newAppliedToGroupMemberPod("pod3", "ns3")},
				RemovedGroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMemberPod("pod2", "ns1"), newAppliedToGroupMemberPod("pod3", "ns3")},
			sets.New[string]("rule2"),
			false,
		},
		{
			"add-and-remove-pods-affecting-two-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			&v1beta2.AppliedToGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group1"},
				AddedGroupMembers:   []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod2", "ns1"), *newAppliedToGroupMemberPod("pod3", "ns3")},
				RemovedGroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMemberPod("pod1", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMemberPod("pod2", "ns1"), newAppliedToGroupMemberPod("pod3", "ns3")},
			sets.New[string]("rule1", "rule2"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			c.appliedToSetByGroup = tt.podSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			ret, err := c.PatchAppliedToGroup(tt.args)
			if (err == nil) == tt.expectedErr {
				t.Fatalf("Got error %v, expected %t", err, tt.expectedErr)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualPods, _ := c.appliedToSetByGroup[tt.args.Name]
			assert.ElementsMatch(t, tt.expectedPods, actualPods.Items(), "stored Pods not equal")
			if !tt.expectedErr {
				assert.Equal(t, len(ret.GroupMembers), len(actualPods))
			}
		})
	}
}

func TestRuleCachePatchAddressGroup(t *testing.T) {
	rule1 := &rule{
		ID:   "rule1",
		From: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1"}},
	}
	rule2 := &rule{
		ID: "rule2",
		To: v1beta2.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
	}
	tests := []struct {
		name               string
		rules              []*rule
		addressSetByGroup  map[string]v1beta2.GroupMemberSet
		args               *v1beta2.AddressGroupPatch
		expectedAddresses  []*v1beta2.GroupMember
		expectedDirtyRules sets.Set[string]
		expectedErr        bool
	}{
		{
			"non-existing-group",
			nil,
			nil,
			&v1beta2.AddressGroupPatch{
				ObjectMeta:        metav1.ObjectMeta{Name: "group0"},
				AddedGroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")},
			},
			nil,
			sets.New[string](),
			true,
		},
		{
			"add-and-remove-addresses-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			&v1beta2.AddressGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group2"},
				AddedGroupMembers:   []v1beta2.GroupMember{*newAddressGroupMember("2.2.2.2"), *newAddressGroupMember("3.3.3.3")},
				RemovedGroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1")},
			},
			[]*v1beta2.GroupMember{newAddressGroupMember("2.2.2.2"), newAddressGroupMember("3.3.3.3")},
			sets.New[string]("rule2"),
			false,
		},
		{
			"add-and-remove-addresses-affecting-two-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			&v1beta2.AddressGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group1"},
				AddedGroupMembers:   []v1beta2.GroupMember{*newAddressGroupMember("2.2.2.2"), *newAddressGroupMember("3.3.3.3")},
				RemovedGroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1")},
			},
			[]*v1beta2.GroupMember{newAddressGroupMember("2.2.2.2"), newAddressGroupMember("3.3.3.3")},
			sets.New[string]("rule1", "rule2"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			c.addressSetByGroup = tt.addressSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			ret, err := c.PatchAddressGroup(tt.args)
			if (err == nil) == tt.expectedErr {
				t.Fatalf("Got error %v, expected %t", err, tt.expectedErr)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualAddresses, _ := c.addressSetByGroup[tt.args.Name]
			assert.ElementsMatch(t, tt.expectedAddresses, actualAddresses.Items(), "stored addresses not equal")
			if !tt.expectedErr {
				assert.Equal(t, len(ret.GroupMembers), len(actualAddresses))
			}
		})
	}
}

func TestRuleCacheUpdateNetworkPolicy(t *testing.T) {
	networkPolicyRule1 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicyRule2 := &v1beta2.NetworkPolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      v1beta2.NetworkPolicyPeer{AddressGroups: []string{"addressGroup2"}},
		To:        v1beta2.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicy1 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	networkPolicy2 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup2"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	networkPolicy3 := &v1beta2.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta2.NetworkPolicyRule{*networkPolicyRule1, *networkPolicyRule2},
		AppliedToGroups: []string{"addressGroup1"},
		SourceRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.K8sNetworkPolicy,
			Namespace: "ns1",
			Name:      "name1",
			UID:       "policy1",
		},
	}
	rule1 := toRule(networkPolicyRule1, networkPolicy1, k8sNPMaxPriority)
	rule2 := toRule(networkPolicyRule1, networkPolicy2, k8sNPMaxPriority)
	rule3 := toRule(networkPolicyRule2, networkPolicy3, k8sNPMaxPriority)
	tests := []struct {
		name               string
		rules              []*rule
		args               *v1beta2.NetworkPolicy
		expectedRules      []*rule
		expectedDirtyRules sets.Set[string]
	}{
		{
			"updating-addressgroup",
			[]*rule{rule1},
			networkPolicy2,
			[]*rule{rule2},
			sets.New[string](rule1.ID, rule2.ID),
		},
		{
			"adding-rule",
			[]*rule{rule1},
			networkPolicy3,
			[]*rule{rule1, rule3},
			sets.New[string](rule3.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.UpdateNetworkPolicy(tt.args)

			actualRules := c.rules.List()
			if !assert.ElementsMatch(t, tt.expectedRules, actualRules) {
				t.Errorf("Got rules %v, expected %v", actualRules, tt.expectedRules)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
		})
	}
}

func TestRuleCacheProcessPodUpdates(t *testing.T) {
	rule1 := &rule{
		ID:              "rule1",
		AppliedToGroups: []string{"group1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		AppliedToGroups: []string{"group1", "group2"},
	}
	tests := []struct {
		name               string
		rules              []*rule
		podSetByGroup      map[string]v1beta2.GroupMemberSet
		podUpdate          string
		expectedDirtyRules sets.Set[string]
	}{
		{
			"non-matching-group",
			nil,
			nil,
			"bar/foo",
			sets.New[string](),
		},
		{
			"matching-one-group-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1"))},
			"ns1/pod1",
			sets.New[string]("rule2"),
		},
		{
			"matching-two-groups-affecting-two-rules",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{
				"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")),
				"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberPod("pod1", "ns1")),
			},
			"ns1/pod1",
			sets.New[string]("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, podUpdateNotifier, _ := newFakeRuleCache()
			c.appliedToSetByGroup = tt.podSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			go podUpdateNotifier.Run(stopCh)
			ns, name := k8s.SplitNamespacedName(tt.podUpdate)
			e := types.PodUpdate{
				PodNamespace: ns,
				PodName:      name,
			}
			podUpdateNotifier.Notify(e)
			func() {
				// Drain the channel with 10 ms timeout so we can know it's done.
				for {
					select {
					case <-recorder.eventCh:
					case <-time.After(time.Millisecond * 10):
						return
					}
				}
			}()

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
		})
	}
}

func TestRuleCacheProcessServiceGroupIDUpdates(t *testing.T) {
	rule1 := &rule{
		ID:              "rule1",
		AppliedToGroups: []string{"group1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		AppliedToGroups: []string{"group1", "group2"},
	}
	rule3 := &rule{
		ID: "rule3",
		To: v1beta2.NetworkPolicyPeer{
			ToServices: []v1beta2.ServiceReference{
				{
					Name:      "svc1",
					Namespace: "ns1",
				},
			},
		},
	}
	rule4 := &rule{
		ID: "rule4",
		To: v1beta2.NetworkPolicyPeer{
			ToServices: []v1beta2.ServiceReference{
				{
					Name:      "svc1",
					Namespace: "ns1",
				},
				{
					Name:      "svc2",
					Namespace: "ns2",
				},
			},
		},
	}
	tests := []struct {
		name               string
		rules              []*rule
		svcSetByGroup      map[string]v1beta2.GroupMemberSet
		svcUpdate          string
		expectedDirtyRules sets.Set[string]
	}{
		{
			"non-matching",
			[]*rule{rule1, rule2, rule3, rule4},
			nil,
			"bar/foo",
			sets.New[string](),
		},
		{
			"matching-one-group-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberService("svc1", "ns1"))},
			"ns1/svc1",
			sets.New[string]("rule2"),
		},
		{
			"matching-two-groups-affecting-two-rules",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{
				"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberService("svc1", "ns1")),
				"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMemberService("svc1", "ns1")),
			},
			"ns1/svc1",
			sets.New[string]("rule1", "rule2"),
		},
		{
			"matching-one-to-service-affecting-one-rule",
			[]*rule{rule3, rule4},
			nil,
			"ns2/svc2",
			sets.New[string]("rule4"),
		},
		{
			"matching-two-to-service-affecting-two-rules",
			[]*rule{rule3, rule4},
			nil,
			"ns1/svc1",
			sets.New[string]("rule3", "rule4"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _, svcUpdateChan := newFakeRuleCache()
			c.appliedToSetByGroup = tt.svcSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			svcUpdateChan <- tt.svcUpdate
			func() {
				// Drain the channel with 10 ms timeout so we can know it's done.
				for {
					select {
					case <-recorder.eventCh:
					case <-time.After(time.Millisecond * 10):
						return
					}
				}
			}()
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
		})
	}
}

func BenchmarkRuleCacheUnionAddressGroups(b *testing.B) {
	var addressGroupMembers1, addressGroupMembers2 []*v1beta2.GroupMember
	// addressGroup1 includes 10K members.
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			addressGroupMembers1 = append(addressGroupMembers1, newAddressGroupMember(fmt.Sprintf("1.1.%d.%d", i, j)))
		}
	}
	addressGroup1 := v1beta2.NewGroupMemberSet(addressGroupMembers1...)
	// addressGroup2 includes 10 members.
	for i := 0; i < 10; i++ {
		addressGroupMembers2 = append(addressGroupMembers2, newAddressGroupMember(fmt.Sprintf("2.2.2.%d", i)))
	}
	addressGroup2 := v1beta2.NewGroupMemberSet(addressGroupMembers2...)
	c, _, _, _ := newFakeRuleCache()
	c.addressSetByGroup["addressGroup1"] = addressGroup1
	c.addressSetByGroup["addressGroup2"] = addressGroup2

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.unionAddressGroups([]string{"addressGroup1", "addressGroup2"})
	}
}
