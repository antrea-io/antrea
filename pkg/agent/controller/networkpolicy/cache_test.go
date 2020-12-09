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
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
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
	rules   sets.String
	eventCh chan string
}

func newDirtyRuleRecorder() *dirtyRuleRecorder {
	return &dirtyRuleRecorder{sets.NewString(), make(chan string, 100)}
}

func (r *dirtyRuleRecorder) Record(ruleID string) {
	r.rules.Insert(ruleID)
	r.eventCh <- ruleID
}

func newAppliedToGroupMember(name, namespace string, containerPorts ...v1beta2.NamedPort) *v1beta2.GroupMember {
	return &v1beta2.GroupMember{Pod: &v1beta2.PodReference{Name: name, Namespace: namespace}, Ports: containerPorts}
}

func newAddressGroupMember(ips ...string) *v1beta2.GroupMember {
	ipAddrs := make([]v1beta2.IPAddress, len(ips))
	for idx, ip := range ips {
		ipAddrs[idx] = v1beta2.IPAddress(net.ParseIP(ip))
	}
	return &v1beta2.GroupMember{IPs: ipAddrs}
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
		expectedDirtyRules sets.String
	}{
		{
			"zero-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AddressGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group0"},
				GroupMembers: []v1beta2.GroupMember{},
			},
			nil,
			sets.NewString(),
		},
		{
			"one-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AddressGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
				GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1")},
			},
			[]*v1beta2.GroupMember{newAddressGroupMember("1.1.1.1")},
			sets.NewString("rule2"),
		},
		{
			"two-rules",
			[]*rule{rule1, rule2},
			&v1beta2.AddressGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
				GroupMembers: []v1beta2.GroupMember{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")},
			},
			[]*v1beta2.GroupMember{newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")},
			sets.NewString("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
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

func newFakeRuleCache() (*ruleCache, *dirtyRuleRecorder, chan v1beta2.PodReference) {
	recorder := newDirtyRuleRecorder()
	ch := make(chan v1beta2.PodReference, 100)
	c := newRuleCache(recorder.Record, ch)
	return c, recorder, ch
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
		expectedDirtyRules sets.String
	}{
		{
			"stale-group-can-be-cleaned",
			[]*rule{},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			[]*v1beta2.AppliedToGroup{},
			map[string]v1beta2.GroupMemberSet{},
			sets.NewString(),
		},
		{
			"existing-group-can-be-updated",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			[]*v1beta2.AppliedToGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
					GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1"), *newAppliedToGroupMember("pod2", "ns1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns1"))},
			sets.NewString("rule1", "rule2"),
		},
		{
			"unchanged-group-can-be-skipped",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			[]*v1beta2.AppliedToGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
					GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			sets.NewString(),
		},
		{
			"new-group-can-be-added",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{},
			[]*v1beta2.AppliedToGroup{
				{
					ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
					GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1"), *newAppliedToGroupMember("pod2", "ns1")},
				},
			},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns1"))},
			sets.NewString("rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.memberSetByGroup = tt.preExistingGroups
			c.ReplaceAppliedToGroups(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			if !reflect.DeepEqual(c.memberSetByGroup, tt.expectedGroups) {
				t.Errorf("Got memberSetByGroup %#v, expected %#v", c.memberSetByGroup, tt.expectedGroups)
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
		expectedDirtyRules sets.String
	}{
		{
			"stale-group-can-be-cleaned",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAddressGroupMember("1.1.1.1"))},
			[]*v1beta2.AddressGroup{},
			map[string]v1beta2.GroupMemberSet{},
			sets.NewString(),
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
			sets.NewString("rule1", "rule2"),
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
			sets.NewString(),
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
			sets.NewString("rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
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
		expectedDirtyRules sets.String
	}{
		{
			"stale-policy-can-be-cleaned",
			[]*rule{rule1},
			[]*v1beta2.NetworkPolicy{},
			[]*rule{},
			sets.NewString(rule1.ID),
		},
		{
			"existing-policy-can-be-updated",
			[]*rule{rule1},
			[]*v1beta2.NetworkPolicy{networkPolicy2},
			[]*rule{rule2},
			sets.NewString(rule1.ID, rule2.ID),
		},
		{
			"unchanged-policy-can-be-skipped",
			[]*rule{rule1},
			[]*v1beta2.NetworkPolicy{networkPolicy1},
			[]*rule{rule1},
			sets.NewString(),
		},
		{
			"new-policy-can-be-added",
			[]*rule{},
			[]*v1beta2.NetworkPolicy{networkPolicy1},
			[]*rule{rule1},
			sets.NewString(rule1.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
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
		expectedDirtyRules sets.String
	}{
		{
			"zero-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AppliedToGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group0"},
				GroupMembers: []v1beta2.GroupMember{},
			},
			nil,
			sets.NewString(),
		},
		{
			"one-rule",
			[]*rule{rule1, rule2},
			&v1beta2.AppliedToGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group2"},
				GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMember("pod1", "ns1")},
			sets.NewString("rule2"),
		},
		{
			"two-rules",
			[]*rule{rule1, rule2},
			&v1beta2.AppliedToGroup{
				ObjectMeta:   metav1.ObjectMeta{Name: "group1"},
				GroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1"), *newAppliedToGroupMember("pod2", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns1")},
			sets.NewString("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			c.AddAppliedToGroup(tt.args)

			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualPods, exists := c.memberSetByGroup[tt.args.Name]
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
	rule1 := toRule(networkPolicyRule1, networkPolicy2, k8sNPMaxPriority)
	rule2 := toRule(networkPolicyRule2, networkPolicy2, k8sNPMaxPriority)
	rule3 := toRule(networkPolicyRule3, networkPolicy3, 0)
	tests := []struct {
		name               string
		args               *v1beta2.NetworkPolicy
		expectedRules      []*rule
		expectedDirtyRules sets.String
	}{
		{
			"zero-rule",
			networkPolicy1,
			[]*rule{},
			sets.NewString(),
		},
		{
			"two-rule",
			networkPolicy2,
			[]*rule{rule1, rule2},
			sets.NewString(rule1.ID, rule2.ID),
		},
		{
			"rule-with-appliedTo",
			networkPolicy3,
			[]*rule{rule3},
			sets.NewString(rule3.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
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
		expectedDirtyRules sets.String
	}{
		{
			"delete-zero-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy0", Namespace: "ns0", Name: "name0"},
			},
			[]*rule{rule1, rule2, rule3},
			sets.NewString(),
		},
		{
			"delete-one-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy1", Namespace: "ns1", Name: "name1"},
			},
			[]*rule{rule2, rule3},
			sets.NewString("rule1"),
		},
		{
			"delete-two-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta2.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy2", Namespace: "ns2", Name: "name2"},
			},
			[]*rule{rule1},
			sets.NewString("rule2", "rule3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
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
	appliedToGroup1 := v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns1"))
	appliedToGroup2 := v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod3", "ns1"), newAppliedToGroupMember("pod2", "ns1"))
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
	tests := []struct {
		name              string
		args              string
		wantCompletedRule *CompletedRule
		wantExists        bool
		wantCompleted     bool
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
			"incompleted-rule",
			rule3.ID,
			nil,
			true,
			false,
		},
		{
			"non-existing-rule",
			"rule4",
			nil,
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := newFakeRuleCache()
			c.addressSetByGroup["addressGroup1"] = addressGroup1
			c.addressSetByGroup["addressGroup2"] = addressGroup2
			c.memberSetByGroup["appliedToGroup1"] = appliedToGroup1
			c.memberSetByGroup["appliedToGroup2"] = appliedToGroup2
			c.rules.Add(rule1)
			c.rules.Add(rule2)
			c.rules.Add(rule3)

			gotCompletedRule, gotExists, gotCompleted := c.GetCompletedRule(tt.args)
			if !reflect.DeepEqual(gotCompletedRule, tt.wantCompletedRule) {
				t.Errorf("GetCompletedRule() gotCompletedRule = %v, want %v", gotCompletedRule, tt.wantCompletedRule)
			}
			if gotExists != tt.wantExists {
				t.Errorf("GetCompletedRule() gotExists = %v, want %v", gotExists, tt.wantExists)
			}
			if gotCompleted != tt.wantCompleted {
				t.Errorf("GetCompletedRule() gotCompleted = %v, want %v", gotCompleted, tt.wantCompleted)
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
		expectedDirtyRules sets.String
		expectedErr        bool
	}{
		{
			"non-existing-group",
			nil,
			nil,
			&v1beta2.AppliedToGroupPatch{
				ObjectMeta:        metav1.ObjectMeta{Name: "group0"},
				AddedGroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")},
			},
			nil,
			sets.NewString(),
			true,
		},
		{
			"add-and-remove-pods-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			&v1beta2.AppliedToGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group2"},
				AddedGroupMembers:   []v1beta2.GroupMember{*newAppliedToGroupMember("pod2", "ns1"), *newAppliedToGroupMember("pod3", "ns3")},
				RemovedGroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMember("pod2", "ns1"), newAppliedToGroupMember("pod3", "ns3")},
			sets.NewString("rule2"),
			false,
		},
		{
			"add-and-remove-pods-affecting-two-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			&v1beta2.AppliedToGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group1"},
				AddedGroupMembers:   []v1beta2.GroupMember{*newAppliedToGroupMember("pod2", "ns1"), *newAppliedToGroupMember("pod3", "ns3")},
				RemovedGroupMembers: []v1beta2.GroupMember{*newAppliedToGroupMember("pod1", "ns1")},
			},
			[]*v1beta2.GroupMember{newAppliedToGroupMember("pod2", "ns1"), newAppliedToGroupMember("pod3", "ns3")},
			sets.NewString("rule1", "rule2"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
			c.memberSetByGroup = tt.podSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			err := c.PatchAppliedToGroup(tt.args)
			if (err == nil) == tt.expectedErr {
				t.Fatalf("Got error %v, expected %t", err, tt.expectedErr)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualPods, _ := c.memberSetByGroup[tt.args.Name]
			assert.ElementsMatch(t, tt.expectedPods, actualPods.Items(), "stored Pods not equal")
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
		expectedDirtyRules sets.String
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
			sets.NewString(),
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
			sets.NewString("rule2"),
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
			sets.NewString("rule1", "rule2"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
			c.addressSetByGroup = tt.addressSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			err := c.PatchAddressGroup(tt.args)
			if (err == nil) == tt.expectedErr {
				t.Fatalf("Got error %v, expected %t", err, tt.expectedErr)
			}
			if !recorder.rules.Equal(tt.expectedDirtyRules) {
				t.Errorf("Got dirty rules %v, expected %v", recorder.rules, tt.expectedDirtyRules)
			}
			actualAddresses, _ := c.addressSetByGroup[tt.args.Name]
			assert.ElementsMatch(t, tt.expectedAddresses, actualAddresses.Items(), "stored addresses not equal")
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
		expectedDirtyRules sets.String
	}{
		{
			"updating-addressgroup",
			[]*rule{rule1},
			networkPolicy2,
			[]*rule{rule2},
			sets.NewString(rule1.ID, rule2.ID),
		},
		{
			"adding-rule",
			[]*rule{rule1},
			networkPolicy3,
			[]*rule{rule1, rule3},
			sets.NewString(rule3.ID),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
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
		podUpdate          v1beta2.PodReference
		expectedDirtyRules sets.String
	}{
		{
			"non-matching-group",
			nil,
			nil,
			v1beta2.PodReference{Name: "foo", Namespace: "bar"},
			sets.NewString(),
		},
		{
			"matching-one-group-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1"))},
			v1beta2.PodReference{Name: "pod1", Namespace: "ns1"},
			sets.NewString("rule2"),
		},
		{
			"matching-two-groups-affecting-two-rules",
			[]*rule{rule1, rule2},
			map[string]v1beta2.GroupMemberSet{
				"group1": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1")),
				"group2": v1beta2.NewGroupMemberSet(newAppliedToGroupMember("pod1", "ns1")),
			},
			v1beta2.PodReference{Name: "pod1", Namespace: "ns1"},
			sets.NewString("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, ch := newFakeRuleCache()
			c.memberSetByGroup = tt.podSetByGroup
			for _, rule := range tt.rules {
				c.rules.Add(rule)
			}
			ch <- tt.podUpdate

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
