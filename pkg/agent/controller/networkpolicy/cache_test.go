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

	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
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
				From: v1beta1.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
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

func newAppliedToGroupMember(name, namespace string) *v1beta1.GroupMemberPod {
	return &v1beta1.GroupMemberPod{Pod: &v1beta1.PodReference{Name: name, Namespace: namespace}}
}

func newAddressGroupMember(ip string) *v1beta1.GroupMemberPod {
	return &v1beta1.GroupMemberPod{IP: v1beta1.IPAddress(net.ParseIP(ip))}
}

func TestRuleCacheAddAddressGroup(t *testing.T) {
	rule1 := &rule{
		ID:   "rule1",
		From: v1beta1.NetworkPolicyPeer{AddressGroups: []string{"group1"}},
	}
	rule2 := &rule{
		ID:   "rule2",
		From: v1beta1.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
	}
	tests := []struct {
		name               string
		rules              []*rule
		args               *v1beta1.AddressGroup
		expectedAddresses  v1beta1.GroupMemberPodSet
		expectedDirtyRules sets.String
	}{
		{
			"zero-rule",
			[]*rule{rule1, rule2},
			&v1beta1.AddressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group0"},
				Pods:       []v1beta1.GroupMemberPod{},
			},
			v1beta1.GroupMemberPodSet{},
			sets.NewString(),
		},
		{
			"one-rule",
			[]*rule{rule1, rule2},
			&v1beta1.AddressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group2"},
				Pods:       []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1")},
			},
			v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1")),
			sets.NewString("rule2"),
		},
		{
			"two-rules",
			[]*rule{rule1, rule2},
			&v1beta1.AddressGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group1"},
				Pods:       []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")},
			},
			v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("2.2.2.2")),
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
			if !actualAddresses.Equal(tt.expectedAddresses) {
				t.Errorf("Got addresses %v, expected %v", actualAddresses, tt.expectedAddresses)
			}
		})
	}
}

func newFakeRuleCache() (*ruleCache, *dirtyRuleRecorder, chan v1beta1.PodReference) {
	recorder := newDirtyRuleRecorder()
	ch := make(chan v1beta1.PodReference, 100)
	c := newRuleCache(recorder.Record, ch)
	return c, recorder, ch
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
		args               *v1beta1.AppliedToGroup
		expectedPods       v1beta1.GroupMemberPodSet
		expectedDirtyRules sets.String
	}{
		{
			"zero-rule",
			[]*rule{rule1, rule2},
			&v1beta1.AppliedToGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group0"},
				Pods:       []v1beta1.GroupMemberPod{},
			},
			v1beta1.NewGroupMemberPodSet(),
			sets.NewString(),
		},
		{
			"one-rule",
			[]*rule{rule1, rule2},
			&v1beta1.AppliedToGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group2"},
				Pods:       []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")},
			},
			v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1")),
			sets.NewString("rule2"),
		},
		{
			"two-rules",
			[]*rule{rule1, rule2},
			&v1beta1.AppliedToGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group1"},
				Pods:       []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1"), *newAppliedToGroupMember("pod2", "ns1")},
			},
			v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns1")),
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
			actualPods, exists := c.podSetByGroup[tt.args.Name]
			if !exists {
				t.Fatalf("AppliedToGroup %s not found", tt.args.Name)
			}
			if !actualPods.Equal(tt.expectedPods) {
				t.Errorf("Got addresses %v, expected %v", actualPods, tt.expectedPods)
			}
		})
	}
}

func TestRuleCacheAddNetworkPolicy(t *testing.T) {
	networkPolicyRule1 := &v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		To:        v1beta1.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicyRule2 := &v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup2"}},
		To:        v1beta1.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicy1 := &v1beta1.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           nil,
		AppliedToGroups: []string{"appliedToGroup1"},
	}
	networkPolicy2 := &v1beta1.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy2"},
		Rules:           []v1beta1.NetworkPolicyRule{*networkPolicyRule1, *networkPolicyRule2},
		AppliedToGroups: []string{"appliedToGroup1"},
	}
	rule1 := toRule(networkPolicyRule1, networkPolicy2)
	rule2 := toRule(networkPolicyRule2, networkPolicy2)
	tests := []struct {
		name               string
		args               *v1beta1.NetworkPolicy
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
		args               *v1beta1.NetworkPolicy
		expectedRules      []*rule
		expectedDirtyRules sets.String
	}{
		{
			"delete-zero-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy0"},
			},
			[]*rule{rule1, rule2, rule3},
			sets.NewString(),
		},
		{
			"delete-one-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy1"},
			},
			[]*rule{rule2, rule3},
			sets.NewString("rule1"),
		},
		{
			"delete-two-rule",
			[]*rule{rule1, rule2, rule3},
			&v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{UID: "policy2"},
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
	addressGroup1 := v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"), newAddressGroupMember("1.1.1.2"))
	addressGroup2 := v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.3"), newAddressGroupMember("1.1.1.2"))
	appliedToGroup1 := v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"), newAppliedToGroupMember("pod2", "ns1"))
	appliedToGroup2 := v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod3", "ns1"), newAppliedToGroupMember("pod2", "ns1"))
	rule1 := &rule{
		ID:              "rule1",
		Direction:       v1beta1.DirectionIn,
		From:            v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		AppliedToGroups: []string{"appliedToGroup1"},
	}
	rule2 := &rule{
		ID:              "rule2",
		Direction:       v1beta1.DirectionOut,
		To:              v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1", "addressGroup2"}},
		AppliedToGroups: []string{"appliedToGroup1", "appliedToGroup2"},
	}
	rule3 := &rule{
		ID:              "rule3",
		Direction:       v1beta1.DirectionIn,
		From:            v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1", "addressGroup2", "addressGroup3"}},
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
				Pods:          appliedToGroup1,
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
				Pods:          appliedToGroup1.Union(appliedToGroup2),
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
			c.podSetByGroup["appliedToGroup1"] = appliedToGroup1
			c.podSetByGroup["appliedToGroup2"] = appliedToGroup2
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
		podSetByGroup      map[string]v1beta1.GroupMemberPodSet
		args               *v1beta1.AppliedToGroupPatch
		expectedPods       v1beta1.GroupMemberPodSet
		expectedDirtyRules sets.String
		expectedErr        bool
	}{
		{
			"non-existing-group",
			nil,
			nil,
			&v1beta1.AppliedToGroupPatch{
				ObjectMeta: metav1.ObjectMeta{Name: "group0"},
				AddedPods:  []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")},
			},
			nil,
			sets.NewString(),
			true,
		},
		{
			"add-and-remove-pods-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta1.GroupMemberPodSet{"group2": v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"))},
			&v1beta1.AppliedToGroupPatch{
				ObjectMeta:  metav1.ObjectMeta{Name: "group2"},
				AddedPods:   []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod2", "ns1")},
				RemovedPods: []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")},
			},
			v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod2", "ns1")),
			sets.NewString("rule2"),
			false,
		},
		{
			"add-and-remove-pods-affecting-two-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta1.GroupMemberPodSet{"group1": v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"))},
			&v1beta1.AppliedToGroupPatch{
				ObjectMeta:  metav1.ObjectMeta{Name: "group1"},
				AddedPods:   []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod2", "ns1")},
				RemovedPods: []v1beta1.GroupMemberPod{*newAppliedToGroupMember("pod1", "ns1")},
			},
			v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod2", "ns1")),
			sets.NewString("rule1", "rule2"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, _ := newFakeRuleCache()
			c.podSetByGroup = tt.podSetByGroup
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
			actualPods, _ := c.podSetByGroup[tt.args.Name]
			if !actualPods.Equal(tt.expectedPods) {
				t.Errorf("Got pods %v, expected %v", actualPods, tt.expectedPods)
			}
		})
	}
}

func TestRuleCachePatchAddressGroup(t *testing.T) {
	rule1 := &rule{
		ID:   "rule1",
		From: v1beta1.NetworkPolicyPeer{AddressGroups: []string{"group1"}},
	}
	rule2 := &rule{
		ID: "rule2",
		To: v1beta1.NetworkPolicyPeer{AddressGroups: []string{"group1", "group2"}},
	}
	tests := []struct {
		name               string
		rules              []*rule
		addressSetByGroup  map[string]v1beta1.GroupMemberPodSet
		args               *v1beta1.AddressGroupPatch
		expectedAddresses  v1beta1.GroupMemberPodSet
		expectedDirtyRules sets.String
		expectedErr        bool
	}{
		{
			"non-existing-group",
			nil,
			nil,
			&v1beta1.AddressGroupPatch{
				ObjectMeta: metav1.ObjectMeta{Name: "group0"},
				AddedPods:  []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1"), *newAddressGroupMember("2.2.2.2")},
			},
			nil,
			sets.NewString(),
			true,
		},
		{
			"add-and-remove-addresses-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta1.GroupMemberPodSet{"group2": v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"))},
			&v1beta1.AddressGroupPatch{
				ObjectMeta:  metav1.ObjectMeta{Name: "group2"},
				AddedPods:   []v1beta1.GroupMemberPod{*newAddressGroupMember("2.2.2.2")},
				RemovedPods: []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1")},
			},
			v1beta1.NewGroupMemberPodSet(newAddressGroupMember("2.2.2.2")),
			sets.NewString("rule2"),
			false,
		},
		{
			"add-and-remove-addresses-affecting-two-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta1.GroupMemberPodSet{"group1": v1beta1.NewGroupMemberPodSet(newAddressGroupMember("1.1.1.1"))},
			&v1beta1.AddressGroupPatch{
				ObjectMeta:  metav1.ObjectMeta{Name: "group1"},
				AddedPods:   []v1beta1.GroupMemberPod{*newAddressGroupMember("2.2.2.2")},
				RemovedPods: []v1beta1.GroupMemberPod{*newAddressGroupMember("1.1.1.1")},
			},
			v1beta1.NewGroupMemberPodSet(newAddressGroupMember("2.2.2.2")),
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
			if !actualAddresses.Equal(tt.expectedAddresses) {
				t.Errorf("Got addresses %v, expected %v", actualAddresses, tt.expectedAddresses)
			}
		})
	}
}

func TestRuleCacheUpdateNetworkPolicy(t *testing.T) {
	networkPolicyRule1 := &v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup1"}},
		To:        v1beta1.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicyRule2 := &v1beta1.NetworkPolicyRule{
		Direction: v1beta1.DirectionIn,
		From:      v1beta1.NetworkPolicyPeer{AddressGroups: []string{"addressGroup2"}},
		To:        v1beta1.NetworkPolicyPeer{},
		Services:  nil,
	}
	networkPolicy1 := &v1beta1.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta1.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup1"},
	}
	networkPolicy2 := &v1beta1.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta1.NetworkPolicyRule{*networkPolicyRule1},
		AppliedToGroups: []string{"addressGroup2"},
	}
	networkPolicy3 := &v1beta1.NetworkPolicy{
		ObjectMeta:      metav1.ObjectMeta{UID: "policy1"},
		Rules:           []v1beta1.NetworkPolicyRule{*networkPolicyRule1, *networkPolicyRule2},
		AppliedToGroups: []string{"addressGroup1"},
	}
	rule1 := toRule(networkPolicyRule1, networkPolicy1)
	rule2 := toRule(networkPolicyRule1, networkPolicy2)
	rule3 := toRule(networkPolicyRule2, networkPolicy3)
	tests := []struct {
		name               string
		rules              []*rule
		args               *v1beta1.NetworkPolicy
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
		podSetByGroup      map[string]v1beta1.GroupMemberPodSet
		podUpdate          v1beta1.PodReference
		expectedDirtyRules sets.String
	}{
		{
			"non-matching-group",
			nil,
			nil,
			v1beta1.PodReference{"foo", "bar"},
			sets.NewString(),
		},
		{
			"matching-one-group-affecting-one-rule",
			[]*rule{rule1, rule2},
			map[string]v1beta1.GroupMemberPodSet{"group2": v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1"))},
			v1beta1.PodReference{Name: "pod1", Namespace: "ns1"},
			sets.NewString("rule2"),
		},
		{
			"matching-two-groups-affecting-two-rules",
			[]*rule{rule1, rule2},
			map[string]v1beta1.GroupMemberPodSet{
				"group1": v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1")),
				"group2": v1beta1.NewGroupMemberPodSet(newAppliedToGroupMember("pod1", "ns1")),
			},
			v1beta1.PodReference{Name: "pod1", Namespace: "ns1"},
			sets.NewString("rule1", "rule2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, recorder, ch := newFakeRuleCache()
			c.podSetByGroup = tt.podSetByGroup
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
