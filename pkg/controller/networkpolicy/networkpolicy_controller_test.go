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
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/workqueue"

	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestToGroupSelector(t *testing.T) {
	pSelector := metav1.LabelSelector{}
	nSelector := metav1.LabelSelector{}
	tables := []struct {
		namespace        string
		podSelector      *metav1.LabelSelector
		nsSelector       *metav1.LabelSelector
		expGroupSelector *antreatypes.GroupSelector
	}{
		{
			"nsName",
			&pSelector,
			nil,
			&antreatypes.GroupSelector{
				Namespace:         "nsName",
				NamespaceSelector: nil,
				PodSelector:       &pSelector,
				NormalizedName:    generateNormalizedName("nsName", &pSelector, nil),
			},
		},
		{
			"nsName",
			nil,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: &nSelector,
				PodSelector:       nil,
				NormalizedName:    generateNormalizedName("", nil, &nSelector),
			},
		},
		{
			"",
			nil,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: &nSelector,
				PodSelector:       nil,
				NormalizedName:    generateNormalizedName("", nil, &nSelector),
			},
		},
		{
			"nsName",
			&pSelector,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: &nSelector,
				PodSelector:       &pSelector,
				NormalizedName:    generateNormalizedName("", &pSelector, &nSelector),
			},
		},
	}
	for _, table := range tables {
		group := toGroupSelector(table.namespace, table.podSelector, table.nsSelector)
		if group.Namespace != table.expGroupSelector.Namespace {
			t.Errorf("Group Namespace incorrectly set. Expected %s, got: %s", table.expGroupSelector.Namespace, group.Namespace)
		}
		if group.NormalizedName != table.expGroupSelector.NormalizedName {
			t.Errorf("Group normalized Name incorrectly set. Expected %s, got: %s", table.expGroupSelector.NormalizedName, group.NormalizedName)
		}
		if group.NamespaceSelector != table.expGroupSelector.NamespaceSelector {
			t.Errorf("Group NamespaceSelector incorrectly set. Expected %v, got: %v", table.expGroupSelector.NamespaceSelector, group.NamespaceSelector)
		}
		if group.PodSelector != table.expGroupSelector.PodSelector {
			t.Errorf("Group PodSelector incorrectly set. Expected %v, got: %v", table.expGroupSelector.PodSelector, group.PodSelector)
		}
	}
}

func TestNormalizeExpr(t *testing.T) {
	tables := []struct {
		key     string
		op      metav1.LabelSelectorOperator
		values  []string
		expName string
	}{
		{
			"role",
			metav1.LabelSelectorOpIn,
			[]string{"db", "app"},
			fmt.Sprintf("%s %s %s", "role", metav1.LabelSelectorOpIn, []string{"db", "app"}),
		},
		{
			"role",
			metav1.LabelSelectorOpExists,
			[]string{},
			fmt.Sprintf("%s %s", "role", metav1.LabelSelectorOpExists),
		},
	}
	for _, table := range tables {
		name := normalizeExpr(table.key, table.op, table.values)
		if name != table.expName {
			t.Errorf("Name not normalized correctly. Expected %s, got %s", table.expName, name)
		}
	}
}

func TestGenerateNormalizedName(t *testing.T) {
	pLabels := map[string]string{"user": "dev"}
	req1 := metav1.LabelSelectorRequirement{
		Key:      "role",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"db", "app"},
	}
	pExprs := []metav1.LabelSelectorRequirement{req1}
	normalizedPodSelector := "role In [db app] And user In [dev]"
	nLabels := map[string]string{"scope": "test"}
	req2 := metav1.LabelSelectorRequirement{
		Key:      "env",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"staging", "prod"},
	}
	nExprs := []metav1.LabelSelectorRequirement{req2}
	pSelector := metav1.LabelSelector{
		MatchLabels:      pLabels,
		MatchExpressions: pExprs,
	}
	nSelector := metav1.LabelSelector{
		MatchLabels:      nLabels,
		MatchExpressions: nExprs,
	}
	normalizedNSSelector := "env NotIn [staging prod] And scope In [test]"
	tables := []struct {
		namespace string
		pSelector *metav1.LabelSelector
		nSelector *metav1.LabelSelector
		expName   string
	}{
		{
			"nsName",
			&pSelector,
			nil,
			fmt.Sprintf("namespace=nsName And podSelector=%s", normalizedPodSelector),
		},
		{
			"nsName",
			nil,
			nil,
			"namespace=nsName",
		},
		{
			"nsName",
			nil,
			&nSelector,
			fmt.Sprintf("namespaceSelector=%s", normalizedNSSelector),
		},
		{
			"nsName",
			&pSelector,
			&nSelector,
			fmt.Sprintf("namespaceSelector=%s And podSelector=%s", normalizedNSSelector, normalizedPodSelector),
		},
	}
	for _, table := range tables {
		name := generateNormalizedName(table.namespace, table.pSelector, table.nSelector)
		if table.expName != name {
			t.Errorf("Unexpected normalized name. Expected %s, got %s", table.expName, name)
		}
	}
}

func TestToAntreaProtocol(t *testing.T) {
	udpProto := v1.ProtocolUDP
	tcpProto := v1.ProtocolTCP
	sctpProto := v1.ProtocolSCTP
	tables := []struct {
		proto            *v1.Protocol
		expInternalProto networkpolicy.Protocol
	}{
		{nil, networkpolicy.ProtocolTCP},
		{&udpProto, networkpolicy.ProtocolUDP},
		{&tcpProto, networkpolicy.ProtocolTCP},
		{&sctpProto, networkpolicy.ProtocolSCTP},
	}
	for _, table := range tables {
		protocol := toAntreaProtocol(table.proto)
		if *protocol != table.expInternalProto {
			t.Errorf("Unexpected Antrea protocol. Expected %v, got %v", table.expInternalProto, *protocol)
		}
	}
}

func TestToAntreaServices(t *testing.T) {
	tcpProto := v1.ProtocolTCP
	portNum := int32(80)
	tables := []struct {
		ports     []networkingv1.NetworkPolicyPort
		expValues []networkpolicy.Service
	}{
		{
			getK8sNetworkPolicyPorts(tcpProto),
			[]networkpolicy.Service{
				{
					Protocol: toAntreaProtocol(&tcpProto),
					Port:     &portNum,
				},
			},
		},
	}
	for _, table := range tables {
		services := toAntreaServices(table.ports)
		service := services[0]
		expValue := table.expValues[0]
		if *service.Protocol != *expValue.Protocol {
			t.Errorf("Unexpected Antrea Protocol in Antrea Service. Expected %v, got %v", *expValue.Protocol, *service.Protocol)
		}
		if *service.Port != *expValue.Port {
			t.Errorf("Unexpected Antrea Port in Antrea Service. Expected %v, got %v", *expValue.Port, *service.Port)
		}
	}
}

func getK8sNetworkPolicyPorts(proto v1.Protocol) []networkingv1.NetworkPolicyPort {
	portNum := intstr.FromInt(80)
	port := networkingv1.NetworkPolicyPort{
		Protocol: &proto,
		Port:     &portNum,
	}
	ports := []networkingv1.NetworkPolicyPort{port}
	return ports
}

func TestProcessNetworkPolicy(t *testing.T) {
	protocolTCP := networkpolicy.ProtocolTCP
	intstr80, intstr81 := intstr.FromInt(80), intstr.FromInt(81)
	int80, int81 := int32(80), int32(81)
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	tests := []struct {
		name                    string
		inputPolicy             *networkingv1.NetworkPolicy
		expectedPolicy          *antreatypes.NetworkPolicy
		expectedAppliedToGroups int
		expectedAddressGroups   int
	}{
		{
			name: "default-allow-ingress",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networkpolicy.NetworkPolicyRule{{
					Direction: networkpolicy.DirectionIn,
					From:      matchAllPeer,
					Services:  nil,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "default-deny-egress",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:             "uidA",
				Name:            "npA",
				Namespace:       "nsA",
				Rules:           []networkpolicy.NetworkPolicyRule{denyAllEgressRule},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
		{
			name: "rules-with-same-selectors",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: selectorA,
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
						},
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port: &intstr81,
								},
							},
							To: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networkpolicy.NetworkPolicyRule{
					{
						Direction: networkpolicy.DirectionIn,
						From: networkpolicy.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networkpolicy.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
					},
					{
						Direction: networkpolicy.DirectionOut,
						To: networkpolicy.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networkpolicy.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: selectorA,
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port: &intstr80,
								},
							},
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
						},
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Port: &intstr81,
								},
							},
							From: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorC,
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networkpolicy.NetworkPolicyRule{
					{
						Direction: networkpolicy.DirectionIn,
						From: networkpolicy.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
						Services: []networkpolicy.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
					},
					{
						Direction: networkpolicy.DirectionIn,
						From: networkpolicy.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", nil, &selectorC).NormalizedName)},
						},
						Services: []networkpolicy.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addressGroupStore := store.NewAddressGroupStore()
			appliedToGroupStore := store.NewAppliedToGroupStore()
			networkPolicyStore := store.NewNetworkPolicyStore()
			c := &NetworkPolicyController{
				addressGroupQueue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
				appliedToGroupQueue:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
				addressGroupStore:          addressGroupStore,
				appliedToGroupStore:        appliedToGroupStore,
				internalNetworkPolicyStore: networkPolicyStore,
			}

			if actualPolicy := c.processNetworkPolicy(tt.inputPolicy); !reflect.DeepEqual(actualPolicy, tt.expectedPolicy) {
				t.Errorf("processNetworkPolicy() got %v, want %v", actualPolicy, tt.expectedPolicy)
			}

			if actualAddressGroups := len(addressGroupStore.List()); actualAddressGroups != tt.expectedAddressGroups {
				t.Errorf("len(addressGroupStore.List()) got %v, want %v", actualAddressGroups, tt.expectedAddressGroups)
			}

			if actualAppliedToGroups := len(appliedToGroupStore.List()); actualAppliedToGroups != tt.expectedAppliedToGroups {
				t.Errorf("len(appliedToGroupStore.List()) got %v, want %v", actualAppliedToGroups, tt.expectedAppliedToGroups)
			}
		})
	}
}
