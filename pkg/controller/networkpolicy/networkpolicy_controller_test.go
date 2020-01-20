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
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync time.Duration = 30 * time.Second

type networkPolicyController struct {
	*NetworkPolicyController
	podStore                   cache.Store
	namespaceStore             cache.Store
	networkPolicyStore         cache.Store
	appliedToGroupStore        storage.Interface
	addressGroupStore          storage.Interface
	internalNetworkPolicyStore storage.Interface
}

func newController() (*fake.Clientset, *networkPolicyController) {
	client := newClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	appliedToGroupStore := store.NewAppliedToGroupStore()
	addressGroupStore := store.NewAddressGroupStore()
	internalNetworkPolicyStore := store.NewNetworkPolicyStore()
	npController := NewNetworkPolicyController(client, informerFactory.Core().V1().Pods(), informerFactory.Core().V1().Namespaces(), informerFactory.Networking().V1().NetworkPolicies(), addressGroupStore, appliedToGroupStore, internalNetworkPolicyStore)
	npController.podListerSynced = alwaysReady
	npController.namespaceListerSynced = alwaysReady
	npController.networkPolicyListerSynced = alwaysReady
	return client, &networkPolicyController{
		npController,
		informerFactory.Core().V1().Pods().Informer().GetStore(),
		informerFactory.Core().V1().Namespaces().Informer().GetStore(),
		informerFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		appliedToGroupStore,
		addressGroupStore,
		internalNetworkPolicyStore,
	}
}

func newClientset() *fake.Clientset {
	client := fake.NewSimpleClientset()

	client.PrependReactor("create", "networkpolicies", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		np := action.(k8stesting.CreateAction).GetObject().(*networkingv1.NetworkPolicy)

		if np.ObjectMeta.GenerateName != "" {
			np.ObjectMeta.Name = fmt.Sprintf("%s-%s", np.ObjectMeta.GenerateName, rand.String(8))
			np.ObjectMeta.GenerateName = ""
		}

		return false, np, nil
	}))

	return client
}

func TestAddNetworkPolicy(t *testing.T) {
	protocolTCP := networking.ProtocolTCP
	intstr80, intstr81 := intstr.FromInt(80), intstr.FromInt(81)
	int80, int81 := intstr.FromInt(80), intstr.FromInt(81)
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	tests := []struct {
		name               string
		inputPolicy        *networkingv1.NetworkPolicy
		expPolicy          *antreatypes.NetworkPolicy
		expAppliedToGroups int
		expAddressGroups   int
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
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{{
					Direction: networking.DirectionIn,
					From:      matchAllPeer,
					Services:  nil,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "default-allow-egress",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npB", UID: "uidB"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidB",
				Name:      "npB",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{{
					Direction: networking.DirectionOut,
					To:        matchAllPeer,
					Services:  nil,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "default-deny-ingress",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npC", UID: "uidC"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidC",
				Name:      "npC",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					denyAllIngressRule,
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "default-deny-egress",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npD", UID: "uidD"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidD",
				Name:      "npD",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					denyAllEgressRule,
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "rules-with-same-selectors",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npE", UID: "uidE"},
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
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidE",
				Name:      "npE",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "rules-with-different-selectors",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npF", UID: "uidF"},
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
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidF",
				Name:      "npF",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
					},
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", nil, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addNetworkPolicy(tt.inputPolicy)
			key, _ := keyFunc(tt.inputPolicy)
			actualPolicyObj, _, _ := npc.internalNetworkPolicyStore.Get(key)
			actualPolicy := actualPolicyObj.(*antreatypes.NetworkPolicy)
			if !reflect.DeepEqual(actualPolicy, tt.expPolicy) {
				t.Errorf("addNetworkPolicy() got %v, want %v", actualPolicy, tt.expPolicy)
			}

			if actualAddressGroups := len(npc.addressGroupStore.List()); actualAddressGroups != tt.expAddressGroups {
				t.Errorf("len(addressGroupStore.List()) got %v, want %v", actualAddressGroups, tt.expAddressGroups)
			}

			if actualAppliedToGroups := len(npc.appliedToGroupStore.List()); actualAppliedToGroups != tt.expAppliedToGroups {
				t.Errorf("len(appliedToGroupStore.List()) got %v, want %v", actualAppliedToGroups, tt.expAppliedToGroups)
			}
		})
	}
	_, npc := newController()
	for _, tt := range tests {
		npc.addNetworkPolicy(tt.inputPolicy)
	}
	assert.Equal(t, npc.GetNetworkPolicyNum(), 6, "expected networkPolicy number is 6")
	assert.Equal(t, npc.GetAddressGroupNum(), 3, "expected addressGroup number is 3")
	assert.Equal(t, npc.GetAppliedToGroupNum(), 2, "appliedToGroup number is 2")
}

func TestDeleteNetworkPolicy(t *testing.T) {
	npObj := getK8sNetworkPolicyObj()
	ns := npObj.ObjectMeta.Namespace
	pSelector := npObj.Spec.PodSelector
	apgID := getNormalizedUID(generateNormalizedName(ns, &pSelector, nil))
	_, npc := newController()
	npc.addNetworkPolicy(npObj)
	npc.deleteNetworkPolicy(npObj)
	_, found, _ := npc.appliedToGroupStore.Get(apgID)
	assert.False(t, found, "expected AppliedToGroup to be deleted")
	adgs := npc.addressGroupStore.List()
	assert.Len(t, adgs, 0, "expected empty AddressGroup list")
	key, _ := keyFunc(npObj)
	_, found, _ = npc.internalNetworkPolicyStore.Get(key)
	assert.False(t, found, "expected internal NetworkPolicy to be deleted")
}

func TestUpdateNetworkPolicy(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	oldNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
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
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &selectorB,
						},
					},
				},
			},
		},
	}
	tests := []struct {
		name                 string
		updatedNetworkPolicy *networkingv1.NetworkPolicy
		expNetworkPolicy     *antreatypes.NetworkPolicy
		expAppliedToGroups   int
		expAddressGroups     int
	}{
		{
			name: "update-pod-selector",
			updatedNetworkPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: selectorA,
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
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
							To: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
						},
					},
				},
			},
			expNetworkPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
		{
			name: "remove-ingress-rule",
			updatedNetworkPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
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
			expNetworkPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "remove-egress-rule",
			updatedNetworkPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
						},
					},
				},
			},
			expNetworkPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
		},
		{
			name: "remove-all-rules",
			updatedNetworkPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
				},
			},
			expNetworkPolicy: &antreatypes.NetworkPolicy{
				UID:             "uidA",
				Name:            "npA",
				Namespace:       "nsA",
				Rules:           []networking.NetworkPolicyRule{},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "add-ingress-rule",
			updatedNetworkPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector:       &selectorB,
									NamespaceSelector: &selectorC,
								},
							},
						},
						{
							From: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &selectorA,
								},
							},
						},
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
						},
					},
				},
			},
			expNetworkPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
					},
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorA).NormalizedName)},
						},
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   3,
		},
		{
			name: "update-egress-rule-selector",
			updatedNetworkPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
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
							To: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &selectorA,
								},
							},
						},
					},
				},
			},
			expNetworkPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidA",
				Name:      "npA",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
						},
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addNetworkPolicy(oldNP)
			npc.updateNetworkPolicy(oldNP, tt.updatedNetworkPolicy)
			key, _ := keyFunc(oldNP)
			actualPolicyObj, _, _ := npc.internalNetworkPolicyStore.Get(key)
			actualPolicy := actualPolicyObj.(*antreatypes.NetworkPolicy)
			if actualAppliedToGroups := len(npc.appliedToGroupStore.List()); actualAppliedToGroups != tt.expAppliedToGroups {
				t.Errorf("updateNetworkPolicy() got %v, want %v", actualAppliedToGroups, tt.expAppliedToGroups)
			}
			if actualAddressGroups := len(npc.addressGroupStore.List()); actualAddressGroups != tt.expAddressGroups {
				t.Errorf("updateNetworkPolicy() got %v, want %v", actualAddressGroups, tt.expAddressGroups)
			}
			if !reflect.DeepEqual(actualPolicy, tt.expNetworkPolicy) {
				t.Errorf("updateNetworkPolicy() got %#v, want %#v", actualPolicy, tt.expNetworkPolicy)
			}
		})
	}
}

func TestAddPod(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"group": "appliedTo"},
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "role",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"db", "app"},
			},
		},
	}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	testNPObj := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "npA",
			Namespace: "nsA",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorSpec,
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &selectorIn,
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &selectorOut,
						},
					},
				},
			},
		},
	}
	tests := []struct {
		name                 string
		addedPod             *v1.Pod
		appGroupMatch        bool
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			name: "not-match-spec-podselector-match-labels",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
		{
			name: "not-match-spec-podselector-match-exprs",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"role": "db"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
		{
			name: "match-spec-podselector",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels: map[string]string{
						"role":  "db",
						"group": "appliedTo",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        true,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
		{
			name: "match-ingress-podselector",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"inGroup": "inAddress"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  true,
			outAddressGroupMatch: false,
		},
		{
			name: "match-egress-podselector",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"outGroup": "outAddress"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: true,
		},
		{
			name: "match-all-selectors",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels: map[string]string{
						"role":     "app",
						"group":    "appliedTo",
						"inGroup":  "inAddress",
						"outGroup": "outAddress",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        true,
			inAddressGroupMatch:  true,
			outAddressGroupMatch: true,
		},
		{
			name: "match-spec-podselector-no-podip",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
		{
			name: "match-rule-podselector-no-ip",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"inGroup": "inAddress"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
		{
			name: "no-match-spec-podselector",
			addedPod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "none"},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: v1.PodStatus{
					Conditions: []v1.PodCondition{
						{
							Type:   v1.PodReady,
							Status: v1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addNetworkPolicy(testNPObj)
			npc.podStore.Add(tt.addedPod)
			appGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorSpec, nil).NormalizedName)
			inGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorIn, nil).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorOut, nil).NormalizedName)
			npc.syncAppliedToGroup(appGroupID)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			appGroupObj, _, _ := npc.appliedToGroupStore.Get(appGroupID)
			appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
			podsAdded := appGroup.PodsByNode["nodeA"]
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			if tt.appGroupMatch {
				assert.Len(t, podsAdded, 1, "expected Pod to match AppliedToGroup")
			} else {
				assert.Len(t, podsAdded, 0, "expected Pod not to match AppliedToGroup")
			}
			memberPod := &networking.GroupMemberPod{IP: ipStrToIPAddress("1.2.3.4")}
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.Pods.Has(memberPod))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.Pods.Has(memberPod))
		})
	}
}

func TestDeletePod(t *testing.T) {
	ns := metav1.NamespaceDefault
	nodeName := "node1"
	matchNPName := "testNP"
	matchLabels := map[string]string{"group": "appliedTo"}
	ruleLabels := map[string]string{"group": "address"}
	matchSelector := metav1.LabelSelector{
		MatchLabels: matchLabels,
	}
	inPSelector := metav1.LabelSelector{
		MatchLabels: ruleLabels,
	}
	matchAppGID := getNormalizedUID(generateNormalizedName(ns, &matchSelector, nil))
	ingressRules := []networkingv1.NetworkPolicyIngressRule{
		{
			From: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &inPSelector,
				},
			},
		},
	}
	matchNPObj := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      matchNPName,
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: matchSelector,
			Ingress:     ingressRules,
		},
	}
	p1IP := "1.1.1.1"
	p2IP := "2.2.2.2"
	p1 := getPod("p1", ns, "", p1IP)
	// Ensure Pod p1 matches AppliedToGroup.
	p1.Labels = matchLabels
	p2 := getPod("p2", ns, "", p2IP)
	// Ensure Pod p2 matches AddressGroup.
	p2.Labels = ruleLabels
	_, npc := newController()
	npc.addNetworkPolicy(matchNPObj)
	npc.podStore.Add(p1)
	npc.podStore.Add(p2)
	npc.syncAppliedToGroup(matchAppGID)
	// Retrieve AddressGroup.
	adgs := npc.addressGroupStore.List()
	// Considering the NP, there should be only one AddressGroup for tests.
	addrGroupObj := adgs[0]
	addrGroup := addrGroupObj.(*antreatypes.AddressGroup)
	npc.syncAddressGroup(addrGroup.Name)
	// Delete Pod P1 matching the AppliedToGroup.
	npc.podStore.Delete(p1)
	npc.syncAppliedToGroup(matchAppGID)
	appGroupObj, _, _ := npc.appliedToGroupStore.Get(matchAppGID)
	appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
	podsAdded := appGroup.PodsByNode[nodeName]
	// Ensure Pod1 reference is removed from AppliedToGroup.
	assert.Len(t, podsAdded, 0, "expected Pod to be deleted from AppliedToGroup")
	// Delete Pod P2 matching the NetworkPolicy Rule.
	npc.podStore.Delete(p2)
	npc.syncAddressGroup(addrGroup.Name)
	updatedAddrGroupObj, _, _ := npc.addressGroupStore.Get(addrGroup.Name)
	updatedAddrGroup := updatedAddrGroupObj.(*antreatypes.AddressGroup)
	// Ensure Pod2 IP is removed from AddressGroup.
	memberPod2 := &networking.GroupMemberPod{IP: ipStrToIPAddress(p2IP)}
	assert.False(t, updatedAddrGroup.Pods.Has(memberPod2))
}

func TestAddNamespace(t *testing.T) {
	selectorSpec := metav1.LabelSelector{}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	testNPObj := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "npA",
			Namespace: "nsA",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorSpec,
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &selectorIn,
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &selectorOut,
						},
					},
				},
			},
		},
	}
	tests := []struct {
		name                 string
		addedNamespace       *v1.Namespace
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			name: "match-namespace-ingress-rule",
			addedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"inGroup": "inAddress"},
				},
			},
			inAddressGroupMatch:  true,
			outAddressGroupMatch: false,
		},
		{
			name: "match-namespace-egress-rule",
			addedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"outGroup": "outAddress"},
				},
			},
			inAddressGroupMatch:  false,
			outAddressGroupMatch: true,
		},
		{
			name: "match-namespace-all",
			addedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "nsA",
					Labels: map[string]string{
						"inGroup":  "inAddress",
						"outGroup": "outAddress",
					},
				},
			},
			inAddressGroupMatch:  true,
			outAddressGroupMatch: true,
		},
		{
			name: "match-namespace-none",
			addedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"group": "none"},
				},
			},
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addNetworkPolicy(testNPObj)
			npc.namespaceStore.Add(tt.addedNamespace)
			p1 := getPod("p1", "nsA", "nodeA", "1.2.3.4")
			p2 := getPod("p2", "nsA", "nodeA", "2.2.3.4")
			npc.podStore.Add(p1)
			npc.podStore.Add(p2)
			inGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorIn).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorOut).NormalizedName)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			memberPod1 := &networking.GroupMemberPod{IP: ipStrToIPAddress("1.2.3.4")}
			memberPod2 := &networking.GroupMemberPod{IP: ipStrToIPAddress("2.2.3.4")}
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.Pods.Has(memberPod1))
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.Pods.Has(memberPod2))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.Pods.Has(memberPod1))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.Pods.Has(memberPod2))
		})
	}
}

func TestDeleteNamespace(t *testing.T) {
	selectorSpec := metav1.LabelSelector{}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	testNPObj := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "npA",
			Namespace: "nsA",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorSpec,
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &selectorIn,
						},
					},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &selectorOut,
						},
					},
				},
			},
		},
	}
	tests := []struct {
		name                 string
		deletedNamespace     *v1.Namespace
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			name: "match-namespace-ingress-rule",
			deletedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"inGroup": "inAddress"},
				},
			},
			inAddressGroupMatch:  true,
			outAddressGroupMatch: false,
		},
		{
			name: "match-namespace-egress-rule",
			deletedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"outGroup": "outAddress"},
				},
			},
			inAddressGroupMatch:  false,
			outAddressGroupMatch: true,
		},
		{
			name: "match-namespace-all",
			deletedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "nsA",
					Labels: map[string]string{
						"inGroup":  "inAddress",
						"outGroup": "outAddress",
					},
				},
			},
			inAddressGroupMatch:  true,
			outAddressGroupMatch: true,
		},
		{
			name: "match-namespace-none",
			deletedNamespace: &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"group": "none"},
				},
			},
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addNetworkPolicy(testNPObj)
			p1 := getPod("p1", "nsA", "", "1.1.1.1")
			p2 := getPod("p2", "nsA", "", "1.1.1.2")
			npc.namespaceStore.Add(tt.deletedNamespace)
			npc.podStore.Add(p1)
			npc.podStore.Add(p2)
			npc.namespaceStore.Delete(tt.deletedNamespace)
			inGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorIn).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorOut).NormalizedName)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			npc.podStore.Delete(p1)
			npc.podStore.Delete(p2)
			npc.namespaceStore.Delete(tt.deletedNamespace)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			memberPod1 := &networking.GroupMemberPod{IP: ipStrToIPAddress("1.1.1.1")}
			memberPod2 := &networking.GroupMemberPod{IP: ipStrToIPAddress("1.1.1.2")}
			if tt.inAddressGroupMatch {
				assert.False(t, updatedInAddrGroup.Pods.Has(memberPod1))
				assert.False(t, updatedInAddrGroup.Pods.Has(memberPod2))
			}
			if tt.outAddressGroupMatch {
				assert.False(t, updatedOutAddrGroup.Pods.Has(memberPod1))
				assert.False(t, updatedOutAddrGroup.Pods.Has(memberPod2))
			}
		})
	}
}

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
		expInternalProto networking.Protocol
	}{
		{nil, networking.ProtocolTCP},
		{&udpProto, networking.ProtocolUDP},
		{&tcpProto, networking.ProtocolTCP},
		{&sctpProto, networking.ProtocolSCTP},
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
	portNum := intstr.FromInt(80)
	tables := []struct {
		ports     []networkingv1.NetworkPolicyPort
		expValues []networking.Service
	}{
		{
			getK8sNetworkPolicyPorts(tcpProto),
			[]networking.Service{
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

func TestToAntreaIPBlock(t *testing.T) {
	expIpNet := networking.IPNet{
		IP:           ipStrToIPAddress("10.0.0.0"),
		PrefixLength: 24,
	}
	tables := []struct {
		ipBlock  *networkingv1.IPBlock
		expValue networking.IPBlock
		err      error
	}{
		{
			&networkingv1.IPBlock{
				CIDR: "10.0.0.0/24",
			},
			networking.IPBlock{
				CIDR: expIpNet,
			},
			nil,
		},
		{
			&networkingv1.IPBlock{
				CIDR: "10.0.0.0",
			},
			networking.IPBlock{},
			fmt.Errorf("invalid format for IPBlock CIDR: 10.0.0.0"),
		},
	}
	for _, table := range tables {
		antreaIPBlock, err := toAntreaIPBlock(table.ipBlock)
		if err != nil {
			if err.Error() != table.err.Error() {
				t.Errorf("Unexpected error in Antrea IPBlock conversion. Expected %v, got %v", table.err, err)
			}
		}
		if antreaIPBlock == nil {
			continue
		}
		ipNet := antreaIPBlock.CIDR
		if bytes.Compare(ipNet.IP, table.expValue.CIDR.IP) != 0 {
			t.Errorf("Unexpected IP in Antrea IPBlock conversion. Expected %v, got %v", table.expValue.CIDR.IP, ipNet.IP)
		}
		if table.expValue.CIDR.PrefixLength != ipNet.PrefixLength {
			t.Errorf("Unexpected PrefixLength in Antrea IPBlock conversion. Expected %v, got %v", table.expValue.CIDR.PrefixLength, ipNet.PrefixLength)
		}
	}
}

func TestProcessNetworkPolicy(t *testing.T) {
	protocolTCP := networking.ProtocolTCP
	intstr80, intstr81 := intstr.FromInt(80), intstr.FromInt(81)
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
				Rules: []networking.NetworkPolicyRule{{
					Direction: networking.DirectionIn,
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
				Rules:           []networking.NetworkPolicyRule{denyAllEgressRule},
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
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr80,
							},
						},
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr81,
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
				Rules: []networking.NetworkPolicyRule{
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr80,
							},
						},
					},
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", nil, &selectorC).NormalizedName)},
						},
						Services: []networking.Service{
							{
								Protocol: &protocolTCP,
								Port:     &intstr81,
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
			_, c := newController()

			if actualPolicy := c.processNetworkPolicy(tt.inputPolicy); !reflect.DeepEqual(actualPolicy, tt.expectedPolicy) {
				t.Errorf("processNetworkPolicy() got %v, want %v", actualPolicy, tt.expectedPolicy)
			}

			if actualAddressGroups := len(c.addressGroupStore.List()); actualAddressGroups != tt.expectedAddressGroups {
				t.Errorf("len(addressGroupStore.List()) got %v, want %v", actualAddressGroups, tt.expectedAddressGroups)
			}

			if actualAppliedToGroups := len(c.appliedToGroupStore.List()); actualAppliedToGroups != tt.expectedAppliedToGroups {
				t.Errorf("len(appliedToGroupStore.List()) got %v, want %v", actualAppliedToGroups, tt.expectedAppliedToGroups)
			}
		})
	}
}

// util functions for testing.
func getK8sNetworkPolicyPorts(proto v1.Protocol) []networkingv1.NetworkPolicyPort {
	portNum := intstr.FromInt(80)
	port := networkingv1.NetworkPolicyPort{
		Protocol: &proto,
		Port:     &portNum,
	}
	ports := []networkingv1.NetworkPolicyPort{port}
	return ports
}

func getK8sNetworkPolicyObj() *networkingv1.NetworkPolicy {
	ns := metav1.NamespaceDefault
	npName := "testing-1"
	pSelector := metav1.LabelSelector{}
	inNsSelector := metav1.LabelSelector{}
	outPSelector := metav1.LabelSelector{}
	ingressRules := []networkingv1.NetworkPolicyIngressRule{
		{
			From: []networkingv1.NetworkPolicyPeer{
				{
					NamespaceSelector: &inNsSelector,
				},
			},
		},
	}
	egressRules := []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector: &outPSelector,
				},
			},
		},
	}
	npObj := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: npName, Namespace: ns},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: pSelector,
			Ingress:     ingressRules,
			Egress:      egressRules,
		},
	}
	return npObj
}

func getPod(name, ns, nodeName, podIP string) *v1.Pod {
	if name == "" {
		name = "testPod"
	}
	if nodeName == "" {
		nodeName = "node1"
	}
	if ns == "" {
		ns = metav1.NamespaceDefault
	}
	if podIP == "" {
		podIP = "1.2.3.4"
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name: "container-1",
			}},
			NodeName: nodeName,
		},
		Status: v1.PodStatus{
			Conditions: []v1.PodCondition{
				{
					Type:   v1.PodReady,
					Status: v1.ConditionTrue,
				},
			},
			PodIP: podIP,
		},
	}
}
