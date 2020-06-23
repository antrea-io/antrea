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
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	fakeversioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync time.Duration = 30 * time.Second

var (
	k8sProtocolUDP  = v1.ProtocolUDP
	k8sProtocolTCP  = v1.ProtocolTCP
	k8sProtocolSCTP = v1.ProtocolSCTP

	protocolTCP = networking.ProtocolTCP

	int80 = intstr.FromInt(80)
	int81 = intstr.FromInt(81)

	strHTTP = intstr.FromString("http")
)

type networkPolicyController struct {
	*NetworkPolicyController
	podStore                   cache.Store
	namespaceStore             cache.Store
	networkPolicyStore         cache.Store
	cnpStore                   cache.Store
	appliedToGroupStore        storage.Interface
	addressGroupStore          storage.Interface
	internalNetworkPolicyStore storage.Interface
	informerFactory            informers.SharedInformerFactory
	crdInformerFactory         crdinformers.SharedInformerFactory
}

// objects is an initial set of K8s objects that is exposed through the client.
func newController(objects ...runtime.Object) (*fake.Clientset, *networkPolicyController) {
	client := newClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	appliedToGroupStore := store.NewAppliedToGroupStore()
	addressGroupStore := store.NewAddressGroupStore()
	internalNetworkPolicyStore := store.NewNetworkPolicyStore()
	npController := NewNetworkPolicyController(client,
		crdClient,
		informerFactory.Core().V1().Pods(),
		informerFactory.Core().V1().Namespaces(),
		informerFactory.Networking().V1().NetworkPolicies(),
		crdInformerFactory.Security().V1alpha1().ClusterNetworkPolicies(),
		addressGroupStore,
		appliedToGroupStore,
		internalNetworkPolicyStore)
	npController.podListerSynced = alwaysReady
	npController.namespaceListerSynced = alwaysReady
	npController.networkPolicyListerSynced = alwaysReady
	npController.cnpListerSynced = alwaysReady
	return client, &networkPolicyController{
		npController,
		informerFactory.Core().V1().Pods().Informer().GetStore(),
		informerFactory.Core().V1().Namespaces().Informer().GetStore(),
		informerFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		crdInformerFactory.Security().V1alpha1().ClusterNetworkPolicies().Informer().GetStore(),
		appliedToGroupStore,
		addressGroupStore,
		internalNetworkPolicyStore,
		informerFactory,
		crdInformerFactory,
	}
}

func newClientset(objects ...runtime.Object) *fake.Clientset {
	client := fake.NewSimpleClientset(objects...)

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
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPeerEgress := matchAllPeer
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll).NormalizedName)}
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
					Priority:  defaultRulePriority,
					Action:    &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "default-allow-egress-without-named-port",
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
					Priority:  defaultRulePriority,
					Action:    &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   0,
		},
		{
			name: "default-allow-egress-with-named-port",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npB", UID: "uidB"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &strHTTP,
								},
							},
						},
					},
				},
			},
			expPolicy: &antreatypes.NetworkPolicy{
				UID:       "uidB",
				Name:      "npB",
				Namespace: "nsA",
				Rules: []networking.NetworkPolicyRule{{
					Direction: networking.DirectionOut,
					To:        matchAllPeerEgress,
					Services: []networking.Service{
						{
							Protocol: &protocolTCP,
							Port:     &strHTTP,
						},
					},
					Priority: defaultRulePriority,
					Action:   &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   1,
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
									Port: &int80,
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
									Port: &int81,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
									Port: &int80,
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
									Port: &int81,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
	assert.Equal(t, 6, npc.GetNetworkPolicyNum(), "expected networkPolicy number is 6")
	assert.Equal(t, 4, npc.GetAddressGroupNum(), "expected addressGroup number is 4")
	assert.Equal(t, 2, npc.GetAppliedToGroupNum(), "appliedToGroup number is 2")
}

func TestDeleteNetworkPolicy(t *testing.T) {
	npObj := getK8sNetworkPolicyObj()
	ns := npObj.ObjectMeta.Namespace
	pSelector := npObj.Spec.PodSelector
	pLabelSelector, _ := metav1.LabelSelectorAsSelector(&pSelector)
	apgID := getNormalizedUID(generateNormalizedName(ns, pLabelSelector, nil))
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: networking.DirectionIn,
						From: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorA).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: networking.DirectionOut,
						To: networking.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
			memberPod := &networking.GroupMemberPod{
				IP:  ipStrToIPAddress("1.2.3.4"),
				Pod: &networking.PodReference{Name: "podA", Namespace: "nsA"},
			}
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
	mLabelSelector, _ := metav1.LabelSelectorAsSelector(&matchSelector)
	inPSelector := metav1.LabelSelector{
		MatchLabels: ruleLabels,
	}
	matchAppGID := getNormalizedUID(generateNormalizedName(ns, mLabelSelector, nil))
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
	p1 := getPod("p1", ns, "", p1IP, false)
	// Ensure Pod p1 matches AppliedToGroup.
	p1.Labels = matchLabels
	p2 := getPod("p2", ns, "", p2IP, false)
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
			p1 := getPod("p1", "nsA", "nodeA", "1.2.3.4", false)
			p2 := getPod("p2", "nsA", "nodeA", "2.2.3.4", false)
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
			memberPod1 := &networking.GroupMemberPod{
				IP:  ipStrToIPAddress("1.2.3.4"),
				Pod: &networking.PodReference{Name: "p1", Namespace: "nsA"},
			}
			memberPod2 := &networking.GroupMemberPod{
				IP:  ipStrToIPAddress("2.2.3.4"),
				Pod: &networking.PodReference{Name: "p2", Namespace: "nsA"},
			}
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
			p1 := getPod("p1", "nsA", "", "1.1.1.1", false)
			p2 := getPod("p2", "nsA", "", "1.1.1.2", false)
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
	pLabelSelector, _ := metav1.LabelSelectorAsSelector(&pSelector)
	nSelector := metav1.LabelSelector{}
	nLabelSelector, _ := metav1.LabelSelectorAsSelector(&nSelector)
	tests := []struct {
		name             string
		namespace        string
		podSelector      *metav1.LabelSelector
		nsSelector       *metav1.LabelSelector
		expGroupSelector *antreatypes.GroupSelector
	}{
		{
			"to-group-selector-ns-pod-selector",
			"nsName",
			&pSelector,
			nil,
			&antreatypes.GroupSelector{
				Namespace:         "nsName",
				NamespaceSelector: nil,
				PodSelector:       pLabelSelector,
				NormalizedName:    generateNormalizedName("nsName", pLabelSelector, nil),
			},
		},
		{
			"to-group-selector-ns-selector",
			"nsName",
			nil,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: nLabelSelector,
				PodSelector:       nil,
				NormalizedName:    generateNormalizedName("", nil, nLabelSelector),
			},
		},
		{
			"to-group-selector-pod-selector",
			"nsName",
			&pSelector,
			nil,
			&antreatypes.GroupSelector{
				Namespace:         "nsName",
				NamespaceSelector: nil,
				PodSelector:       pLabelSelector,
				NormalizedName:    generateNormalizedName("nsName", pLabelSelector, nil),
			},
		},
		{
			"to-group-selector-ns-selector-pod-selector",
			"nsName",
			&pSelector,
			&nSelector,
			&antreatypes.GroupSelector{
				Namespace:         "",
				NamespaceSelector: nLabelSelector,
				PodSelector:       pLabelSelector,
				NormalizedName:    generateNormalizedName("", pLabelSelector, nLabelSelector),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := toGroupSelector(tt.namespace, tt.podSelector, tt.nsSelector)
			if group.Namespace != tt.expGroupSelector.Namespace {
				t.Errorf("Group Namespace incorrectly set. Expected %s, got: %s", tt.expGroupSelector.Namespace, group.Namespace)
			}
			if group.NormalizedName != tt.expGroupSelector.NormalizedName {
				t.Errorf("Group normalized Name incorrectly set. Expected %s, got: %s", tt.expGroupSelector.NormalizedName, group.NormalizedName)
			}
			if group.NamespaceSelector != nil && tt.expGroupSelector.NamespaceSelector != nil {
				if !reflect.DeepEqual(group.NamespaceSelector, tt.expGroupSelector.NamespaceSelector) {
					t.Errorf("Group NamespaceSelector incorrectly set. Expected %v, got: %v", tt.expGroupSelector.NamespaceSelector, group.NamespaceSelector)
				}
			}
			if group.PodSelector != nil && tt.expGroupSelector.PodSelector != nil {
				if !reflect.DeepEqual(group.PodSelector, tt.expGroupSelector.PodSelector) {
					t.Errorf("Group PodSelector incorrectly set. Expected %v, got: %v", tt.expGroupSelector.PodSelector, group.PodSelector)
				}
			}
		})
	}
}

func TestGenerateNormalizedName(t *testing.T) {
	pLabels := map[string]string{"app": "client"}
	req1 := metav1.LabelSelectorRequirement{
		Key:      "role",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"db", "app"},
	}
	pExprs := []metav1.LabelSelectorRequirement{req1}
	normalizedPodSelector := "app=client,role in (app,db)"
	nLabels := map[string]string{"scope": "test"}
	req2 := metav1.LabelSelectorRequirement{
		Key:      "env",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"staging", "prod"},
	}
	nExprs := []metav1.LabelSelectorRequirement{req2}
	normalizedNSSelector := "env notin (prod,staging),scope=test"
	pSelector := metav1.LabelSelector{
		MatchLabels:      pLabels,
		MatchExpressions: pExprs,
	}
	pLabelSelector, _ := metav1.LabelSelectorAsSelector(&pSelector)
	nSelector := metav1.LabelSelector{
		MatchLabels:      nLabels,
		MatchExpressions: nExprs,
	}
	nLabelSelector, _ := metav1.LabelSelectorAsSelector(&nSelector)
	tables := []struct {
		namespace string
		pSelector labels.Selector
		nSelector labels.Selector
		expName   string
	}{
		{
			"nsName",
			pLabelSelector,
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
			nLabelSelector,
			fmt.Sprintf("namespaceSelector=%s", normalizedNSSelector),
		},
		{
			"nsName",
			pLabelSelector,
			nLabelSelector,
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
	tables := []struct {
		proto            *v1.Protocol
		expInternalProto networking.Protocol
	}{
		{nil, networking.ProtocolTCP},
		{&k8sProtocolUDP, networking.ProtocolUDP},
		{&k8sProtocolTCP, networking.ProtocolTCP},
		{&k8sProtocolSCTP, networking.ProtocolSCTP},
	}
	for _, table := range tables {
		protocol := toAntreaProtocol(table.proto)
		if *protocol != table.expInternalProto {
			t.Errorf("Unexpected Antrea protocol. Expected %v, got %v", table.expInternalProto, *protocol)
		}
	}
}

func TestToAntreaServices(t *testing.T) {
	tables := []struct {
		ports              []networkingv1.NetworkPolicyPort
		expSedrvices       []networking.Service
		expNamedPortExists bool
	}{
		{
			ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int80,
				},
			},
			expSedrvices: []networking.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &int80,
				},
			},
			expNamedPortExists: false,
		},
		{
			ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &strHTTP,
				},
			},
			expSedrvices: []networking.Service{
				{
					Protocol: toAntreaProtocol(&k8sProtocolTCP),
					Port:     &strHTTP,
				},
			},
			expNamedPortExists: true,
		},
	}
	for _, table := range tables {
		services, namedPortExist := toAntreaServices(table.ports)
		assert.Equal(t, table.expSedrvices, services)
		assert.Equal(t, table.expNamedPortExists, namedPortExist)
	}
}

func TestToAntreaIPBlock(t *testing.T) {
	expIPNet := networking.IPNet{
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
				CIDR: expIPNet,
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

func TestToAntreaPeer(t *testing.T) {
	testNPObj := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "npA",
			Namespace: "nsA",
		},
	}
	cidr := "10.0.0.0/16"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	exc1 := "10.0.1.0/24"
	exc2 := "10.0.2.0/24"
	excSlice := []string{exc1, exc2}
	exc1Net, _ := cidrStrToIPNet(exc1)
	exc2Net, _ := cidrStrToIPNet(exc2)
	selectorIP := networkingv1.IPBlock{CIDR: cidr}
	selectorIPAndExc := networkingv1.IPBlock{CIDR: cidr,
		Except: excSlice}
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorAll := metav1.LabelSelector{}
	matchAllPodsPeer := matchAllPeer
	matchAllPodsPeer.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll).NormalizedName)}
	tests := []struct {
		name           string
		inPeers        []networkingv1.NetworkPolicyPeer
		outPeer        networking.NetworkPolicyPeer
		direction      networking.Direction
		namedPortExist bool
	}{
		{
			name: "pod-ns-selector-peer-ingress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("nsA", &selectorA, &selectorB).NormalizedName),
					getNormalizedUID(toGroupSelector("nsA", &selectorC, nil).NormalizedName),
				},
			},
			direction: networking.DirectionIn,
		},
		{
			name: "pod-ns-selector-peer-egress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					PodSelector:       &selectorA,
					NamespaceSelector: &selectorB,
				},
				{
					PodSelector: &selectorC,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("nsA", &selectorA, &selectorB).NormalizedName),
					getNormalizedUID(toGroupSelector("nsA", &selectorC, nil).NormalizedName),
				},
			},
			direction: networking.DirectionOut,
		},
		{
			name: "ipblock-selector-peer-ingress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				IPBlocks: []networking.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: networking.DirectionIn,
		},
		{
			name: "ipblock-selector-peer-egress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				IPBlocks: []networking.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: networking.DirectionOut,
		},
		{
			name: "ipblock-with-exc-selector-peer-ingress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIPAndExc,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				IPBlocks: []networking.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []networking.IPNet{*exc1Net, *exc2Net},
					},
				},
			},
			direction: networking.DirectionIn,
		},
		{
			name: "ipblock-with-exc-selector-peer-egress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIPAndExc,
				},
			},
			outPeer: networking.NetworkPolicyPeer{
				IPBlocks: []networking.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []networking.IPNet{*exc1Net, *exc2Net},
					},
				},
			},
			direction: networking.DirectionOut,
		},
		{
			name:      "empty-peer-ingress",
			inPeers:   []networkingv1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: networking.DirectionIn,
		},
		{
			name:           "empty-peer-egress-with-named-port",
			inPeers:        []networkingv1.NetworkPolicyPeer{},
			outPeer:        matchAllPodsPeer,
			direction:      networking.DirectionOut,
			namedPortExist: true,
		},
		{
			name:      "empty-peer-egress-without-named-port",
			inPeers:   []networkingv1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: networking.DirectionOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			actualPeer := npc.toAntreaPeer(tt.inPeers, testNPObj, tt.direction, tt.namedPortExist)
			if !reflect.DeepEqual(tt.outPeer.AddressGroups, (*actualPeer).AddressGroups) {
				t.Errorf("Unexpected AddressGroups in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.AddressGroups, (*actualPeer).AddressGroups)
			}
			if len(tt.outPeer.IPBlocks) != len((*actualPeer).IPBlocks) {
				t.Errorf("Unexpected number of IPBlocks in Antrea Peer conversion. Expected %v, got %v", len(tt.outPeer.IPBlocks), len((*actualPeer).IPBlocks))
			}
			for i := 0; i < len(tt.outPeer.IPBlocks); i++ {
				if !compareIPBlocks(&(tt.outPeer.IPBlocks[i]), &((*actualPeer).IPBlocks[i])) {
					t.Errorf("Unexpected IPBlocks in Antrea Peer conversion. Expected %v, got %v", tt.outPeer.IPBlocks[i], (*actualPeer).IPBlocks[i])
				}
			}
		})
	}
}

func TestProcessNetworkPolicy(t *testing.T) {
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
					Priority:  defaultRulePriority,
					Action:    &defaultAction,
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
									Port: &int80,
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
									Port: &int81,
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
								Port:     &int80,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
									Port: &int80,
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
									Port: &int81,
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
								Port:     &int80,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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
						Priority: defaultRulePriority,
						Action:   &defaultAction,
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

func TestPodToMemberPod(t *testing.T) {
	namedPod := getPod("", "", "", "", true)
	unNamedPod := getPod("", "", "", "", false)
	tests := []struct {
		name         string
		inputPod     *v1.Pod
		expMemberPod networking.GroupMemberPod
		includeIP    bool
		includeRef   bool
		namedPort    bool
	}{
		{
			name:     "namedport-pod-with-ip-ref",
			inputPod: namedPod,
			expMemberPod: networking.GroupMemberPod{
				IP: ipStrToIPAddress(namedPod.Status.PodIP),
				Pod: &networking.PodReference{
					Name:      namedPod.Name,
					Namespace: namedPod.Namespace,
				},
				Ports: []networking.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP:  true,
			includeRef: true,
			namedPort:  true,
		},
		{
			name:     "namedport-pod-with-ip",
			inputPod: namedPod,
			expMemberPod: networking.GroupMemberPod{
				IP: ipStrToIPAddress(namedPod.Status.PodIP),
				Ports: []networking.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP:  true,
			includeRef: false,
			namedPort:  true,
		},
		{
			name:     "namedport-pod-with-ref",
			inputPod: namedPod,
			expMemberPod: networking.GroupMemberPod{
				Pod: &networking.PodReference{
					Name:      namedPod.Name,
					Namespace: namedPod.Namespace,
				},
				Ports: []networking.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP:  false,
			includeRef: true,
			namedPort:  true,
		},
		{
			name:     "unnamedport-pod-with-ref",
			inputPod: unNamedPod,
			expMemberPod: networking.GroupMemberPod{
				Pod: &networking.PodReference{
					Name:      unNamedPod.Name,
					Namespace: unNamedPod.Namespace,
				},
			},
			includeIP:  false,
			includeRef: true,
			namedPort:  false,
		},
		{
			name:     "unnamedport-pod-with-ip",
			inputPod: unNamedPod,
			expMemberPod: networking.GroupMemberPod{
				IP: ipStrToIPAddress(unNamedPod.Status.PodIP),
			},
			includeIP:  true,
			includeRef: false,
			namedPort:  false,
		},
		{
			name:     "unnamedport-pod-with-ip-ref",
			inputPod: unNamedPod,
			expMemberPod: networking.GroupMemberPod{
				IP: ipStrToIPAddress(unNamedPod.Status.PodIP),
				Pod: &networking.PodReference{
					Name:      unNamedPod.Name,
					Namespace: unNamedPod.Namespace,
				},
				Ports: []networking.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP:  true,
			includeRef: true,
			namedPort:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMemberPod := podToMemberPod(tt.inputPod, tt.includeIP, tt.includeRef)
			// Case where the PodReference must not be populated.
			if !tt.includeRef {
				if actualMemberPod.Pod != nil {
					t.Errorf("podToMemberPod() got unexpected PodReference %v, want nil", *(*actualMemberPod).Pod)
				}
			} else if !reflect.DeepEqual(*(*actualMemberPod).Pod, *(tt.expMemberPod).Pod) {
				t.Errorf("podToMemberPod() got unexpected PodReference %v, want %v", *(*actualMemberPod).Pod, *(tt.expMemberPod).Pod)
			}
			// Case where the IPAddress must not be populated.
			if !tt.includeIP {
				if actualMemberPod.IP != nil {
					t.Errorf("podToMemberPod() got unexpected IP %v, want nil", actualMemberPod.IP)
				}
			} else if bytes.Compare(actualMemberPod.IP, tt.expMemberPod.IP) != 0 {
				t.Errorf("podToMemberPod() got unexpected IP %v, want %v", actualMemberPod.IP, tt.expMemberPod.IP)
			}
			if !tt.namedPort {
				if len(actualMemberPod.Ports) > 0 {
					t.Errorf("podToMemberPod() got unexpected Ports %v, want []", actualMemberPod.Ports)
				}
			} else if !reflect.DeepEqual(actualMemberPod.Ports, tt.expMemberPod.Ports) {
				t.Errorf("podToMemberPod() got unexpected Ports %v, want %v", actualMemberPod.Ports, tt.expMemberPod.Ports)
			}
		})
	}
}

func TestCIDRStrToIPNet(t *testing.T) {
	tests := []struct {
		name string
		inC  string
		expC *networking.IPNet
	}{
		{
			name: "cidr-valid",
			inC:  "10.0.0.0/16",
			expC: &networking.IPNet{
				IP:           ipStrToIPAddress("10.0.0.0"),
				PrefixLength: int32(16),
			},
		},
		{
			name: "cidr-invalid",
			inC:  "10.0.0.0/",
			expC: nil,
		},
		{
			name: "cidr-prefix-invalid",
			inC:  "10.0.0.0/a",
			expC: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actC, _ := cidrStrToIPNet(tt.inC)
			if !reflect.DeepEqual(actC, tt.expC) {
				t.Errorf("cidrStrToIPNet() got unexpected IPNet %v, want %v", actC, tt.expC)
			}
		})
	}
}

func TestIPStrToIPAddress(t *testing.T) {
	ip1 := "10.0.1.10"
	expIP1 := net.ParseIP(ip1)
	ip2 := "1090.0.1.10"
	tests := []struct {
		name  string
		ipStr string
		expIP networking.IPAddress
	}{
		{
			name:  "str-ip-valid",
			ipStr: ip1,
			expIP: networking.IPAddress(expIP1),
		},
		{
			name:  "str-ip-invalid",
			ipStr: ip2,
			expIP: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actIP := ipStrToIPAddress(tt.ipStr)
			if bytes.Compare(actIP, tt.expIP) != 0 {
				t.Errorf("ipStrToIPAddress() got unexpected IPAddress %v, want %v", actIP, tt.expIP)
			}
		})
	}
}

func TestDeleteFinalStateUnknownPod(t *testing.T) {
	_, c := newController()
	c.heartbeatCh = make(chan heartbeat, 2)
	ns := metav1.NamespaceDefault
	pod := getPod("p1", ns, "", "1.1.1.1", false)
	c.addPod(pod)
	key, _ := cache.MetaNamespaceKeyFunc(pod)
	c.deletePod(cache.DeletedFinalStateUnknown{Key: key, Obj: pod})
	close(c.heartbeatCh)
	var ok bool
	_, ok = <-c.heartbeatCh
	assert.True(t, ok, "Missing event on channel")
	_, ok = <-c.heartbeatCh
	assert.True(t, ok, "Missing event on channel")
}

func TestDeleteFinalStateUnknownNamespace(t *testing.T) {
	_, c := newController()
	c.heartbeatCh = make(chan heartbeat, 2)
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nsA",
		},
	}
	c.addNamespace(ns)
	c.deleteNamespace(cache.DeletedFinalStateUnknown{Key: "nsA", Obj: ns})
	close(c.heartbeatCh)
	var ok bool
	_, ok = <-c.heartbeatCh
	assert.True(t, ok, "Missing event on channel")
	_, ok = <-c.heartbeatCh
	assert.True(t, ok, "Missing event on channel")
}

func TestDeleteFinalStateUnknownNetworkPolicy(t *testing.T) {
	_, c := newController()
	c.heartbeatCh = make(chan heartbeat, 2)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	c.addNetworkPolicy(np)
	key, _ := cache.MetaNamespaceKeyFunc(np)
	c.deleteNetworkPolicy(cache.DeletedFinalStateUnknown{Key: key, Obj: np})
	close(c.heartbeatCh)
	var ok bool
	_, ok = <-c.heartbeatCh
	assert.True(t, ok, "Missing event on channel")
	_, ok = <-c.heartbeatCh
	assert.True(t, ok, "Missing event on channel")
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

func getPod(name, ns, nodeName, podIP string, namedPort bool) *v1.Pod {
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
	ctrPort := v1.ContainerPort{
		ContainerPort: 80,
		Protocol:      "tcp",
	}
	if namedPort {
		ctrPort.Name = "http"
	}
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name:  "container-1",
				Ports: []v1.ContainerPort{ctrPort},
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

// compareIPBlocks is a util function to compare the contents of two IPBlocks.
func compareIPBlocks(ipb1, ipb2 *networking.IPBlock) bool {
	if ipb1 == nil && ipb2 == nil {
		return true
	}
	if (ipb1 == nil && ipb2 != nil) || (ipb1 != nil && ipb2 == nil) {
		return false
	}
	ipNet1 := (*ipb1).CIDR
	ipNet2 := (*ipb2).CIDR
	if !compareIPNet(ipNet1, ipNet2) {
		return false
	}
	exc1 := (*ipb1).Except
	exc2 := (*ipb2).Except
	if len(exc1) != len(exc2) {
		return false
	}
	for i := 0; i < len(exc1); i++ {
		if !compareIPNet(exc1[i], exc2[i]) {
			return false
		}
	}
	return true
}

// compareIPNet is a util function to compare the contents of two IPNets.
func compareIPNet(ipn1, ipn2 networking.IPNet) bool {
	if bytes.Compare(ipn1.IP, ipn2.IP) != 0 {
		return false
	}
	if ipn1.PrefixLength != ipn2.PrefixLength {
		return false
	}
	return true
}
