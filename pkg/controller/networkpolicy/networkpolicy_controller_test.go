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
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	fakeversioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync time.Duration = 30 * time.Second

var (
	k8sProtocolUDP  = corev1.ProtocolUDP
	k8sProtocolTCP  = corev1.ProtocolTCP
	k8sProtocolSCTP = corev1.ProtocolSCTP

	protocolTCP = controlplane.ProtocolTCP

	int80   = intstr.FromInt(80)
	int81   = intstr.FromInt(81)
	int1000 = intstr.FromInt(1000)

	int32For1999 = int32(1999)

	strHTTP = intstr.FromString("http")
)

type networkPolicyController struct {
	*NetworkPolicyController
	podStore                   cache.Store
	externalEntityStore        cache.Store
	namespaceStore             cache.Store
	networkPolicyStore         cache.Store
	cnpStore                   cache.Store
	tierStore                  cache.Store
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
	groupStore := store.NewGroupStore()
	npController := NewNetworkPolicyController(client,
		crdClient,
		informerFactory.Core().V1().Pods(),
		informerFactory.Core().V1().Namespaces(),
		crdInformerFactory.Core().V1alpha2().ExternalEntities(),
		informerFactory.Networking().V1().NetworkPolicies(),
		crdInformerFactory.Security().V1alpha1().ClusterNetworkPolicies(),
		crdInformerFactory.Security().V1alpha1().NetworkPolicies(),
		crdInformerFactory.Security().V1alpha1().Tiers(),
		crdInformerFactory.Core().V1alpha2().ClusterGroups(),
		addressGroupStore,
		appliedToGroupStore,
		internalNetworkPolicyStore,
		groupStore)
	npController.podListerSynced = alwaysReady
	npController.namespaceListerSynced = alwaysReady
	npController.networkPolicyListerSynced = alwaysReady
	npController.cnpListerSynced = alwaysReady
	npController.tierLister = crdInformerFactory.Security().V1alpha1().Tiers().Lister()
	npController.tierListerSynced = alwaysReady
	return client, &networkPolicyController{
		npController,
		informerFactory.Core().V1().Pods().Informer().GetStore(),
		crdInformerFactory.Core().V1alpha2().ExternalEntities().Informer().GetStore(),
		informerFactory.Core().V1().Namespaces().Informer().GetStore(),
		informerFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		crdInformerFactory.Security().V1alpha1().ClusterNetworkPolicies().Informer().GetStore(),
		crdInformerFactory.Security().V1alpha1().Tiers().Informer().GetStore(),
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
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll, nil).NormalizedName)}
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{{
					Direction: controlplane.DirectionIn,
					From:      matchAllPeer,
					Services:  nil,
					Priority:  defaultRulePriority,
					Action:    &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npB",
					UID:       "uidB",
				},
				Rules: []controlplane.NetworkPolicyRule{{
					Direction: controlplane.DirectionOut,
					To:        matchAllPeer,
					Services:  nil,
					Priority:  defaultRulePriority,
					Action:    &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidB",
				Name: "uidB",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npB",
					UID:       "uidB",
				},
				Rules: []controlplane.NetworkPolicyRule{{
					Direction: controlplane.DirectionOut,
					To:        matchAllPeerEgress,
					Services: []controlplane.Service{
						{
							Protocol: &protocolTCP,
							Port:     &strHTTP,
						},
					},
					Priority: defaultRulePriority,
					Action:   &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidC",
				Name: "uidC",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npC",
					UID:       "uidC",
				},
				Rules: []controlplane.NetworkPolicyRule{
					denyAllIngressRule,
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidD",
				Name: "uidD",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npD",
					UID:       "uidD",
				},
				Rules: []controlplane.NetworkPolicyRule{
					denyAllEgressRule,
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidE",
				Name: "uidE",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npE",
					UID:       "uidE",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil, nil).NormalizedName)},
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
				UID:  "uidF",
				Name: "uidF",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npF",
					UID:       "uidF",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", nil, &selectorC, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil, nil).NormalizedName)},
			},
			expAppliedToGroups: 1,
			expAddressGroups:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addNetworkPolicy(tt.inputPolicy)
			key := internalNetworkPolicyKeyFunc(tt.inputPolicy)
			actualPolicyObj, _, _ := npc.internalNetworkPolicyStore.Get(key)
			actualPolicy := actualPolicyObj.(*antreatypes.NetworkPolicy)
			assert.Equal(t, tt.expPolicy, actualPolicy)
			assert.Equal(t, tt.expAddressGroups, len(npc.addressGroupStore.List()))
			assert.Equal(t, tt.expAppliedToGroups, len(npc.appliedToGroupStore.List()))
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
	apgID := getNormalizedUID(generateNormalizedName(ns, pLabelSelector, nil, nil))
	_, npc := newController()
	npc.addNetworkPolicy(npObj)
	npc.deleteNetworkPolicy(npObj)
	_, found, _ := npc.appliedToGroupStore.Get(apgID)
	assert.False(t, found, "expected AppliedToGroup to be deleted")
	adgs := npc.addressGroupStore.List()
	assert.Len(t, adgs, 0, "expected empty AddressGroup list")
	key := internalNetworkPolicyKeyFunc(npObj)
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules:           []controlplane.NetworkPolicyRule{},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("", nil, &selectorA, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil, nil).NormalizedName)},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
			key := internalNetworkPolicyKeyFunc(oldNP)
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
		addedPod             *corev1.Pod
		appGroupMatch        bool
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			name: "not-match-spec-podselector-match-labels",
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"role": "db"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels: map[string]string{
						"role":  "db",
						"group": "appliedTo",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"inGroup": "inAddress"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"outGroup": "outAddress"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
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
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"inGroup": "inAddress"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "none"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
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
			appGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorSpec, nil, nil).NormalizedName)
			inGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorIn, nil, nil).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorOut, nil, nil).NormalizedName)
			npc.syncAppliedToGroup(appGroupID)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			appGroupObj, _, _ := npc.appliedToGroupStore.Get(appGroupID)
			appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
			podsAdded := appGroup.GroupMemberByNode["nodeA"]
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			if tt.appGroupMatch {
				assert.Len(t, podsAdded, 1, "expected Pod to match AppliedToGroup")
			} else {
				assert.Len(t, podsAdded, 0, "expected Pod not to match AppliedToGroup")
			}
			memberPod := &controlplane.GroupMember{
				Pod: &controlplane.PodReference{Name: "podA", Namespace: "nsA"},
				IPs: []controlplane.IPAddress{ipStrToIPAddress("1.2.3.4")},
			}
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.GroupMembers.Has(memberPod))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.GroupMembers.Has(memberPod))
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
	matchAppGID := getNormalizedUID(generateNormalizedName(ns, mLabelSelector, nil, nil))
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
	podsAdded := appGroup.GroupMemberByNode[nodeName]
	// Ensure Pod1 reference is removed from AppliedToGroup.
	assert.Len(t, podsAdded, 0, "expected Pod to be deleted from AppliedToGroup")
	// Delete Pod P2 matching the NetworkPolicy Rule.
	npc.podStore.Delete(p2)
	npc.syncAddressGroup(addrGroup.Name)
	updatedAddrGroupObj, _, _ := npc.addressGroupStore.Get(addrGroup.Name)
	updatedAddrGroup := updatedAddrGroupObj.(*antreatypes.AddressGroup)
	// Ensure Pod2 IP is removed from AddressGroup.
	memberPod2 := &controlplane.GroupMember{IPs: []controlplane.IPAddress{ipStrToIPAddress(p2IP)}}
	assert.False(t, updatedAddrGroup.GroupMembers.Has(memberPod2))
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
		addedNamespace       *corev1.Namespace
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			name: "match-namespace-ingress-rule",
			addedNamespace: &corev1.Namespace{
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
			addedNamespace: &corev1.Namespace{
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
			addedNamespace: &corev1.Namespace{
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
			addedNamespace: &corev1.Namespace{
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
			inGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorIn, nil).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorOut, nil).NormalizedName)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			memberPod1 := &controlplane.GroupMember{
				Pod: &controlplane.PodReference{Name: "p1", Namespace: "nsA"},
				IPs: []controlplane.IPAddress{ipStrToIPAddress("1.2.3.4")},
			}
			memberPod2 := &controlplane.GroupMember{
				Pod: &controlplane.PodReference{Name: "p2", Namespace: "nsA"},
				IPs: []controlplane.IPAddress{ipStrToIPAddress("2.2.3.4")},
			}
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.GroupMembers.Has(memberPod1))
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.GroupMembers.Has(memberPod2))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.GroupMembers.Has(memberPod1))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.GroupMembers.Has(memberPod2))
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
		deletedNamespace     *corev1.Namespace
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			name: "match-namespace-ingress-rule",
			deletedNamespace: &corev1.Namespace{
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
			deletedNamespace: &corev1.Namespace{
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
			deletedNamespace: &corev1.Namespace{
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
			deletedNamespace: &corev1.Namespace{
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
			inGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorIn, nil).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("", nil, &selectorOut, nil).NormalizedName)
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
			memberPod1 := &controlplane.GroupMember{IPs: []controlplane.IPAddress{ipStrToIPAddress("1.1.1.1")}}
			memberPod2 := &controlplane.GroupMember{IPs: []controlplane.IPAddress{ipStrToIPAddress("1.1.1.2")}}
			if tt.inAddressGroupMatch {
				assert.False(t, updatedInAddrGroup.GroupMembers.Has(memberPod1))
				assert.False(t, updatedInAddrGroup.GroupMembers.Has(memberPod2))
			}
			if tt.outAddressGroupMatch {
				assert.False(t, updatedOutAddrGroup.GroupMembers.Has(memberPod1))
				assert.False(t, updatedOutAddrGroup.GroupMembers.Has(memberPod2))
			}
		})
	}
}

func TestFilterAddressGroupsForPodOrExternalEntity(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test-select"},
	}
	eeSelectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"platform": "aws"},
	}
	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "ns1",
			Labels: map[string]string{"purpose": "test-select"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns2",
		},
	}
	addrGrp1 := &antreatypes.AddressGroup{
		UID:      "uid1",
		Name:     "AddrGrp1",
		Selector: *toGroupSelector("ns1", &selectorSpec, nil, nil),
	}
	addrGrp2 := &antreatypes.AddressGroup{
		UID:      "uid2",
		Name:     "AddrGrp2",
		Selector: *toGroupSelector("ns1", nil, nil, &eeSelectorSpec),
	}
	addrGrp3 := &antreatypes.AddressGroup{
		UID:      "uid3",
		Name:     "AddrGrp3",
		Selector: *toGroupSelector("", nil, &selectorSpec, nil),
	}
	addrGrp4 := &antreatypes.AddressGroup{
		UID:      "uid4",
		Name:     "AddrGrp4",
		Selector: *toGroupSelector("", &selectorSpec, &selectorSpec, nil),
	}

	pod1 := getPod("pod1", "ns1", "node1", "1.1.1.1", false)
	pod1.Labels = map[string]string{"purpose": "test-select"}
	pod2 := getPod("pod2", "ns1", "node1", "1.1.1.2", false)
	pod3 := getPod("pod3", "ns2", "node1", "1.1.1.3", false)
	ee1 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee1",
			Namespace: "ns1",
			Labels:    map[string]string{"platform": "aws"},
		},
	}
	ee2 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee2",
			Namespace: "ns1",
			Labels:    map[string]string{"platform": "gke"},
		},
	}
	tests := []struct {
		name           string
		toMatch        metav1.Object
		expectedGroups sets.String
	}{
		{
			"pod-match-selector-match-ns",
			pod1,
			sets.NewString("AddrGrp1", "AddrGrp3", "AddrGrp4"),
		},
		{
			"pod-unmatch-selector-match-ns",
			pod2,
			sets.NewString("AddrGrp3"),
		},
		{
			"pod-unmatch-selector-unmatch-ns",
			pod3,
			sets.String{},
		},
		{
			"externalEntity-match-selector-match-ns",
			ee1,
			sets.NewString("AddrGrp2", "AddrGrp3"),
		},
		{
			"externalEntity-unmatch-selector-match-ns",
			ee2,
			sets.NewString("AddrGrp3"),
		},
	}
	_, npc := newController()
	npc.addressGroupStore.Create(addrGrp1)
	npc.addressGroupStore.Create(addrGrp2)
	npc.addressGroupStore.Create(addrGrp3)
	npc.addressGroupStore.Create(addrGrp4)
	npc.namespaceStore.Add(ns1)
	npc.namespaceStore.Add(ns2)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedGroups, npc.filterAddressGroupsForPodOrExternalEntity(tt.toMatch),
				"Filtered AddressGroups does not match expectation")
		})
	}
}

func TestFilterAppliedToGroupsForPodOrExternalEntity(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test-select"},
	}
	eeSelectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"platform": "aws"},
	}
	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "ns1",
			Labels: map[string]string{"purpose": "test-select"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns2",
		},
	}
	atGrp1 := &antreatypes.AppliedToGroup{
		UID:      "uid1",
		Name:     "ATGrp1",
		Selector: *toGroupSelector("ns1", &selectorSpec, nil, nil),
	}
	atGrp2 := &antreatypes.AppliedToGroup{
		UID:      "uid2",
		Name:     "ATGrp2",
		Selector: *toGroupSelector("ns1", nil, nil, &eeSelectorSpec),
	}
	atGrp3 := &antreatypes.AppliedToGroup{
		UID:      "uid3",
		Name:     "ATGrp3",
		Selector: *toGroupSelector("", nil, &selectorSpec, nil),
	}
	atGrp4 := &antreatypes.AppliedToGroup{
		UID:      "uid4",
		Name:     "ATGrp4",
		Selector: *toGroupSelector("", &selectorSpec, &selectorSpec, nil),
	}

	pod1 := getPod("pod1", "ns1", "node1", "1.1.1.1", false)
	pod1.Labels = map[string]string{"purpose": "test-select"}
	pod2 := getPod("pod2", "ns1", "node1", "1.1.1.2", false)
	pod3 := getPod("pod3", "ns2", "node1", "1.1.1.3", false)
	ee1 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee1",
			Namespace: "ns1",
			Labels:    map[string]string{"platform": "aws"},
		},
	}
	ee2 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee2",
			Namespace: "ns1",
			Labels:    map[string]string{"platform": "gke"},
		},
	}
	tests := []struct {
		name           string
		toMatch        metav1.Object
		expectedGroups sets.String
	}{
		{
			"pod-match-selector-match-ns",
			pod1,
			sets.NewString("ATGrp1", "ATGrp3", "ATGrp4"),
		},
		{
			"pod-unmatch-selector-match-ns",
			pod2,
			sets.NewString("ATGrp3"),
		},
		{
			"pod-unmatch-selector-unmatch-ns",
			pod3,
			sets.String{},
		},
		{
			"externalEntity-match-selector-match-ns",
			ee1,
			sets.NewString("ATGrp2", "ATGrp3"),
		},
		{
			"externalEntity-unmatch-selector-match-ns",
			ee2,
			sets.NewString("ATGrp3"),
		},
	}
	_, npc := newController()
	npc.appliedToGroupStore.Create(atGrp1)
	npc.appliedToGroupStore.Create(atGrp2)
	npc.appliedToGroupStore.Create(atGrp3)
	npc.appliedToGroupStore.Create(atGrp4)
	npc.namespaceStore.Add(ns1)
	npc.namespaceStore.Add(ns2)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedGroups, npc.filterAppliedToGroupsForPodOrExternalEntity(tt.toMatch),
				"Filtered AppliedTo Groups does not match expectation")
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
				NormalizedName:    generateNormalizedName("nsName", pLabelSelector, nil, nil),
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
				NormalizedName:    generateNormalizedName("", nil, nLabelSelector, nil),
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
				NormalizedName:    generateNormalizedName("nsName", pLabelSelector, nil, nil),
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
				NormalizedName:    generateNormalizedName("", pLabelSelector, nLabelSelector, nil),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := toGroupSelector(tt.namespace, tt.podSelector, tt.nsSelector, nil)
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
		name := generateNormalizedName(table.namespace, table.pSelector, table.nSelector, nil)
		if table.expName != name {
			t.Errorf("Unexpected normalized name. Expected %s, got %s", table.expName, name)
		}
	}
}

func TestToAntreaProtocol(t *testing.T) {
	tables := []struct {
		proto            *corev1.Protocol
		expInternalProto controlplane.Protocol
	}{
		{nil, controlplane.ProtocolTCP},
		{&k8sProtocolUDP, controlplane.ProtocolUDP},
		{&k8sProtocolTCP, controlplane.ProtocolTCP},
		{&k8sProtocolSCTP, controlplane.ProtocolSCTP},
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
		expSedrvices       []controlplane.Service
		expNamedPortExists bool
	}{
		{
			ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &k8sProtocolTCP,
					Port:     &int80,
				},
			},
			expSedrvices: []controlplane.Service{
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
			expSedrvices: []controlplane.Service{
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
	expIPNet := controlplane.IPNet{
		IP:           ipStrToIPAddress("10.0.0.0"),
		PrefixLength: 24,
	}
	tables := []struct {
		ipBlock  *networkingv1.IPBlock
		expValue controlplane.IPBlock
		err      error
	}{
		{
			&networkingv1.IPBlock{
				CIDR: "10.0.0.0/24",
			},
			controlplane.IPBlock{
				CIDR: expIPNet,
			},
			nil,
		},
		{
			&networkingv1.IPBlock{
				CIDR: "10.0.0.0",
			},
			controlplane.IPBlock{},
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
	matchAllPodsPeer.AddressGroups = []string{getNormalizedUID(toGroupSelector("", nil, &selectorAll, nil).NormalizedName)}
	tests := []struct {
		name           string
		inPeers        []networkingv1.NetworkPolicyPeer
		outPeer        controlplane.NetworkPolicyPeer
		direction      controlplane.Direction
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
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("nsA", &selectorA, &selectorB, nil).NormalizedName),
					getNormalizedUID(toGroupSelector("nsA", &selectorC, nil, nil).NormalizedName),
				},
			},
			direction: controlplane.DirectionIn,
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
			outPeer: controlplane.NetworkPolicyPeer{
				AddressGroups: []string{
					getNormalizedUID(toGroupSelector("nsA", &selectorA, &selectorB, nil).NormalizedName),
					getNormalizedUID(toGroupSelector("nsA", &selectorC, nil, nil).NormalizedName),
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name: "ipblock-selector-peer-ingress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "ipblock-selector-peer-egress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIP,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *cidrIPNet,
					},
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name: "ipblock-with-exc-selector-peer-ingress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIPAndExc,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []controlplane.IPNet{*exc1Net, *exc2Net},
					},
				},
			},
			direction: controlplane.DirectionIn,
		},
		{
			name: "ipblock-with-exc-selector-peer-egress",
			inPeers: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &selectorIPAndExc,
				},
			},
			outPeer: controlplane.NetworkPolicyPeer{
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []controlplane.IPNet{*exc1Net, *exc2Net},
					},
				},
			},
			direction: controlplane.DirectionOut,
		},
		{
			name:      "empty-peer-ingress",
			inPeers:   []networkingv1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: controlplane.DirectionIn,
		},
		{
			name:           "empty-peer-egress-with-named-port",
			inPeers:        []networkingv1.NetworkPolicyPeer{},
			outPeer:        matchAllPodsPeer,
			direction:      controlplane.DirectionOut,
			namedPortExist: true,
		},
		{
			name:      "empty-peer-egress-without-named-port",
			inPeers:   []networkingv1.NetworkPolicyPeer{},
			outPeer:   matchAllPeer,
			direction: controlplane.DirectionOut,
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{{
					Direction: controlplane.DirectionIn,
					From:      matchAllPeer,
					Services:  nil,
					Priority:  defaultRulePriority,
					Action:    &defaultAction,
				}},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules:           []controlplane.NetworkPolicyRule{denyAllEgressRule},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionOut,
						To: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, &selectorC, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil, nil).NormalizedName)},
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
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npA",
					UID:       "uidA",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorB, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int80,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(toGroupSelector("nsA", nil, &selectorC, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int81,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(toGroupSelector("nsA", &selectorA, nil, nil).NormalizedName)},
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

func TestPodToGroupMember(t *testing.T) {
	namedPod := getPod("", "", "", "", true)
	unNamedPod := getPod("", "", "", "", false)
	tests := []struct {
		name         string
		inputPod     *corev1.Pod
		expMemberPod controlplane.GroupMember
		includeIP    bool
		namedPort    bool
	}{
		{
			name:     "namedport-pod-with-ip-ref",
			inputPod: namedPod,
			expMemberPod: controlplane.GroupMember{
				IPs: []controlplane.IPAddress{ipStrToIPAddress(namedPod.Status.PodIP)},
				Pod: &controlplane.PodReference{
					Name:      namedPod.Name,
					Namespace: namedPod.Namespace,
				},
				Ports: []controlplane.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP: true,
			namedPort: true,
		},
		{
			name:     "namedport-pod-with-ip",
			inputPod: namedPod,
			expMemberPod: controlplane.GroupMember{
				IPs: []controlplane.IPAddress{ipStrToIPAddress(namedPod.Status.PodIP)},
				Pod: &controlplane.PodReference{
					Name:      namedPod.Name,
					Namespace: namedPod.Namespace,
				},
				Ports: []controlplane.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP: true,
			namedPort: true,
		},
		{
			name:     "namedport-pod-with-ref",
			inputPod: namedPod,
			expMemberPod: controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      namedPod.Name,
					Namespace: namedPod.Namespace,
				},
				Ports: []controlplane.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP: false,
			namedPort: true,
		},
		{
			name:     "unnamedport-pod-with-ref",
			inputPod: unNamedPod,
			expMemberPod: controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      unNamedPod.Name,
					Namespace: unNamedPod.Namespace,
				},
			},
			includeIP: false,
			namedPort: false,
		},
		{
			name:     "unnamedport-pod-with-ip",
			inputPod: unNamedPod,
			expMemberPod: controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      unNamedPod.Name,
					Namespace: unNamedPod.Namespace,
				},
				IPs: []controlplane.IPAddress{ipStrToIPAddress(unNamedPod.Status.PodIP)},
			},
			includeIP: true,
			namedPort: false,
		},
		{
			name:     "unnamedport-pod-with-ip-ref",
			inputPod: unNamedPod,
			expMemberPod: controlplane.GroupMember{
				IPs: []controlplane.IPAddress{ipStrToIPAddress(unNamedPod.Status.PodIP)},
				Pod: &controlplane.PodReference{
					Name:      unNamedPod.Name,
					Namespace: unNamedPod.Namespace,
				},
				Ports: []controlplane.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
			includeIP: true,
			namedPort: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMemberPod := podToGroupMember(tt.inputPod, tt.includeIP)
			if !reflect.DeepEqual(*(*actualMemberPod).Pod, *(tt.expMemberPod).Pod) {
				t.Errorf("podToMemberPod() got unexpected PodReference %v, want %v", *(*actualMemberPod).Pod, *(tt.expMemberPod).Pod)
			}
			// Case where the IPAddress must not be populated.
			if !tt.includeIP {
				if len(actualMemberPod.IPs) > 0 {
					t.Errorf("podToMemberPod() got unexpected IP %v, want nil", actualMemberPod.IPs)
				}
			} else if !comparePodIPs(actualMemberPod.IPs, tt.expMemberPod.IPs) {
				t.Errorf("podToMemberPod() got unexpected IP %v, want %v", actualMemberPod.IPs, tt.expMemberPod.IPs)
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

func comparePodIPs(actIPs, expIPs []controlplane.IPAddress) bool {
	if len(actIPs) != len(expIPs) {
		return false
	}
	for _, ip := range actIPs {
		if !containsPodIP(expIPs, ip) {
			return false
		}
	}
	return true
}

func containsPodIP(expIPs []controlplane.IPAddress, actIP controlplane.IPAddress) bool {
	for _, expIP := range expIPs {
		if bytes.Compare(actIP, expIP) == 0 {
			return true
		}
	}
	return false
}

func TestCIDRStrToIPNet(t *testing.T) {
	tests := []struct {
		name string
		inC  string
		expC *controlplane.IPNet
	}{
		{
			name: "cidr-valid",
			inC:  "10.0.0.0/16",
			expC: &controlplane.IPNet{
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
		expIP controlplane.IPAddress
	}{
		{
			name:  "str-ip-valid",
			ipStr: ip1,
			expIP: controlplane.IPAddress(expIP1),
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
	ns := &corev1.Namespace{
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

func getQueuedGroups(npc *networkPolicyController) (atGroups, addrGroups sets.String) {
	atGroups, addrGroups = sets.NewString(), sets.NewString()
	atLen, addrLen := npc.appliedToGroupQueue.Len(), npc.addressGroupQueue.Len()
	for i := 0; i < atLen; i++ {
		id, _ := npc.appliedToGroupQueue.Get()
		atGroups.Insert(id.(string))
		npc.appliedToGroupQueue.Done(id)
	}
	for i := 0; i < addrLen; i++ {
		id, _ := npc.addressGroupQueue.Get()
		addrGroups.Insert(id.(string))
		npc.addressGroupQueue.Done(id)
	}
	return
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

func getPod(name, ns, nodeName, podIP string, namedPort bool) *corev1.Pod {
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
	ctrPort := corev1.ContainerPort{
		ContainerPort: 80,
		Protocol:      "tcp",
	}
	if namedPort {
		ctrPort.Name = "http"
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "container-1",
				Ports: []corev1.ContainerPort{ctrPort},
			}},
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: podIP,
			PodIPs: []corev1.PodIP{
				{
					IP: podIP,
				},
			},
		},
	}
}

// compareIPBlocks is a util function to compare the contents of two IPBlocks.
func compareIPBlocks(ipb1, ipb2 *controlplane.IPBlock) bool {
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
func compareIPNet(ipn1, ipn2 controlplane.IPNet) bool {
	if bytes.Compare(ipn1.IP, ipn2.IP) != 0 {
		return false
	}
	if ipn1.PrefixLength != ipn2.PrefixLength {
		return false
	}
	return true
}
