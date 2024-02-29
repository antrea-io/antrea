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
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	fakepolicyversioned "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	policyv1a1informers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"

	fakemcsversioned "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/fake"
	mcsinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apiserver/storage"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/labelidentity"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/externalnode"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync = 30 * time.Second

var (
	k8sProtocolUDP  = corev1.ProtocolUDP
	k8sProtocolTCP  = corev1.ProtocolTCP
	k8sProtocolSCTP = corev1.ProtocolSCTP

	protocolTCP  = controlplane.ProtocolTCP
	protocolICMP = controlplane.ProtocolICMP
	protocolIGMP = controlplane.ProtocolIGMP

	int80   = intstr.FromInt(80)
	int81   = intstr.FromInt(81)
	int1000 = intstr.FromInt(1000)

	int32For1999  = int32(1999)
	int32For32220 = int32(32220)
	int32For32230 = int32(32230)

	strHTTP = intstr.FromString("http")
)

type networkPolicyController struct {
	*NetworkPolicyController
	namespaceStore             cache.Store
	serviceStore               cache.Store
	networkPolicyStore         cache.Store
	acnpStore                  cache.Store
	annpStore                  cache.Store
	anpStore                   cache.Store
	banpStore                  cache.Store
	tierStore                  cache.Store
	cgStore                    cache.Store
	gStore                     cache.Store
	appliedToGroupStore        storage.Interface
	addressGroupStore          storage.Interface
	internalNetworkPolicyStore storage.Interface
	informerFactory            informers.SharedInformerFactory
	crdInformerFactory         crdinformers.SharedInformerFactory
	groupingController         *grouping.GroupEntityController
	labelIdentityController    *labelidentity.Controller
}

// objects is an initial set of K8s objects that is exposed through the client.
func newController(k8sObjects, crdObjects []runtime.Object) (*fake.Clientset, *networkPolicyController) {
	client := newClientset(k8sObjects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)
	mcsClient := fakemcsversioned.NewSimpleClientset()
	policyClient := fakepolicyversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	mcsInformerFactory := mcsinformers.NewSharedInformerFactory(mcsClient, informerDefaultResync)
	policyInformerFactory := policyv1a1informers.NewSharedInformerFactory(policyClient, informerDefaultResync)
	appliedToGroupStore := store.NewAppliedToGroupStore()
	addressGroupStore := store.NewAddressGroupStore()
	internalNetworkPolicyStore := store.NewNetworkPolicyStore()
	internalGroupStore := store.NewGroupStore()
	cgInformer := crdInformerFactory.Crd().V1beta1().ClusterGroups()
	gInformer := crdInformerFactory.Crd().V1beta1().Groups()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	groupingController := grouping.NewGroupEntityController(groupEntityIndex,
		informerFactory.Core().V1().Pods(),
		informerFactory.Core().V1().Namespaces(),
		crdInformerFactory.Crd().V1alpha2().ExternalEntities())
	labelIndex := labelidentity.NewLabelIdentityIndex()
	labelIdentityController := labelidentity.NewLabelIdentityController(
		labelIndex,
		mcsInformerFactory.Multicluster().V1alpha1().LabelIdentities())
	npController := NewNetworkPolicyController(client,
		crdClient,
		groupEntityIndex,
		labelIndex,
		informerFactory.Core().V1().Namespaces(),
		informerFactory.Core().V1().Services(),
		informerFactory.Networking().V1().NetworkPolicies(),
		informerFactory.Core().V1().Nodes(),
		crdInformerFactory.Crd().V1beta1().ClusterNetworkPolicies(),
		crdInformerFactory.Crd().V1beta1().NetworkPolicies(),
		policyInformerFactory.Policy().V1alpha1().AdminNetworkPolicies(),
		policyInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies(),
		crdInformerFactory.Crd().V1beta1().Tiers(),
		cgInformer,
		gInformer,
		addressGroupStore,
		appliedToGroupStore,
		internalNetworkPolicyStore,
		internalGroupStore,
		true)
	npController.namespaceLister = informerFactory.Core().V1().Namespaces().Lister()
	npController.namespaceListerSynced = alwaysReady
	npController.networkPolicyListerSynced = alwaysReady
	npController.acnpListerSynced = alwaysReady
	npController.tierLister = crdInformerFactory.Crd().V1beta1().Tiers().Lister()
	npController.tierListerSynced = alwaysReady
	npController.cgInformer = cgInformer
	npController.cgLister = cgInformer.Lister()
	npController.cgListerSynced = alwaysReady
	npController.serviceLister = informerFactory.Core().V1().Services().Lister()
	npController.serviceListerSynced = alwaysReady
	return client, &networkPolicyController{
		npController,
		informerFactory.Core().V1().Namespaces().Informer().GetStore(),
		informerFactory.Core().V1().Services().Informer().GetStore(),
		informerFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		crdInformerFactory.Crd().V1beta1().ClusterNetworkPolicies().Informer().GetStore(),
		crdInformerFactory.Crd().V1beta1().NetworkPolicies().Informer().GetStore(),
		policyInformerFactory.Policy().V1alpha1().AdminNetworkPolicies().Informer().GetStore(),
		policyInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies().Informer().GetStore(),
		crdInformerFactory.Crd().V1beta1().Tiers().Informer().GetStore(),
		crdInformerFactory.Crd().V1beta1().ClusterGroups().Informer().GetStore(),
		crdInformerFactory.Crd().V1beta1().Groups().Informer().GetStore(),
		appliedToGroupStore,
		addressGroupStore,
		internalNetworkPolicyStore,
		informerFactory,
		crdInformerFactory,
		groupingController,
		labelIdentityController,
	}
}

// newControllerWithoutEventHandler creates a networkPolicyController that doesn't register event handlers so that the
// tests can call event handlers in their own ways.
func newControllerWithoutEventHandler(k8sObjects, crdObjects []runtime.Object) (*fake.Clientset, *networkPolicyController) {
	client := newClientset(k8sObjects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)
	policyClient := fakepolicyversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	policyInformerFactory := policyv1a1informers.NewSharedInformerFactory(policyClient, informerDefaultResync)
	appliedToGroupStore := store.NewAppliedToGroupStore()
	addressGroupStore := store.NewAddressGroupStore()
	internalNetworkPolicyStore := store.NewNetworkPolicyStore()
	internalGroupStore := store.NewGroupStore()
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()
	tierInformer := crdInformerFactory.Crd().V1beta1().Tiers()
	acnpInformer := crdInformerFactory.Crd().V1beta1().ClusterNetworkPolicies()
	annpInformer := crdInformerFactory.Crd().V1beta1().NetworkPolicies()
	anpInformer := policyInformerFactory.Policy().V1alpha1().AdminNetworkPolicies()
	banpInformer := policyInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies()
	cgInformer := crdInformerFactory.Crd().V1beta1().ClusterGroups()
	groupInformer := crdInformerFactory.Crd().V1beta1().Groups()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	npController := &NetworkPolicyController{
		kubeClient:                 client,
		crdClient:                  crdClient,
		namespaceLister:            namespaceInformer.Lister(),
		networkPolicyInformer:      networkPolicyInformer,
		networkPolicyLister:        networkPolicyInformer.Lister(),
		networkPolicyListerSynced:  networkPolicyInformer.Informer().HasSynced,
		tierInformer:               tierInformer,
		tierLister:                 tierInformer.Lister(),
		tierListerSynced:           tierInformer.Informer().HasSynced,
		acnpInformer:               acnpInformer,
		acnpLister:                 acnpInformer.Lister(),
		acnpListerSynced:           acnpInformer.Informer().HasSynced,
		annpInformer:               annpInformer,
		annpLister:                 annpInformer.Lister(),
		annpListerSynced:           annpInformer.Informer().HasSynced,
		cgInformer:                 cgInformer,
		cgLister:                   cgInformer.Lister(),
		cgListerSynced:             cgInformer.Informer().HasSynced,
		addressGroupStore:          addressGroupStore,
		appliedToGroupStore:        appliedToGroupStore,
		internalNetworkPolicyStore: internalNetworkPolicyStore,
		internalGroupStore:         internalGroupStore,
		appliedToGroupQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "appliedToGroup"),
		addressGroupQueue:          workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "addressGroup"),
		internalNetworkPolicyQueue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalNetworkPolicy"),
		internalGroupQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalGroup"),
		groupingInterface:          groupEntityIndex,
		appliedToGroupNotifier:     newNotifier(),
	}
	npController.tierInformer.Informer().AddIndexers(tierIndexers)
	npController.acnpInformer.Informer().AddIndexers(acnpIndexers)
	npController.annpInformer.Informer().AddIndexers(annpIndexers)
	return client, &networkPolicyController{
		npController,
		informerFactory.Core().V1().Namespaces().Informer().GetStore(),
		informerFactory.Core().V1().Services().Informer().GetStore(),
		informerFactory.Networking().V1().NetworkPolicies().Informer().GetStore(),
		acnpInformer.Informer().GetStore(),
		annpInformer.Informer().GetStore(),
		anpInformer.Informer().GetStore(),
		banpInformer.Informer().GetStore(),
		tierInformer.Informer().GetStore(),
		cgInformer.Informer().GetStore(),
		groupInformer.Informer().GetStore(),
		appliedToGroupStore,
		addressGroupStore,
		internalNetworkPolicyStore,
		informerFactory,
		crdInformerFactory,
		nil,
		nil,
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
	_, npc := newController(nil, nil)
	np := getK8sNetworkPolicyObj()
	npc.addNetworkPolicy(np)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getKNPReference(np)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestDeleteNetworkPolicy(t *testing.T) {
	_, npc := newController(nil, nil)
	np := getK8sNetworkPolicyObj()
	npc.addNetworkPolicy(np)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getKNPReference(np)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
}

func TestUpdateNetworkPolicy(t *testing.T) {
	_, npc := newController(nil, nil)
	np := getK8sNetworkPolicyObj()
	newNP := np.DeepCopy()
	newNP.Spec.Ingress = nil
	npc.updateNetworkPolicy(np, newNP)
	require.Equal(t, 1, npc.internalNetworkPolicyQueue.Len())
	key, done := npc.internalNetworkPolicyQueue.Get()
	expectedKey := getKNPReference(np)
	assert.Equal(t, *expectedKey, key)
	assert.False(t, done)
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
	selectorGroup := metav1.LabelSelector{
		MatchLabels: map[string]string{"clustergroup": "yes"},
	}
	testCG := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cgA",
		},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorGroup,
		},
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
		groupMatch           bool
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           false,
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           false,
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        true,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           false,
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  true,
			outAddressGroupMatch: false,
			groupMatch:           false,
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: true,
			groupMatch:           false,
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        true,
			inAddressGroupMatch:  true,
			outAddressGroupMatch: true,
			groupMatch:           false,
		},
		{
			name: "match-all-selectors-host-network",
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
					NodeName:    "nodeA",
					HostNetwork: true,
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           false,
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
			groupMatch:           false,
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
			groupMatch:           false,
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           false,
		},
		{
			name: "match-cg-only",
			addedPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "nsA",
					Labels:    map[string]string{"clustergroup": "yes"},
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
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			appGroupMatch:        false,
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			npc.networkPolicyStore.Add(testNPObj)
			npc.syncInternalNetworkPolicy(getKNPReference(testNPObj))
			groupKey := testCG.Name
			npc.addClusterGroup(testCG)
			npc.cgStore.Add(testCG)
			npc.groupingInterface.AddPod(tt.addedPod)
			appGroupID := getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorSpec, nil, nil, nil).NormalizedName)
			inGroupID := getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorIn, nil, nil, nil).NormalizedName)
			outGroupID := getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorOut, nil, nil, nil).NormalizedName)
			npc.syncAppliedToGroup(appGroupID)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			npc.syncInternalGroup(groupKey)
			appGroupObj, _, _ := npc.appliedToGroupStore.Get(appGroupID)
			appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
			podsAdded := appGroup.GroupMemberByNode["nodeA"]
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			groupMembers, _, _ := npc.GetGroupMembers(groupKey)
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
			assert.Equal(t, tt.groupMatch, groupMembers.Has(memberPod))
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
	matchAppGID := getNormalizedUID(antreatypes.GenerateNormalizedName(ns, mLabelSelector, nil, nil, nil))
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
	selectorGroup := metav1.LabelSelector{
		MatchLabels: ruleLabels,
	}
	testCG := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cgA",
		},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorGroup,
		},
	}
	groupKey := testCG.Name
	p1IP := "1.1.1.1"
	p2IP := "2.2.2.2"
	p1 := getPod("p1", ns, "", p1IP, false)
	// Ensure Pod p1 matches AppliedToGroup.
	p1.Labels = matchLabels
	p2 := getPod("p2", ns, "", p2IP, false)
	// Ensure Pod p2 matches AddressGroup.
	p2.Labels = ruleLabels
	_, npc := newController(nil, nil)
	npc.networkPolicyStore.Add(matchNPObj)
	npc.syncInternalNetworkPolicy(getKNPReference(matchNPObj))
	npc.addClusterGroup(testCG)
	npc.groupingInterface.AddPod(p1)
	npc.groupingInterface.AddPod(p2)
	npc.syncAppliedToGroup(matchAppGID)
	// Retrieve AddressGroup.
	adgs := npc.addressGroupStore.List()
	// Considering the NP, there should be only one AddressGroup for tests.
	addrGroupObj := adgs[0]
	addrGroup := addrGroupObj.(*antreatypes.AddressGroup)
	npc.syncAddressGroup(addrGroup.Name)
	// Delete Pod P1 matching the AppliedToGroup.
	npc.groupingInterface.DeletePod(p1)
	npc.syncAppliedToGroup(matchAppGID)
	appGroupObj, _, _ := npc.appliedToGroupStore.Get(matchAppGID)
	appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
	podsAdded := appGroup.GroupMemberByNode[nodeName]
	// Ensure Pod1 reference is removed from AppliedToGroup.
	assert.Len(t, podsAdded, 0, "expected Pod to be deleted from AppliedToGroup")
	// Delete Pod P2 matching the NetworkPolicy Rule.
	npc.groupingInterface.DeletePod(p2)
	npc.syncAddressGroup(addrGroup.Name)
	npc.syncInternalGroup(groupKey)
	updatedAddrGroupObj, _, _ := npc.addressGroupStore.Get(addrGroup.Name)
	updatedAddrGroup := updatedAddrGroupObj.(*antreatypes.AddressGroup)
	// Ensure Pod2 IP is removed from AddressGroup.
	memberPod2 := &controlplane.GroupMember{IPs: []controlplane.IPAddress{ipStrToIPAddress(p2IP)}}
	groupMembers, _, _ := npc.GetGroupMembers(groupKey)
	assert.False(t, updatedAddrGroup.GroupMembers.Has(memberPod2))
	assert.False(t, groupMembers.Has(memberPod2))
}

func TestAddNamespace(t *testing.T) {
	selectorSpec := metav1.LabelSelector{}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	selectorGroup := metav1.LabelSelector{
		MatchLabels: map[string]string{"clustergroup": "yes"},
	}
	testCG := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cgA",
		},
		Spec: v1beta1.GroupSpec{
			NamespaceSelector: &selectorGroup,
		},
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
		groupMatch           bool
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
			groupMatch:           false,
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
			groupMatch:           false,
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
			groupMatch:           false,
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
			groupMatch:           false,
		},
		{
			name: "match-namespace-cg",
			addedNamespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"clustergroup": "yes"},
				},
			},
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			npc.networkPolicyStore.Add(testNPObj)
			npc.syncInternalNetworkPolicy(getKNPReference(testNPObj))
			npc.addClusterGroup(testCG)
			npc.cgStore.Add(testCG)
			groupKey := testCG.Name

			npc.groupingInterface.AddNamespace(tt.addedNamespace)
			p1 := getPod("p1", "nsA", "nodeA", "1.2.3.4", false)
			p2 := getPod("p2", "nsA", "nodeA", "2.2.3.4", false)
			npc.groupingInterface.AddPod(p1)
			npc.groupingInterface.AddPod(p2)
			inGroupID := getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorIn, nil, nil).NormalizedName)
			outGroupID := getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorOut, nil, nil).NormalizedName)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			npc.syncInternalGroup(groupKey)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			groupMembers, _, _ := npc.GetGroupMembers(groupKey)
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
			assert.Equal(t, tt.groupMatch, groupMembers.Has(memberPod1))
			assert.Equal(t, tt.groupMatch, groupMembers.Has(memberPod2))
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
	selectorGroup := metav1.LabelSelector{
		MatchLabels: map[string]string{"clustergroup": "yes"},
	}
	testCG := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cgA",
		},
		Spec: v1beta1.GroupSpec{
			NamespaceSelector: &selectorGroup,
		},
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
		groupMatch           bool
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
			groupMatch:           false,
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
			groupMatch:           false,
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
			groupMatch:           false,
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
			groupMatch:           false,
		},
		{
			name: "match-namespace-cg",
			deletedNamespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "nsA",
					Labels: map[string]string{"clustergroup": "yes"},
				},
			},
			inAddressGroupMatch:  false,
			outAddressGroupMatch: false,
			groupMatch:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			npc.networkPolicyStore.Add(testNPObj)
			npc.syncInternalNetworkPolicy(getKNPReference(testNPObj))
			npc.addClusterGroup(testCG)
			groupKey := testCG.Name
			p1 := getPod("p1", "nsA", "", "1.1.1.1", false)
			p2 := getPod("p2", "nsA", "", "1.1.1.2", false)
			npc.groupingInterface.AddNamespace(tt.deletedNamespace)
			npc.groupingInterface.AddPod(p1)
			npc.groupingInterface.AddPod(p2)
			npc.groupingInterface.DeleteNamespace(tt.deletedNamespace)
			inGroupID := getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorIn, nil, nil).NormalizedName)
			outGroupID := getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorOut, nil, nil).NormalizedName)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			npc.syncInternalGroup(groupKey)
			npc.groupingInterface.DeletePod(p1)
			npc.groupingInterface.DeletePod(p2)
			npc.groupingInterface.DeleteNamespace(tt.deletedNamespace)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			npc.syncInternalGroup(groupKey)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			groupMembers, _, _ := npc.GetGroupMembers(groupKey)
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
			if tt.groupMatch {
				assert.False(t, groupMembers.Has(memberPod1))
				assert.False(t, groupMembers.Has(memberPod2))
			}
		})
	}
}

func TestAddAndUpdateService(t *testing.T) {
	testPod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-1",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "test-1"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: "1.2.3.4",
			PodIPs: []corev1.PodIP{
				{IP: "1.2.3.4"},
			},
		},
	}
	testPod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-2",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "test-2"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: "4.3.2.1",
			PodIPs: []corev1.PodIP{
				{IP: "4.3.2.1"},
			},
		},
	}
	testCG1 := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cg-1",
		},
		Spec: v1beta1.GroupSpec{
			ServiceReference: &v1beta1.NamespacedName{
				Name:      "test-svc-1",
				Namespace: "test-ns",
			},
		},
	}
	testCG2 := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cg-2",
		},
		Spec: v1beta1.GroupSpec{
			ServiceReference: &v1beta1.NamespacedName{
				Name:      "test-svc-2",
				Namespace: "test-ns",
			},
		},
	}
	testSvc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc-1",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "test-1"},
		},
	}
	testSvc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc-2",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{},
	}
	testSvc1Updated := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc-1",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "test-2"},
		},
	}
	_, npc := newController(nil, nil)
	npc.cgStore.Add(testCG1)
	npc.cgStore.Add(testCG2)
	npc.addClusterGroup(testCG1)
	npc.addClusterGroup(testCG2)
	npc.groupingInterface.AddPod(testPod1)
	npc.groupingInterface.AddPod(testPod2)
	npc.serviceStore.Add(testSvc1)
	npc.serviceStore.Add(testSvc2)
	npc.syncInternalGroup(testCG1.Name)
	npc.syncInternalGroup(testCG2.Name)
	memberPod1 := &controlplane.GroupMember{
		Pod: &controlplane.PodReference{
			Name:      "test-pod-1",
			Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{ipStrToIPAddress("1.2.3.4")},
	}
	memberPod2 := &controlplane.GroupMember{
		Pod: &controlplane.PodReference{
			Name:      "test-pod-2",
			Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{ipStrToIPAddress("4.3.2.1")},
	}
	groupMembers1, _, _ := npc.GetGroupMembers(testCG1.Name)
	assert.True(t, groupMembers1.Has(memberPod1))
	assert.False(t, groupMembers1.Has(memberPod2))
	groupMembers2, _, _ := npc.GetGroupMembers(testCG2.Name)
	assert.False(t, groupMembers2.Has(memberPod1))
	assert.False(t, groupMembers2.Has(memberPod2))
	// Update svc-1 to select app test-2 instead
	npc.serviceStore.Update(testSvc1Updated)
	npc.syncInternalGroup(testCG1.Name)
	groupMembers1Updated, _, _ := npc.GetGroupMembers(testCG1.Name)
	assert.False(t, groupMembers1Updated.Has(memberPod1))
	assert.True(t, groupMembers1Updated.Has(memberPod2))
}

func TestDeleteService(t *testing.T) {
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "test"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: "1.2.3.4",
			PodIPs: []corev1.PodIP{
				{IP: "1.2.3.4"},
			},
		},
	}
	testCG := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cg",
		},
		Spec: v1beta1.GroupSpec{
			ServiceReference: &v1beta1.NamespacedName{
				Name:      "test-svc",
				Namespace: "test-ns",
			},
		},
	}
	testSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "test"},
		},
	}
	_, npc := newController(nil, nil)
	npc.cgStore.Add(testCG)
	npc.addClusterGroup(testCG)
	npc.groupingInterface.AddPod(testPod)
	npc.serviceStore.Add(testSvc)
	npc.syncInternalGroup(testCG.Name)
	memberPod := &controlplane.GroupMember{
		Pod: &controlplane.PodReference{
			Name:      "test-pod",
			Namespace: "test-ns",
		},
		IPs: []controlplane.IPAddress{ipStrToIPAddress("1.2.3.4")},
	}
	groupMembers, _, _ := npc.GetGroupMembers(testCG.Name)
	assert.True(t, groupMembers.Has(memberPod))
	// Make sure that after Service deletion, the Pod member is removed from Group.
	npc.serviceStore.Delete(testSvc)
	npc.syncInternalGroup(testCG.Name)
	groupMembersUpdated, _, _ := npc.GetGroupMembers(testCG.Name)
	assert.False(t, groupMembersUpdated.Has(memberPod))
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
				NormalizedName:    antreatypes.GenerateNormalizedName("nsName", pLabelSelector, nil, nil, nil),
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
				NormalizedName:    antreatypes.GenerateNormalizedName("", nil, nLabelSelector, nil, nil),
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
				NormalizedName:    antreatypes.GenerateNormalizedName("nsName", pLabelSelector, nil, nil, nil),
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
				NormalizedName:    antreatypes.GenerateNormalizedName("", pLabelSelector, nLabelSelector, nil, nil),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := antreatypes.NewGroupSelector(tt.namespace, tt.podSelector, tt.nsSelector, nil, nil)
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
		name := antreatypes.GenerateNormalizedName(table.namespace, table.pSelector, table.nSelector, nil, nil)
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
	matchAllPodsPeer.AddressGroups = []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorAll, nil, nil).NormalizedName)}
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
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, &selectorB, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorC, nil, nil, nil).NormalizedName),
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
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, &selectorB, nil, nil).NormalizedName),
					getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorC, nil, nil, nil).NormalizedName),
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
			_, npc := newController(nil, nil)
			actualPeer, _ := npc.toAntreaPeer(tt.inPeers, testNPObj, tt.direction, tt.namedPortExist)
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
	selectorAll := metav1.LabelSelector{}
	matchAllPeerEgress := matchAllPeer
	matchAllPeerEgress.AddressGroups = []string{getNormalizedUID(antreatypes.NewGroupSelector("", nil, &selectorAll, nil, nil).NormalizedName)}
	tests := []struct {
		name                    string
		existingObjects         []runtime.Object
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
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
			expectedPolicy: &antreatypes.NetworkPolicy{
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
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
			expectedPolicy: &antreatypes.NetworkPolicy{
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorB, &selectorC, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorB, &selectorC, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorB, nil, nil, nil).NormalizedName)},
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
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", nil, &selectorC, nil, nil).NormalizedName)},
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
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   2,
		},
		{
			name: "rule-with-end-port",
			inputPolicy: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npG", UID: "uidG"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: selectorA,
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								{
									Protocol: &k8sProtocolTCP,
									Port:     &int1000,
									EndPort:  &int32For1999,
								},
							},
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &selectorB,
								},
							},
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidG",
				Name: "uidG",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.K8sNetworkPolicy,
					Namespace: "nsA",
					Name:      "npG",
					UID:       "uidG",
				},
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From: controlplane.NetworkPolicyPeer{
							AddressGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorB, nil, nil, nil).NormalizedName)},
						},
						Services: []controlplane.Service{
							{
								Protocol: &protocolTCP,
								Port:     &int1000,
								EndPort:  &int32For1999,
							},
						},
						Priority: defaultRulePriority,
						Action:   &defaultAction,
					},
				},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorA, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   1,
		},
		{
			name: "default-allow-ingress-enabling-logging",
			existingObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "nsA",
						Annotations: map[string]string{"networkpolicy.antrea.io/enable-logging": "true"},
					},
				},
			},
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
					Direction:     controlplane.DirectionIn,
					From:          matchAllPeer,
					Services:      nil,
					Priority:      defaultRulePriority,
					Action:        &defaultAction,
					EnableLogging: true,
				}},
				AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("nsA", &metav1.LabelSelector{}, nil, nil, nil).NormalizedName)},
			},
			expectedAppliedToGroups: 1,
			expectedAddressGroups:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(tt.existingObjects, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)

			actualPolicy, actualAppliedToGroups, actualAddressGroups := c.processNetworkPolicy(tt.inputPolicy)
			assert.Equal(t, tt.expectedPolicy, actualPolicy, "processNetworkPolicy() got unexpected result")

			if len(actualAddressGroups) != tt.expectedAddressGroups {
				t.Errorf("len(addressGroups) got %v, want %v", len(actualAddressGroups), tt.expectedAddressGroups)
			}

			if len(actualAppliedToGroups) != tt.expectedAppliedToGroups {
				t.Errorf("len(appliedToGroup) got %v, want %v", len(actualAppliedToGroups), tt.expectedAppliedToGroups)
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
				t.Errorf("podToGroupMember() got unexpected PodReference %v, want %v", *(*actualMemberPod).Pod, *(tt.expMemberPod).Pod)
			}
			// Case where the IPAddress must not be populated.
			if !tt.includeIP {
				if len(actualMemberPod.IPs) > 0 {
					t.Errorf("podToGroupMember() got unexpected IP %v, want nil", actualMemberPod.IPs)
				}
			} else if !comparePodIPs(actualMemberPod.IPs, tt.expMemberPod.IPs) {
				t.Errorf("podToGroupMember() got unexpected IP %v, want %v", actualMemberPod.IPs, tt.expMemberPod.IPs)
			}
			if !tt.namedPort {
				if len(actualMemberPod.Ports) > 0 {
					t.Errorf("podToGroupMember() got unexpected Ports %v, want []", actualMemberPod.Ports)
				}
			} else if !reflect.DeepEqual(actualMemberPod.Ports, tt.expMemberPod.Ports) {
				t.Errorf("podToGroupMember() got unexpected Ports %v, want %v", actualMemberPod.Ports, tt.expMemberPod.Ports)
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

func TestIPNetToCIDRStr(t *testing.T) {
	ipNetV4, _ := cidrStrToIPNet("10.9.8.7/6")
	ipNetV6, _ := cidrStrToIPNet("2002::1234:abcd:ffff:c0a8:101/64")
	tests := []struct {
		name string
		inC  controlplane.IPNet
		expC string
	}{
		{
			name: "ipv4-address",
			inC:  *ipNetV4,
			expC: "10.9.8.7/6",
		},
		{
			name: "ipv6-address",
			inC:  *ipNetV6,
			expC: "2002::1234:abcd:ffff:c0a8:101/64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expC, tt.inC.String())
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

func TestDeleteFinalStateUnknownNetworkPolicy(t *testing.T) {
	_, c := newController(nil, nil)
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

func TestInternalGroupKeyFunc(t *testing.T) {
	expValue := "cgA"
	cg := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uid-a"},
		Spec: v1beta1.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	actualValue := internalGroupKeyFunc(&cg)
	assert.Equal(t, expValue, actualValue)

	expValue = "nsA/gA"
	g := v1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uid-a"},
		Spec: v1beta1.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	actualValue = internalGroupKeyFunc(&g)
	assert.Equal(t, expValue, actualValue)
}

func TestGetAppliedToWorkloads(t *testing.T) {
	var emptyEEs []*v1alpha2.ExternalEntity
	var emptyPods []*corev1.Pod
	var emptyNodes []*corev1.Node
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	cgA := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorA,
		},
	}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	cgB := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorB,
		},
	}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	cgC := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorC,
		},
	}
	cgD := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorC,
		},
	}
	nestedCG1 := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nested-cg-A-B", UID: "uidE"},
		Spec: v1beta1.GroupSpec{
			ChildGroups: []v1beta1.ClusterGroupReference{"cgA", "cgB"},
		},
	}
	nestedCG2 := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nested-cg-A-C", UID: "uidF"},
		Spec: v1beta1.GroupSpec{
			ChildGroups: []v1beta1.ClusterGroupReference{"cgA", "cgC"},
		},
	}
	nestedCG3 := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nested-cg-A-C", UID: "uidG"},
		Spec: v1beta1.GroupSpec{
			ChildGroups: []v1beta1.ClusterGroupReference{"cgA", "cgC", "cgD"},
		},
	}
	podA := getPod("podA", "nsA", "nodeA", "10.0.0.1", false)
	podA.Labels = map[string]string{"foo1": "bar1"}
	podB := getPod("podB", "nsA", "nodeB", "10.0.0.2", false)
	podB.Labels = map[string]string{"foo3": "bar3"}

	selectorD := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"foo4": "bar4",
		},
	}
	nodeSelector, _ := metav1.LabelSelectorAsSelector(&selectorD)
	nodeGroup := antreatypes.GroupSelector{
		NodeSelector: nodeSelector,
	}
	nodeA := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeA",
			Labels: map[string]string{"foo4": "bar4"},
		},
	}
	nodeB := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeB",
			Labels: map[string]string{"foo5": "bar5"},
		},
	}
	tests := []struct {
		name     string
		inATG    *antreatypes.AppliedToGroup
		expPods  []*corev1.Pod
		expEEs   []*v1alpha2.ExternalEntity
		expNodes []*corev1.Node
	}{
		{
			name: "atg-for-cg",
			inATG: &antreatypes.AppliedToGroup{
				Name:        cgA.Name,
				UID:         cgA.UID,
				SourceGroup: cgA.Name,
			},
			expPods:  []*corev1.Pod{podA},
			expEEs:   emptyEEs,
			expNodes: emptyNodes,
		},
		{
			name: "atg-for-cg-no-pod-match",
			inATG: &antreatypes.AppliedToGroup{
				Name:        cgB.Name,
				UID:         cgB.UID,
				SourceGroup: cgB.Name,
			},
			expPods:  emptyPods,
			expEEs:   emptyEEs,
			expNodes: emptyNodes,
		},
		{
			name: "atg-for-nested-cg-one-child-empty",
			inATG: &antreatypes.AppliedToGroup{
				Name:        nestedCG1.Name,
				UID:         nestedCG1.UID,
				SourceGroup: nestedCG1.Name,
			},
			expPods:  []*corev1.Pod{podA},
			expEEs:   emptyEEs,
			expNodes: emptyNodes,
		},
		{
			name: "atg-for-nested-cg-both-children-match-pod",
			inATG: &antreatypes.AppliedToGroup{
				Name:        nestedCG2.Name,
				UID:         nestedCG2.UID,
				SourceGroup: nestedCG2.Name,
			},
			expPods:  []*corev1.Pod{podA, podB},
			expEEs:   emptyEEs,
			expNodes: emptyNodes,
		},
		{
			name: "atg-for-nested-cg-children-overlap-pod",
			inATG: &antreatypes.AppliedToGroup{
				Name:        nestedCG3.Name,
				UID:         nestedCG3.UID,
				SourceGroup: nestedCG3.Name,
			},
			expPods:  []*corev1.Pod{podA, podB},
			expEEs:   emptyEEs,
			expNodes: emptyNodes,
		},
		{
			name: "atg-for-node",
			inATG: &antreatypes.AppliedToGroup{
				Selector: &nodeGroup,
			},
			expPods:  emptyPods,
			expEEs:   emptyEEs,
			expNodes: []*corev1.Node{nodeA},
		},
	}
	_, c := newController([]runtime.Object{nodeA, nodeB}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.groupingInterface.AddPod(podA)
	c.groupingInterface.AddPod(podB)
	clusterGroups := []v1beta1.ClusterGroup{cgA, cgB, cgC, cgD, nestedCG1, nestedCG2}
	for i, cg := range clusterGroups {
		c.cgStore.Add(&clusterGroups[i])
		c.addClusterGroup(&clusterGroups[i])
		c.syncInternalGroup(cg.Name)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualPods, actualEEs, actualNodes, actualErr := c.getAppliedToWorkloads(tt.inATG)
			assert.NoError(t, actualErr)
			assert.Equal(t, tt.expEEs, actualEEs)
			assert.Equal(t, tt.expPods, actualPods)
			assert.Equal(t, tt.expNodes, actualNodes)
		})
	}
}

func TestGetAddressGroupMemberSet(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	cgA := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorA,
		},
	}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	cgB := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorB,
		},
	}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	cgC := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorC,
		},
	}
	cgD := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
		Spec: v1beta1.GroupSpec{
			PodSelector: &selectorC,
		},
	}
	nestedCG1 := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nested-cg-A-B", UID: "uidE"},
		Spec: v1beta1.GroupSpec{
			ChildGroups: []v1beta1.ClusterGroupReference{"cgA", "cgB"},
		},
	}
	nestedCG2 := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nested-cg-A-C", UID: "uidF"},
		Spec: v1beta1.GroupSpec{
			ChildGroups: []v1beta1.ClusterGroupReference{"cgA", "cgC"},
		},
	}
	nestedCG3 := v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "nested-cg-A-C", UID: "uidG"},
		Spec: v1beta1.GroupSpec{
			ChildGroups: []v1beta1.ClusterGroupReference{"cgA", "cgC", "cgD"},
		},
	}
	podA := getPod("podA", "nsA", "nodeA", "10.0.0.1", false)
	podA.Labels = map[string]string{"foo1": "bar1"}
	podB := getPod("podB", "nsA", "nodeB", "10.0.0.2", false)
	podB.Labels = map[string]string{"foo3": "bar3"}

	podAMemberSet := controlplane.GroupMemberSet{}
	podAMemberSet.Insert(podToGroupMember(podA, true))
	podABMemberSet := controlplane.GroupMemberSet{}
	podABMemberSet.Insert(podToGroupMember(podA, true))
	podABMemberSet.Insert(podToGroupMember(podB, true))
	tests := []struct {
		name         string
		inAddrGrp    *antreatypes.AddressGroup
		expMemberSet controlplane.GroupMemberSet
	}{
		{
			name: "addrgrp-for-cg",
			inAddrGrp: &antreatypes.AddressGroup{
				Name:        cgA.Name,
				UID:         cgA.UID,
				SourceGroup: cgA.Name,
			},
			expMemberSet: podAMemberSet,
		},
		{
			name: "addrgrp-for-cg-no-pod-match",
			inAddrGrp: &antreatypes.AddressGroup{
				Name:        cgB.Name,
				UID:         cgB.UID,
				SourceGroup: cgB.Name,
			},
			expMemberSet: controlplane.GroupMemberSet{},
		},
		{
			name: "addrgrp-for-nested-cg-one-child-empty",
			inAddrGrp: &antreatypes.AddressGroup{
				Name:        nestedCG1.Name,
				UID:         nestedCG1.UID,
				SourceGroup: nestedCG1.Name,
			},
			expMemberSet: podAMemberSet,
		},
		{
			name: "addrgrp-for-nested-cg-both-children-match-pod",
			inAddrGrp: &antreatypes.AddressGroup{
				Name:        nestedCG2.Name,
				UID:         nestedCG2.UID,
				SourceGroup: nestedCG2.Name,
			},
			expMemberSet: podABMemberSet,
		},
		{
			name: "addrgrp-for-nested-cg-children-overlap-pod",
			inAddrGrp: &antreatypes.AddressGroup{
				Name:        nestedCG3.Name,
				UID:         nestedCG3.UID,
				SourceGroup: nestedCG3.Name,
			},
			expMemberSet: podABMemberSet,
		},
	}
	_, c := newController(nil, nil)
	c.groupingInterface.AddPod(podA)
	c.groupingInterface.AddPod(podB)
	clusterGroups := []v1beta1.ClusterGroup{cgA, cgB, cgC, cgD, nestedCG1, nestedCG2}
	for i, cg := range clusterGroups {
		c.cgStore.Add(&clusterGroups[i])
		c.addClusterGroup(&clusterGroups[i])
		c.syncInternalGroup(cg.Name)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMemberSet := c.getAddressGroupMemberSet(tt.inAddrGrp)
			extraItems := actualMemberSet.Difference(tt.expMemberSet)
			missingItems := tt.expMemberSet.Difference(actualMemberSet)
			assert.Equal(t, []*controlplane.GroupMember{}, extraItems.Items())
			assert.Equal(t, []*controlplane.GroupMember{}, missingItems.Items())
		})
	}
}

func TestAddressGroupWithNodeSelector(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	_, c := newController(nil, nil)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.Start(stopCh)
	go c.groupingController.Run(stopCh)
	go c.groupingInterface.Run(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	cache.WaitForCacheSync(stopCh, c.groupingInterfaceSynced)

	nodeSelectorA := metav1.LabelSelector{MatchLabels: map[string]string{"env": "pro"}}

	fakeNode0 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeNode0"},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "1.1.1.1"}}},
	}
	fakeNode1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "fakeNode1"},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "1.1.1.2"}}},
	}

	createNode := func(node *corev1.Node) error {
		_, err := c.kubeClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		assert.Eventually(t, func() bool {
			newNode, err := c.nodeLister.Get(node.Name)
			return reflect.DeepEqual(node, newNode) && err == nil
		}, time.Second, 100*time.Millisecond)
		return nil
	}
	fakeNode0.Labels = nodeSelectorA.MatchLabels
	assert.NoError(t, createNode(fakeNode0))
	assert.NoError(t, createNode(fakeNode1))

	ag := c.createAddressGroup("", nil, nil, nil, &nodeSelectorA)
	assert.NoError(t, c.addressGroupStore.Create(ag))
	assert.NoError(t, c.syncAddressGroup(ag.Name))
	addrGroupObj, _, err := c.addressGroupStore.Get(ag.Name)
	assert.NoError(t, err)
	addrGroup := addrGroupObj.(*antreatypes.AddressGroup)
	groupMembers := addrGroup.GroupMembers
	memberNode0 := &controlplane.GroupMember{IPs: []controlplane.IPAddress{ipStrToIPAddress("1.1.1.1")}}
	memberNode1 := &controlplane.GroupMember{IPs: []controlplane.IPAddress{ipStrToIPAddress("1.1.1.2")}}
	assert.True(t, groupMembers.Has(memberNode0))
	assert.False(t, groupMembers.Has(memberNode1))
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

// TestMultipleNetworkPoliciesWithSameAppliedTo verifies NetworkPolicyController can create and delete
// InternalNetworkPolicy, AppliedToGroups and AddressGroups correctly when concurrently processing multiple
// NetworkPolicies that refer to the same groups.
func TestMultipleNetworkPoliciesWithSameAppliedTo(t *testing.T) {
	// podA and podB will be selected by the AppliedToGroup.
	podA := getPod("podA", "default", "nodeA", "10.0.0.1", false)
	podA.Labels = selectorA.MatchLabels
	podB := getPod("podB", "default", "nodeB", "10.0.1.1", false)
	podB.Labels = selectorA.MatchLabels
	// podC will be selected by the AddressGroup.
	podC := getPod("podC", "default", "nodeC", "10.0.2.1", false)
	podC.Labels = selectorB.MatchLabels
	// policyA and policyB use the same AppliedToGroup and AddressGroup.
	policyA := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "npA", UID: "uidA"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorA,
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{{PodSelector: &selectorB}},
				},
			},
		},
	}
	policyB := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "npB", UID: "uidB"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorA,
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{{PodSelector: &selectorB}},
				},
			},
		},
	}

	selectorAGroup := antreatypes.NewGroupSelector("default", &selectorA, nil, nil, nil)
	selectorAGroupUID := getNormalizedUID(selectorAGroup.NormalizedName)
	selectorBGroup := antreatypes.NewGroupSelector("default", &selectorB, nil, nil, nil)
	selectorBGroupUID := getNormalizedUID(selectorBGroup.NormalizedName)
	expectedAppliedToGroup := &antreatypes.AppliedToGroup{
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]("nodeA", "nodeB")}, // according to podA and podB
		UID:      types.UID(selectorAGroupUID),
		Name:     selectorAGroupUID,
		Selector: selectorAGroup,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{
			"nodeA": controlplane.NewGroupMemberSet(&controlplane.GroupMember{Pod: &controlplane.PodReference{
				Name:      podA.Name,
				Namespace: podA.Namespace,
			}}),
			"nodeB": controlplane.NewGroupMemberSet(&controlplane.GroupMember{Pod: &controlplane.PodReference{
				Name:      podB.Name,
				Namespace: podB.Namespace,
			}}),
		},
	}
	expectedAddressGroup := &antreatypes.AddressGroup{
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]("nodeA", "nodeB")}, // according to policyA and policyB
		UID:      types.UID(selectorBGroupUID),
		Name:     selectorBGroupUID,
		Selector: selectorBGroup,
		GroupMembers: controlplane.NewGroupMemberSet(&controlplane.GroupMember{Pod: &controlplane.PodReference{
			Name:      podC.Name,
			Namespace: podC.Namespace,
		}, IPs: []controlplane.IPAddress{ipStrToIPAddress(podC.Status.PodIP)}}),
	}
	expectedPolicyA := &antreatypes.NetworkPolicy{
		UID:      "uidA",
		Name:     "uidA",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]("nodeA", "nodeB")}, // according to AppliedToGroup
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: "default",
			Name:      "npA",
			UID:       "uidA",
		},
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{selectorBGroupUID}},
				Priority:  defaultRulePriority,
				Action:    &defaultAction,
			},
		},
		AppliedToGroups: []string{selectorAGroupUID},
	}
	expectedPolicyB := &antreatypes.NetworkPolicy{
		UID:      "uidB",
		Name:     "uidB",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]("nodeA", "nodeB")}, // according to AppliedToGroup
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: "default",
			Name:      "npB",
			UID:       "uidB",
		},
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionOut,
				To: controlplane.NetworkPolicyPeer{
					AddressGroups: []string{selectorBGroupUID},
				},
				Priority: defaultRulePriority,
				Action:   &defaultAction,
			},
		},
		AppliedToGroups: []string{selectorAGroupUID},
	}
	_, c := newController([]runtime.Object{podA, podB, podC}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	go c.groupingInterface.Run(stopCh)
	go c.groupingController.Run(stopCh)
	go c.Run(stopCh)

	c.kubeClient.NetworkingV1().NetworkPolicies(policyA.Namespace).Create(context.TODO(), policyA, metav1.CreateOptions{})
	c.kubeClient.NetworkingV1().NetworkPolicies(policyB.Namespace).Create(context.TODO(), policyB, metav1.CreateOptions{})

	checkInternalNetworkPolicyExist(t, c, expectedPolicyA)
	checkInternalNetworkPolicyExist(t, c, expectedPolicyB)
	checkAppliedToGroupExist(t, c, expectedAppliedToGroup)
	checkAddressGroupExist(t, c, expectedAddressGroup)

	c.kubeClient.NetworkingV1().NetworkPolicies(policyA.Namespace).Delete(context.TODO(), policyA.Name, metav1.DeleteOptions{})
	c.kubeClient.NetworkingV1().NetworkPolicies(policyB.Namespace).Delete(context.TODO(), policyB.Name, metav1.DeleteOptions{})

	checkInternalNetworkPolicyNotExist(t, c, expectedPolicyA)
	checkInternalNetworkPolicyNotExist(t, c, expectedPolicyB)
	checkAppliedToGroupNotExist(t, c, expectedAppliedToGroup)
	checkAddressGroupNotExist(t, c, expectedAddressGroup)
}

func checkInternalNetworkPolicyExist(t *testing.T, c *networkPolicyController, policy *antreatypes.NetworkPolicy) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		obj, exists, _ := c.internalNetworkPolicyStore.Get(string(policy.UID))
		if !assert.True(collect, exists) {
			return
		}
		assert.Equal(collect, policy, obj.(*antreatypes.NetworkPolicy))
	}, 3*time.Second, 10*time.Millisecond)
}

func checkAppliedToGroupExist(t *testing.T, c *networkPolicyController, appliedToGroup *antreatypes.AppliedToGroup) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		obj, exists, _ := c.appliedToGroupStore.Get(string(appliedToGroup.UID))
		if !assert.True(collect, exists) {
			return
		}
		assert.Equal(collect, appliedToGroup, obj.(*antreatypes.AppliedToGroup))
	}, 3*time.Second, 10*time.Millisecond)
}

func checkAddressGroupExist(t *testing.T, c *networkPolicyController, addressGroup *antreatypes.AddressGroup) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		obj, exists, _ := c.addressGroupStore.Get(string(addressGroup.UID))
		if !assert.True(collect, exists) {
			return
		}
		assert.Equal(collect, addressGroup, obj.(*antreatypes.AddressGroup))
	}, 3*time.Second, 10*time.Millisecond)
}

func checkInternalNetworkPolicyNotExist(t *testing.T, c *networkPolicyController, policy *antreatypes.NetworkPolicy) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, exists, _ := c.internalNetworkPolicyStore.Get(string(policy.UID))
		assert.False(collect, exists)
	}, 3*time.Second, 10*time.Millisecond)
}

func checkAppliedToGroupNotExist(t *testing.T, c *networkPolicyController, appliedToGroup *antreatypes.AppliedToGroup) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, exists, _ := c.appliedToGroupStore.Get(string(appliedToGroup.UID))
		assert.False(collect, exists)
	}, 3*time.Second, 10*time.Millisecond)
}

func checkAddressGroupNotExist(t *testing.T, c *networkPolicyController, addressGroup *antreatypes.AddressGroup) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, exists, _ := c.addressGroupStore.Get(string(addressGroup.UID))
		assert.False(collect, exists)
	}, 3*time.Second, 10*time.Millisecond)
}

func TestSyncInternalNetworkPolicy(t *testing.T) {
	p10 := float64(10)
	inputPolicy := &v1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnpA", UID: "uidA"},
		Spec: v1beta1.ClusterNetworkPolicySpec{
			AppliedTo: []v1beta1.AppliedTo{
				{PodSelector: &selectorA},
				{PodSelector: &selectorB},
			},
			Priority: p10,
			Ingress: []v1beta1.Rule{
				{
					From:   []v1beta1.NetworkPolicyPeer{{PodSelector: &selectorA}},
					Action: &allowAction,
				},
			},
			Egress: []v1beta1.Rule{
				{
					To:     []v1beta1.NetworkPolicyPeer{{PodSelector: &selectorB}},
					Action: &allowAction,
				},
			},
		},
	}

	selectorAGroup := getNormalizedUID(antreatypes.NewGroupSelector("", &selectorA, nil, nil, nil).NormalizedName)
	selectorBGroup := getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)
	selectorCGroup := getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, nil, nil, nil).NormalizedName)
	expectedPolicy := &antreatypes.NetworkPolicy{
		UID:      "uidA",
		Name:     "uidA",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: "cnpA",
			UID:  "uidA",
		},
		Priority:     &p10,
		TierPriority: ptr.To(v1beta1.DefaultTierPriority),
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From: controlplane.NetworkPolicyPeer{
					AddressGroups: []string{selectorAGroup},
				},
				Priority: 0,
				Action:   &allowAction,
			},
			{
				Direction: controlplane.DirectionOut,
				To: controlplane.NetworkPolicyPeer{
					AddressGroups: []string{selectorBGroup},
				},
				Priority: 0,
				Action:   &allowAction,
			},
		},
		AppliedToGroups: []string{selectorBGroup, selectorAGroup},
	}

	// Add a new policy, it should create an internal NetworkPolicy, AddressGroups and AppliedToGroups used by it.
	_, c := newController(nil, nil)
	c.acnpStore.Add(inputPolicy)
	networkPolicyRef := getACNPReference(inputPolicy)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRef))
	internalPolicies := c.internalNetworkPolicyStore.List()
	require.Len(t, internalPolicies, 1)
	actualPolicy := internalPolicies[0].(*antreatypes.NetworkPolicy)
	assert.Equal(t, expectedPolicy, actualPolicy)
	checkQueueItemExistence(t, c.addressGroupQueue, selectorAGroup, selectorBGroup)
	checkGroupItemExistence(t, c.addressGroupStore, selectorAGroup, selectorBGroup)
	checkQueueItemExistence(t, c.appliedToGroupQueue, selectorAGroup, selectorBGroup)
	checkGroupItemExistence(t, c.appliedToGroupStore, selectorAGroup, selectorBGroup)

	// Set AppliedToGroups' span, the internal NetworkPolicy should be union of them.
	appliedToGroupA, _, _ := c.appliedToGroupStore.Get(selectorAGroup)
	appliedToGroupA.(*antreatypes.AppliedToGroup).NodeNames = sets.New[string]("nodeA", "nodeB")
	appliedToGroupB, _, _ := c.appliedToGroupStore.Get(selectorBGroup)
	appliedToGroupB.(*antreatypes.AppliedToGroup).NodeNames = sets.New[string]("nodeB", "nodeC")
	expectedPolicy.NodeNames = sets.New[string]("nodeA", "nodeB", "nodeC")
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRef))
	internalPolicies = c.internalNetworkPolicyStore.List()
	require.Len(t, internalPolicies, 1)
	actualPolicy = internalPolicies[0].(*antreatypes.NetworkPolicy)
	assert.Equal(t, expectedPolicy, actualPolicy)
	// AddressGroups should be resynced while AppliedToGroups should not.
	checkQueueItemExistence(t, c.addressGroupQueue, selectorAGroup, selectorBGroup)
	checkQueueItemExistence(t, c.appliedToGroupQueue)

	// Update the original NetworkPolicy's spec, stale groups should be deleted while new groups should be created.
	updatedInputPolicy := inputPolicy.DeepCopy()
	// Change selectorA to selectorC
	updatedInputPolicy.Spec.AppliedTo[0].PodSelector = &selectorC
	updatedInputPolicy.Spec.Ingress[0].From[0].PodSelector = &selectorC
	c.acnpStore.Update(updatedInputPolicy)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRef))
	internalPolicies = c.internalNetworkPolicyStore.List()
	require.Len(t, internalPolicies, 1)
	actualPolicy = internalPolicies[0].(*antreatypes.NetworkPolicy)
	expectedPolicy.AppliedToGroups = []string{selectorCGroup, selectorBGroup}
	expectedPolicy.Rules[0].From.AddressGroups = []string{selectorCGroup}
	expectedPolicy.NodeNames = sets.New[string]("nodeC", "nodeB")
	assert.Equal(t, expectedPolicy, actualPolicy)
	checkQueueItemExistence(t, c.addressGroupQueue, selectorCGroup, selectorBGroup, selectorAGroup)
	// AddressGroup with selectA is no longer used, it should be deleted from the storage.
	checkGroupItemExistence(t, c.addressGroupStore, selectorCGroup, selectorBGroup)
	checkQueueItemExistence(t, c.appliedToGroupQueue, selectorCGroup)
	// AppliedToGroup with selectA is no longer used, it should be deleted from the storage.
	checkGroupItemExistence(t, c.appliedToGroupStore, selectorCGroup, selectorBGroup)

	// Remove the original NetworkPolicy, the internal NetworkPolicy and all AddressGroups and AppliedToGroups should be
	// removed.
	c.acnpStore.Delete(updatedInputPolicy)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRef))
	internalPolicies = c.internalNetworkPolicyStore.List()
	require.Len(t, internalPolicies, 0)
	checkQueueItemExistence(t, c.addressGroupQueue, selectorCGroup, selectorBGroup)
	checkGroupItemExistence(t, c.addressGroupStore)
	checkQueueItemExistence(t, c.appliedToGroupQueue)
	checkGroupItemExistence(t, c.appliedToGroupStore)
}

// TestSyncInternalNetworkPolicyWithSameName verifies SyncInternalNetworkPolicy can work correctly when processing
// multiple NetworkPolicies that have the same name.
func TestSyncInternalNetworkPolicyWithSameName(t *testing.T) {
	// policyA and policyB have the same name but different UIDs.
	policyA := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo", UID: "uidA"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorA,
		},
	}
	policyB := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo", UID: "uidB"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorB,
		},
	}

	selectorAGroup := getNormalizedUID(antreatypes.NewGroupSelector("default", &selectorA, nil, nil, nil).NormalizedName)
	selectorBGroup := getNormalizedUID(antreatypes.NewGroupSelector("default", &selectorB, nil, nil, nil).NormalizedName)
	expectedPolicyA := &antreatypes.NetworkPolicy{
		UID:      "uidA",
		Name:     "uidA",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: "default",
			Name:      "foo",
			UID:       "uidA",
		},
		AppliedToGroups: []string{selectorAGroup},
		Rules:           []controlplane.NetworkPolicyRule{},
	}
	expectedPolicyB := &antreatypes.NetworkPolicy{
		UID:      "uidB",
		Name:     "uidB",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: "default",
			Name:      "foo",
			UID:       "uidB",
		},
		AppliedToGroups: []string{selectorBGroup},
		Rules:           []controlplane.NetworkPolicyRule{},
	}

	// Add and sync policyA first, it should create an AppliedToGroup.
	_, c := newController(nil, nil)
	c.networkPolicyStore.Add(policyA)
	networkPolicyRefA := getKNPReference(policyA)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefA))
	obj, exists, _ := c.internalNetworkPolicyStore.Get(expectedPolicyA.Name)
	require.True(t, exists)
	assert.Equal(t, expectedPolicyA, obj.(*antreatypes.NetworkPolicy))
	checkGroupItemExistence(t, c.appliedToGroupStore, selectorAGroup)

	// Delete policyA and add policyB, then sync them concurrently, the resources associated with policyA should be deleted.
	c.networkPolicyStore.Delete(policyA)
	c.networkPolicyStore.Add(policyB)
	networkPolicyRefB := getKNPReference(policyB)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefA))
	}()
	go func() {
		defer wg.Done()
		assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefB))
	}()
	wg.Wait()
	_, exists, _ = c.internalNetworkPolicyStore.Get(expectedPolicyA.Name)
	require.False(t, exists)
	obj, exists, _ = c.internalNetworkPolicyStore.Get(expectedPolicyB.Name)
	require.True(t, exists)
	assert.Equal(t, expectedPolicyB, obj.(*antreatypes.NetworkPolicy))
	checkGroupItemExistence(t, c.appliedToGroupStore, selectorBGroup)

	// Delete policyB and sync it, the resources associated with policyB should be deleted.
	c.networkPolicyStore.Delete(policyB)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefB))
	_, exists, _ = c.internalNetworkPolicyStore.Get(expectedPolicyB.Name)
	require.False(t, exists)
	checkGroupItemExistence(t, c.appliedToGroupStore)
}

// TestSyncInternalNetworkPolicyConcurrently verifies SyncInternalNetworkPolicy can create and delete AppliedToGroups
// and AddressGroups correctly when concurrently processing multiple NetworkPolicies that refer to the same groups.
func TestSyncInternalNetworkPolicyConcurrently(t *testing.T) {
	// policyA and policyB use the same AppliedToGroup and AddressGroup.
	policyA := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "npA", UID: "uidA"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorA,
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{{PodSelector: &selectorB}},
				},
			},
		},
	}
	policyB := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "npB", UID: "uidB"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selectorA,
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{{PodSelector: &selectorB}},
				},
			},
		},
	}

	selectorAGroup := getNormalizedUID(antreatypes.NewGroupSelector("default", &selectorA, nil, nil, nil).NormalizedName)
	selectorBGroup := getNormalizedUID(antreatypes.NewGroupSelector("default", &selectorB, nil, nil, nil).NormalizedName)
	expectedPolicyA := &antreatypes.NetworkPolicy{
		UID:      "uidA",
		Name:     "uidA",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: "default",
			Name:      "npA",
			UID:       "uidA",
		},
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{selectorBGroup}},
				Priority:  defaultRulePriority,
				Action:    &defaultAction,
			},
		},
		AppliedToGroups: []string{selectorAGroup},
	}
	expectedPolicyB := &antreatypes.NetworkPolicy{
		UID:      "uidB",
		Name:     "uidB",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: "default",
			Name:      "npB",
			UID:       "uidB",
		},
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionOut,
				To: controlplane.NetworkPolicyPeer{
					AddressGroups: []string{selectorBGroup},
				},
				Priority: defaultRulePriority,
				Action:   &defaultAction,
			},
		},
		AppliedToGroups: []string{selectorAGroup},
	}

	// Add and sync policyA first, it should create an AddressGroup and AppliedToGroups.
	_, c := newController(nil, nil)
	c.networkPolicyStore.Add(policyA)
	networkPolicyRefA := getKNPReference(policyA)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefA))
	obj, exists, _ := c.internalNetworkPolicyStore.Get(expectedPolicyA.Name)
	require.True(t, exists)
	assert.Equal(t, expectedPolicyA, obj.(*antreatypes.NetworkPolicy))
	checkGroupItemExistence(t, c.appliedToGroupStore, selectorAGroup)
	checkGroupItemExistence(t, c.addressGroupStore, selectorBGroup)

	// Delete policyA and add policyB, then sync them concurrently, the groups should still exist.
	c.networkPolicyStore.Delete(policyA)
	c.networkPolicyStore.Add(policyB)
	networkPolicyRefB := getKNPReference(policyB)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefA))
	}()
	go func() {
		defer wg.Done()
		assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefB))
	}()
	wg.Wait()
	_, exists, _ = c.internalNetworkPolicyStore.Get(expectedPolicyA.Name)
	require.False(t, exists)
	obj, exists, _ = c.internalNetworkPolicyStore.Get(expectedPolicyB.Name)
	require.True(t, exists)
	assert.Equal(t, expectedPolicyB, obj.(*antreatypes.NetworkPolicy))
	checkGroupItemExistence(t, c.appliedToGroupStore, selectorAGroup)
	checkGroupItemExistence(t, c.addressGroupStore, selectorBGroup)

	// Delete policyB and sync it, the groups should be deleted.
	c.networkPolicyStore.Delete(policyB)
	assert.NoError(t, c.syncInternalNetworkPolicy(networkPolicyRefB))
	_, exists, _ = c.internalNetworkPolicyStore.Get(expectedPolicyB.Name)
	require.False(t, exists)
	checkGroupItemExistence(t, c.addressGroupStore)
	checkGroupItemExistence(t, c.appliedToGroupStore)
}

func TestSyncInternalNetworkPolicyWithGroups(t *testing.T) {
	p10 := float64(10)
	podA := getPod("podA", "nsA", "nodeA", "10.0.0.1", false)
	podA.Labels = selectorA.MatchLabels
	podB := getPod("podB", "nsB", "nodeB", "10.0.0.2", false)
	podB.Labels = selectorA.MatchLabels
	selectorBGroup := getNormalizedUID(antreatypes.NewGroupSelector("nsA", &selectorB, nil, nil, nil).NormalizedName)

	tests := []struct {
		name           string
		groups         []*v1beta1.Group
		inputPolicy    *v1beta1.NetworkPolicy
		expectedPolicy *antreatypes.NetworkPolicy
	}{
		{
			name: "annp with valid group",
			groups: []*v1beta1.Group{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "groupA"},
					Spec:       v1beta1.GroupSpec{PodSelector: &selectorA},
				},
			},
			inputPolicy: &v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "annpA", UID: "uidA"},
				Spec: v1beta1.NetworkPolicySpec{
					AppliedTo: []v1beta1.AppliedTo{
						{Group: "groupA"},
					},
					Priority: p10,
					Ingress: []v1beta1.Rule{
						{
							From:   []v1beta1.NetworkPolicyPeer{{PodSelector: &selectorB}},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:      "uidA",
				Name:     "uidA",
				SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]("nodeA")},
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "nsA",
					Name:      "annpA",
					UID:       "uidA",
				},
				Priority:     &p10,
				TierPriority: ptr.To(v1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{selectorBGroup}},
						Action:    &allowAction,
					},
				},
				AppliedToGroups: []string{"nsA/groupA"},
			},
		},
		{
			name: "annp with valid parent group",
			groups: []*v1beta1.Group{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "parentGroup"},
					Spec:       v1beta1.GroupSpec{ChildGroups: []v1beta1.ClusterGroupReference{"groupA"}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "groupA"},
					Spec:       v1beta1.GroupSpec{PodSelector: &selectorA},
				},
			},
			inputPolicy: &v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "annpA", UID: "uidA"},
				Spec: v1beta1.NetworkPolicySpec{
					AppliedTo: []v1beta1.AppliedTo{
						{Group: "parentGroup"},
					},
					Priority: p10,
					Ingress: []v1beta1.Rule{
						{
							From:   []v1beta1.NetworkPolicyPeer{{PodSelector: &selectorB}},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:      "uidA",
				Name:     "uidA",
				SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]("nodeA")},
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "nsA",
					Name:      "annpA",
					UID:       "uidA",
				},
				Priority:     &p10,
				TierPriority: ptr.To(v1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{selectorBGroup}},
						Action:    &allowAction,
					},
				},
				AppliedToGroups: []string{"nsA/parentGroup"},
			},
		},
		{
			name: "annp with invalid group selecting pods in multiple Namespaces",
			groups: []*v1beta1.Group{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "groupA"},
					Spec:       v1beta1.GroupSpec{NamespaceSelector: &metav1.LabelSelector{}, PodSelector: &selectorA},
				},
			},
			inputPolicy: &v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "annpA", UID: "uidA"},
				Spec: v1beta1.NetworkPolicySpec{
					AppliedTo: []v1beta1.AppliedTo{
						{Group: "groupA"},
					},
					Priority: p10,
					Ingress: []v1beta1.Rule{
						{
							From:   []v1beta1.NetworkPolicyPeer{{PodSelector: &selectorB}},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "nsA",
					Name:      "annpA",
					UID:       "uidA",
				},
				Priority:     &p10,
				TierPriority: ptr.To(v1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{selectorBGroup}},
						Action:    &allowAction,
					},
				},
				AppliedToGroups: []string{"nsA/groupA"},
				SyncError:       &ErrNetworkPolicyAppliedToUnsupportedGroup{groupName: "groupA", namespace: "nsA"},
			},
		},
		{
			name: "annp with invalid parent group selecting pods in multiple Namespaces",
			groups: []*v1beta1.Group{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "parentGroup"},
					Spec:       v1beta1.GroupSpec{ChildGroups: []v1beta1.ClusterGroupReference{"groupA"}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "groupA"},
					Spec:       v1beta1.GroupSpec{NamespaceSelector: &metav1.LabelSelector{}, PodSelector: &selectorA},
				},
			},
			inputPolicy: &v1beta1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "annpA", UID: "uidA"},
				Spec: v1beta1.NetworkPolicySpec{
					AppliedTo: []v1beta1.AppliedTo{
						{Group: "parentGroup"},
					},
					Priority: p10,
					Ingress: []v1beta1.Rule{
						{
							From:   []v1beta1.NetworkPolicyPeer{{PodSelector: &selectorB}},
							Action: &allowAction,
						},
					},
				},
			},
			expectedPolicy: &antreatypes.NetworkPolicy{
				UID:  "uidA",
				Name: "uidA",
				SourceRef: &controlplane.NetworkPolicyReference{
					Type:      controlplane.AntreaNetworkPolicy,
					Namespace: "nsA",
					Name:      "annpA",
					UID:       "uidA",
				},
				Priority:     &p10,
				TierPriority: ptr.To(v1beta1.DefaultTierPriority),
				Rules: []controlplane.NetworkPolicyRule{
					{
						Direction: controlplane.DirectionIn,
						From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{selectorBGroup}},
						Action:    &allowAction,
					},
				},
				AppliedToGroups: []string{"nsA/parentGroup"},
				SyncError:       &ErrNetworkPolicyAppliedToUnsupportedGroup{groupName: "parentGroup", namespace: "nsA"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController([]runtime.Object{podA, podB}, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)
			go c.groupingInterface.Run(stopCh)
			go c.groupingController.Run(stopCh)
			go c.Run(stopCh)

			for _, group := range tt.groups {
				c.crdClient.CrdV1beta1().Groups(group.Namespace).Create(context.TODO(), group, metav1.CreateOptions{})
			}
			c.crdClient.CrdV1beta1().NetworkPolicies(tt.inputPolicy.Namespace).Create(context.TODO(), tt.inputPolicy, metav1.CreateOptions{})

			var gotPolicy *antreatypes.NetworkPolicy
			err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 3*time.Second, true, func(ctx context.Context) (done bool, err error) {
				obj, exists, _ := c.internalNetworkPolicyStore.Get(tt.expectedPolicy.Name)
				if !exists {
					return false, nil
				}
				gotPolicy = obj.(*antreatypes.NetworkPolicy)
				return reflect.DeepEqual(tt.expectedPolicy, gotPolicy), nil
			})
			assert.NoError(t, err, "Expected %#v\ngot %#v", tt.expectedPolicy, gotPolicy)
		})
	}
}

func TestSyncAppliedToGroupWithExternalEntity(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"group": "appliedTo"},
	}
	tests := []struct {
		name                string
		addedExternalEntity *v1alpha2.ExternalEntity
		entityNodeKey       string
		addedInSpan         bool
	}{
		{
			name: "match-external-entity-created-by-external-node",
			addedExternalEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "entityA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       externalnode.EntityOwnerKind,
							Name:       "nodeA",
						},
					},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					ExternalNode: "nodeA",
				},
			},
			entityNodeKey: "nsA/nodeA",
			addedInSpan:   true,
		},
		{
			name: "match-external-entity-created-by-other-modules",
			addedExternalEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "entityB",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "external-modules",
							Name:       "nodeB",
						},
					},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					ExternalNode: "nodeB",
				},
			},
			entityNodeKey: "nodeB",
			addedInSpan:   true,
		},
		{
			name: "match-external-entity-not-set-external-node",
			addedExternalEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "entityA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "appliedTo"},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "external-modules",
							Name:       "nodeB",
						},
					},
				},
				Spec: v1alpha2.ExternalEntitySpec{},
			},
			entityNodeKey: "nodeB",
			addedInSpan:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			npc.groupingInterface.AddExternalEntity(tt.addedExternalEntity)
			groupSelector := antreatypes.NewGroupSelector("nsA", nil, nil, &selectorSpec, nil)
			appGroupID := getNormalizedUID(groupSelector.NormalizedName)
			appliedToGroup := &antreatypes.AppliedToGroup{
				Name:     appGroupID,
				UID:      types.UID(appGroupID),
				Selector: groupSelector,
			}
			npc.appliedToGroupStore.Create(appliedToGroup)
			npc.groupingInterface.AddGroup(appliedToGroupType, appliedToGroup.Name, appliedToGroup.Selector)
			npc.syncAppliedToGroup(appGroupID)
			appGroupObj, _, _ := npc.appliedToGroupStore.Get(appGroupID)
			appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
			entitiesAdded := appGroup.GroupMemberByNode[tt.entityNodeKey]
			if tt.addedInSpan {
				assert.Equal(t, 1, len(entitiesAdded), "expected Entity Node to add into AppliedToGroup span")
			} else {
				assert.Equal(t, 0, len(entitiesAdded), "expected Entity Node not to add into AppliedToGroup span")
			}
		})
	}
}

func TestSyncAppliedToGroupWithNode(t *testing.T) {
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"foo1": "bar1"},
	}
	nodeA := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeA",
			Labels: map[string]string{"foo1": "bar1"},
		},
	}
	nodeB := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeB",
			Labels: map[string]string{"foo1": "bar1"},
		},
	}
	nodeC := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeC",
			Labels: map[string]string{"foo2": "bar2"},
		},
	}

	_, npc := newController([]runtime.Object{nodeA, nodeB, nodeC}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.informerFactory.Start(stopCh)
	npc.informerFactory.WaitForCacheSync(stopCh)
	groupSelector := antreatypes.NewGroupSelector("", nil, nil, nil, &selector)
	appGroupID := getNormalizedUID(groupSelector.NormalizedName)
	appliedToGroup := &antreatypes.AppliedToGroup{
		Name:     appGroupID,
		UID:      types.UID(appGroupID),
		Selector: groupSelector,
	}
	npc.appliedToGroupStore.Create(appliedToGroup)
	npc.syncAppliedToGroup(appGroupID)

	expectedAppliedToGroup := &antreatypes.AppliedToGroup{
		Name:     appGroupID,
		UID:      types.UID(appGroupID),
		Selector: groupSelector,
		SpanMeta: antreatypes.SpanMeta{
			NodeNames: sets.Set[string](sets.NewString("nodeA", "nodeB")),
		},
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{
			"nodeA": controlplane.NewGroupMemberSet(&controlplane.GroupMember{
				Node: &controlplane.NodeReference{
					Name: "nodeA",
				},
			}),
			"nodeB": controlplane.NewGroupMemberSet(&controlplane.GroupMember{
				Node: &controlplane.NodeReference{
					Name: "nodeB",
				},
			}),
		},
	}
	gotAppliedToGroupObj, _, _ := npc.appliedToGroupStore.Get(appGroupID)
	gotAppliedToGroup := gotAppliedToGroupObj.(*antreatypes.AppliedToGroup)
	assert.Equal(t, expectedAppliedToGroup, gotAppliedToGroup)
}

func TestClusterNetworkPolicyWithClusterGroup(t *testing.T) {
	ctx := context.TODO()
	podA := getPod("podA", "nsA", "nodeA", "10.0.0.1", false)
	podA.Labels = map[string]string{"fooA": "barA"}
	podB := getPod("podB", "nsB", "nodeB", "10.0.0.2", false)
	podB.Labels = map[string]string{"fooB": "barB"}

	cgA := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "cgA-uid"},
		Spec:       v1beta1.GroupSpec{PodSelector: &metav1.LabelSelector{MatchLabels: podA.Labels}},
	}
	cgB := &v1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "cgB-uid"},
		Spec:       v1beta1.GroupSpec{PodSelector: &metav1.LabelSelector{MatchLabels: podB.Labels}},
	}
	acnp := &v1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "acnpA", UID: "acnpA-uid"},
		Spec: v1beta1.ClusterNetworkPolicySpec{
			AppliedTo: []v1beta1.AppliedTo{{Group: cgA.Name}},
			Priority:  10,
			Ingress: []v1beta1.Rule{
				{From: []v1beta1.NetworkPolicyPeer{{Group: cgB.Name}}, Action: &allowAction},
			},
		},
	}

	_, npc := newController([]runtime.Object{podA, podB}, []runtime.Object{cgA, cgB, acnp})
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.informerFactory.Start(stopCh)
	npc.informerFactory.WaitForCacheSync(stopCh)
	npc.crdInformerFactory.Start(stopCh)
	npc.crdInformerFactory.WaitForCacheSync(stopCh)
	go npc.Run(stopCh)
	go npc.groupingController.Run(stopCh)
	go npc.groupingInterface.Run(stopCh)

	expectedPolicy := &antreatypes.NetworkPolicy{
		SpanMeta:  antreatypes.SpanMeta{NodeNames: sets.New(podA.Spec.NodeName)},
		UID:       acnp.UID,
		Name:      string(acnp.UID),
		SourceRef: &controlplane.NetworkPolicyReference{Type: controlplane.AntreaClusterNetworkPolicy, Name: acnp.Name, UID: acnp.UID},
		Priority:  ptr.To(acnp.Spec.Priority),
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{cgB.Name}},
				Action:    &allowAction,
			},
		},
		AppliedToGroups: []string{cgA.Name},
		TierPriority:    ptr.To(v1beta1.DefaultTierPriority),
	}
	expectedAppliedToGroup := &antreatypes.AppliedToGroup{
		SpanMeta:    antreatypes.SpanMeta{NodeNames: sets.New(podA.Spec.NodeName)},
		UID:         cgA.UID,
		Name:        cgA.Name,
		SourceGroup: cgA.Name,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{
			podA.Spec.NodeName: controlplane.NewGroupMemberSet(&controlplane.GroupMember{
				Pod: &controlplane.PodReference{Name: podA.Name, Namespace: podA.Namespace},
			}),
		},
	}
	expectedAddressGroup := &antreatypes.AddressGroup{
		SpanMeta:    antreatypes.SpanMeta{NodeNames: sets.New(podA.Spec.NodeName)},
		UID:         cgB.UID,
		Name:        cgB.Name,
		SourceGroup: cgB.Name,
		GroupMembers: controlplane.NewGroupMemberSet(&controlplane.GroupMember{
			Pod: &controlplane.PodReference{Name: podB.Name, Namespace: podB.Namespace},
			IPs: []controlplane.IPAddress{ipStrToIPAddress(podB.Status.PodIP)},
		}),
	}

	checkResources := func(policy *antreatypes.NetworkPolicy, atg *antreatypes.AppliedToGroup, ag *antreatypes.AddressGroup) {
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			policies := npc.internalNetworkPolicyStore.List()
			if !assert.Len(c, policies, 1) {
				return
			}
			assert.Equal(c, policy, policies[0].(*antreatypes.NetworkPolicy))

			atgs := npc.appliedToGroupStore.List()
			if atg != nil {
				if !assert.Len(c, atgs, 1) {
					return
				}
				assert.Equal(c, atg, atgs[0].(*antreatypes.AppliedToGroup))
			} else {
				assert.Empty(c, atgs)
			}

			ags := npc.addressGroupStore.List()
			if ag != nil {
				if !assert.Len(c, ags, 1) {
					return
				}
				assert.Equal(c, ag, ags[0].(*antreatypes.AddressGroup))
			} else {
				assert.Empty(c, ags)
			}
		}, 2*time.Second, 50*time.Millisecond)
	}
	checkResources(expectedPolicy, expectedAppliedToGroup, expectedAddressGroup)

	// Delete the ClusterGroup used by the AddressGroup, the AddressGroup should be deleted, the rule's peer should be empty.
	npc.crdClient.CrdV1beta1().ClusterGroups().Delete(ctx, cgB.Name, metav1.DeleteOptions{})
	expectedPolicy2 := &antreatypes.NetworkPolicy{
		SpanMeta:  antreatypes.SpanMeta{NodeNames: sets.New(podA.Spec.NodeName)},
		UID:       acnp.UID,
		Name:      string(acnp.UID),
		SourceRef: &controlplane.NetworkPolicyReference{Type: controlplane.AntreaClusterNetworkPolicy, Name: acnp.Name, UID: acnp.UID},
		Priority:  ptr.To(acnp.Spec.Priority),
		Rules: []controlplane.NetworkPolicyRule{
			{Direction: controlplane.DirectionIn, Action: &allowAction},
		},
		AppliedToGroups: []string{cgA.Name},
		TierPriority:    ptr.To(v1beta1.DefaultTierPriority),
	}
	checkResources(expectedPolicy2, expectedAppliedToGroup, nil)

	// Delete the ClusterGroup used by the AppliedToGroup, the AppliedToGroup should be deleted, the policy's span and
	// appliedToGroup should be empty.
	npc.crdClient.CrdV1beta1().ClusterGroups().Delete(ctx, cgA.Name, metav1.DeleteOptions{})
	expectedPolicy3 := &antreatypes.NetworkPolicy{
		SpanMeta:  antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		UID:       acnp.UID,
		Name:      string(acnp.UID),
		SourceRef: &controlplane.NetworkPolicyReference{Type: controlplane.AntreaClusterNetworkPolicy, Name: acnp.Name, UID: acnp.UID},
		Priority:  ptr.To(acnp.Spec.Priority),
		Rules: []controlplane.NetworkPolicyRule{
			{Direction: controlplane.DirectionIn, Action: &allowAction},
		},
		AppliedToGroups: []string{},
		TierPriority:    ptr.To(v1beta1.DefaultTierPriority),
	}
	checkResources(expectedPolicy3, nil, nil)

	// Recreate the ClusterGroups, everything should be restored.
	npc.crdClient.CrdV1beta1().ClusterGroups().Create(ctx, cgA, metav1.CreateOptions{})
	npc.crdClient.CrdV1beta1().ClusterGroups().Create(ctx, cgB, metav1.CreateOptions{})
	checkResources(expectedPolicy, expectedAppliedToGroup, expectedAddressGroup)
}

func checkQueueItemExistence(t *testing.T, queue workqueue.RateLimitingInterface, items ...string) {
	require.Equal(t, len(items), queue.Len())
	expectedItems := sets.New[string](items...)
	actualItems := sets.New[string]()
	for i := 0; i < len(expectedItems); i++ {
		key, _ := queue.Get()
		actualItems.Insert(key.(string))
		queue.Done(key)
	}
	assert.Equal(t, expectedItems, actualItems)
}

func checkGroupItemExistence(t *testing.T, store storage.Interface, groups ...string) {
	assert.Len(t, store.List(), len(groups))
	for _, group := range groups {
		_, exists, _ := store.Get(group)
		assert.True(t, exists)
	}
}

func TestNodeToGroupMember(t *testing.T) {
	tests := []struct {
		name                string
		node                *corev1.Node
		includeIP           bool
		expectedGroupMember *controlplane.GroupMember
	}{
		{
			name: "node-to-group-member-with-ip",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
				Spec: corev1.NodeSpec{
					PodCIDR: "172.16.10.0/24",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.1.2",
						},
					},
				},
			},
			includeIP: true,
			expectedGroupMember: &controlplane.GroupMember{
				Node: &controlplane.NodeReference{
					Name: "node1",
				},
				IPs: []controlplane.IPAddress{
					ipStrToIPAddress("192.168.1.2"),
					ipStrToIPAddress("172.16.10.1"),
				},
			},
		},
		{
			name: "node-to-group-member-without-ip",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
				Spec: corev1.NodeSpec{
					PodCIDR: "172.16.11.0/24",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "192.168.1.3",
						},
					},
				},
			},
			includeIP: false,
			expectedGroupMember: &controlplane.GroupMember{
				Node: &controlplane.NodeReference{
					Name: "node2",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMember := nodeToGroupMember(tt.node, tt.includeIP)
			assert.Equal(t, tt.expectedGroupMember.Node, gotMember.Node)
			assert.ElementsMatch(t, tt.expectedGroupMember.IPs, gotMember.IPs)
		})
	}
}
