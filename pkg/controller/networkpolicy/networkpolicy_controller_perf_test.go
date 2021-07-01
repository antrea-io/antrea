// +build !race

// Copyright 2020 Antrea Authors
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
	"flag"
	"fmt"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

var (
	allowAction = v1alpha1.RuleActionAllow
	dropAction  = v1alpha1.RuleActionDrop
)

/*
TestInitXLargeScaleWithSmallNamespaces* tests the execution time and the memory usage of computing a scale
of 25k Namespaces, 75k NetworkPolicies, 100k Pods. 4 Pods per namespace. The reference value is:

NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
25000        100000  75000                  0                          0                        1.84       1368         26715         1716 1717 1716
25000        100000  75000                  0                          0                        1.13       1319         27247         2248 2249 2248
25000        100000  75000                  0                          0                        2.89       1411         100000        75001 75001 75001
25000        100000  75000                  0                          0                        3.07       1412         100000        75001 75001 75001

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithSmallNamespaces(t *testing.T) {
	namespaces, k8sNPs, pods := getXLargeScaleWithSmallNamespaces()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, k8sNPs, nil, nil, pods)
}

func getXLargeScaleWithSmallNamespaces() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		label1 := map[string]string{"app-1": "scale-1"}
		label2 := map[string]string{"app-2": "scale-2"}
		k8sNPs := []*networkingv1.NetworkPolicy{
			newNetworkPolicy(namespace, "default-deny-all", nil, nil, nil, nil, nil),
			newNetworkPolicy(namespace, "np-1", label1, label1, nil, nil, nil),
			newNetworkPolicy(namespace, "np-2", label2, label2, nil, nil, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "pod1", label1),
			newPod(namespace, "pod2", label1),
			newPod(namespace, "pod3", label2),
			newPod(namespace, "pod4", label2),
		}
		return namespaces, k8sNPs, pods
	}
	namespaces, k8sNPs, pods := getXObjects(25000, getObjects)
	return namespaces, k8sNPs, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
25000        100000  0                      75000                      0                        2.48       1145         100000        75001 3 75001
*/
func TestInitXLargeScaleWithSmallNamespacesACNP(t *testing.T) {
	namespaces, acnps, pods := getXLargeScaleWithSmallNamespacesACNP()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, nil, acnps, nil, pods)
}

func getXLargeScaleWithSmallNamespacesACNP() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		label1 := map[string]string{"app-1": "scale-1"}
		label2 := map[string]string{"app-2": "scale-2"}
		acnps := []*v1alpha1.ClusterNetworkPolicy{
			newClusterNetworkPolicy("default-deny-all", "", 0, nil, nil, nil, &dropAction, nil),
			newClusterNetworkPolicy("np-1", "", 1, newCRDsPeer(label1, nil), newCRDsPeer(label1, nil), nil, &allowAction, nil),
			newClusterNetworkPolicy("np-2", "", 1, newCRDsPeer(label2, nil), newCRDsPeer(label2, nil), nil, &allowAction, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "pod1", label1),
			newPod(namespace, "pod2", label1),
			newPod(namespace, "pod3", label2),
			newPod(namespace, "pod4", label2),
		}
		return namespaces, acnps, pods
	}
	namespaces, acnps, pods := getXObjectsACNP(25000, getObjects)
	return namespaces, acnps, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
25000        100000  0                      0                          75000                    2.92       1311         100000        75001 50001 75001
*/
func TestInitXLargeScaleWithSmallNamespacesANP(t *testing.T) {
	namespaces, anps, pods := getXLargeScaleWithSmallNamespacesANP()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, nil, nil, anps, pods)
}

func getXLargeScaleWithSmallNamespacesANP() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		label1 := map[string]string{"app-1": "scale-1"}
		label2 := map[string]string{"app-2": "scale-2"}
		anps := []*v1alpha1.NetworkPolicy{
			newAntreaNetworkPolicy(namespace, "default-deny-all", "", 0, nil, nil, nil, &dropAction, nil),
			newAntreaNetworkPolicy(namespace, "np-1", "", 1, newCRDsPeer(label1, nil), newCRDsPeer(label1, nil), nil, &allowAction, nil),
			newAntreaNetworkPolicy(namespace, "np-2", "", 1, newCRDsPeer(label2, nil), newCRDsPeer(label2, nil), nil, &allowAction, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "pod1", label1),
			newPod(namespace, "pod2", label1),
			newPod(namespace, "pod3", label2),
			newPod(namespace, "pod4", label2),
		}
		return namespaces, anps, pods
	}
	namespaces, anps, pods := getXObjectsANP(25000, getObjects)
	return namespaces, anps, pods
}

/*
TestInitXLargeScaleWithLargeNamespaces* tests the execution time and the memory usage of computing a scale
of 100 Namespaces, 1.01k NetworkPolicies, 100k Pods. 100 Pods per namespace. The reference value is:

NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
100          100000  10100                  0                          0                        0.53       1084         10200         10101 10101 10101
*/
func TestInitXLargeScaleWithLargeNamespaces(t *testing.T) {
	namespaces, k8sNPs, pods := getXLargeScaleWithLargeNamespaces()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, k8sNPs, nil, nil, pods)
}

func getXLargeScaleWithLargeNamespaces() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{
			newNamespace(namespace, map[string]string{"app": namespace}),
		}
		k8sNPs := []*networkingv1.NetworkPolicy{
			newNetworkPolicy(namespace, "default-deny-all", nil, nil, nil, nil, nil),
		}
		var pods []*corev1.Pod
		for i := 0; i < 100; i++ {
			labels := map[string]string{fmt.Sprintf("app-%d", i): fmt.Sprintf("scale-%d", i)}
			k8sNPs = append(k8sNPs, newNetworkPolicy(namespace, fmt.Sprintf("np-%d", i), labels, labels, nil, nil, nil))
			for j := 0; j < 10; j++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", i, j), labels))
			}
		}
		return namespaces, k8sNPs, pods
	}
	namespaces, k8sNPs, pods := getXObjects(100, getObjects)
	return namespaces, k8sNPs, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
100          100000  0                      10100                      0                        1.68       707          10200         10101 101 10101
*/
func TestInitXLargeScaleWithLargeNamespacesACNP(t *testing.T) {
	namespaces, acnps, pods := getXLargeScaleWithLargeNamespacesACNP()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, nil, acnps, nil, pods)
}

func getXLargeScaleWithLargeNamespacesACNP() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{
			newNamespace(namespace, map[string]string{"app": namespace}),
		}
		acnps := []*v1alpha1.ClusterNetworkPolicy{
			newClusterNetworkPolicy("default-deny-all", "", 0, nil, nil, nil, &dropAction, nil),
		}
		var pods []*corev1.Pod
		for i := 0; i < 100; i++ {
			labels := map[string]string{fmt.Sprintf("app-%d", i): fmt.Sprintf("scale-%d", i)}
			acnps = append(acnps, newClusterNetworkPolicy(fmt.Sprintf("np-%d", i), "", 1, newCRDsPeer(labels, nil), newCRDsPeer(labels, nil), nil, &allowAction, nil))
			for j := 0; j < 10; j++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", i, j), labels))
			}
		}
		return namespaces, acnps, pods
	}
	namespaces, acnps, pods := getXObjectsACNP(100, getObjects)
	return namespaces, acnps, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
100          100000  0                      0                          10100                    1.81       910          10200         10101 10001 10101
*/
func TestInitXLargeScaleWithLargeNamespacesANP(t *testing.T) {
	namespaces, anps, pods := getXLargeScaleWithLargeNamespacesANP()
	testComputeNetworkPolicy(t, 10*time.Second, namespaces, nil, nil, anps, pods)
}

func getXLargeScaleWithLargeNamespacesANP() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
		namespace := rand.String(8)
		namespaces := []*corev1.Namespace{
			newNamespace(namespace, map[string]string{"app": namespace}),
		}
		anps := []*v1alpha1.NetworkPolicy{
			newAntreaNetworkPolicy(namespace, "default-deny-all", "", 0, nil, nil, nil, &dropAction, nil),
		}
		var pods []*corev1.Pod
		for i := 0; i < 100; i++ {
			labels := map[string]string{fmt.Sprintf("app-%d", i): fmt.Sprintf("scale-%d", i)}
			anps = append(anps, newAntreaNetworkPolicy(namespace, fmt.Sprintf("np-%d", i), "", 1, newCRDsPeer(labels, nil), newCRDsPeer(labels, nil), nil, &allowAction, nil))
			for j := 0; j < 10; j++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", i, j), labels))
			}
		}
		return namespaces, anps, pods
	}
	namespaces, anps, pods := getXObjectsANP(100, getObjects)
	return namespaces, anps, pods
}

/*
TestInitXLargeScaleWithOneNamespaces* tests the execution time and the memory usage of computing a scale
of 1 Namespaces, 10k NetworkPolicies, 10k Pods where each network policy selects each pod (applied + ingress).

NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   10000                  0                          0                        0.24       100          10001         10001 2 10001

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithOneNamespace(t *testing.T) {
	namespaces, k8sNPs, pods := getXLargeScaleWithOneNamespace()
	testComputeNetworkPolicy(t, 15*time.Second, namespaces, k8sNPs, nil, nil, pods)
}

func getXLargeScaleWithOneNamespace() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		label := map[string]string{"app-1": "scale-1"}
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		k8sNPs := []*networkingv1.NetworkPolicy{newNetworkPolicy(namespace, "", label, label, nil, nil, nil)}
		pods := []*corev1.Pod{newPod(namespace, "", label)}
		return namespaces, k8sNPs, pods
	}
	namespaces, k8sNPs, pods := getXObjects(10000, getObjects)
	return namespaces[0:1], k8sNPs, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   0                      10000                      0                        0.31       107          10001         10001 2 10001
*/
func TestInitXLargeScaleWithOneNamespaceACNP(t *testing.T) {
	namespaces, acnps, pods := getXLargeScaleWithOneNamespaceACNP()
	testComputeNetworkPolicy(t, 15*time.Second, namespaces, nil, acnps, nil, pods)
}

func getXLargeScaleWithOneNamespaceACNP() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
		label := map[string]string{"app-1": "scale-1"}
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		acnps := []*v1alpha1.ClusterNetworkPolicy{newClusterNetworkPolicy("", "", 0, newCRDsPeer(label, nil), newCRDsPeer(label, nil), nil, &allowAction, nil)}
		pods := []*corev1.Pod{newPod(namespace, "", label)}
		return namespaces, acnps, pods
	}
	namespaces, acnps, pods := getXObjectsACNP(10000, getObjects)
	return namespaces[0:1], acnps, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   0                      0                          10000                    0.31       105          10001         10001 2 10001
*/
func TestInitXLargeScaleWithOneNamespaceANP(t *testing.T) {
	namespaces, anps, pods := getXLargeScaleWithOneNamespaceANP()
	testComputeNetworkPolicy(t, 15*time.Second, namespaces, nil, nil, anps, pods)
}

func getXLargeScaleWithOneNamespaceANP() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
		label := map[string]string{"app-1": "scale-1"}
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		anps := []*v1alpha1.NetworkPolicy{newAntreaNetworkPolicy(namespace, "", "", 0, newCRDsPeer(label, nil), newCRDsPeer(label, nil), nil, &allowAction, nil)}
		pods := []*corev1.Pod{newPod(namespace, "", label)}
		return namespaces, anps, pods
	}
	namespaces, anps, pods := getXObjectsANP(10000, getObjects)
	return namespaces[0:1], anps, pods
}

/*
TestInitXLargeScaleWithNetpolPerPod* tests the execution time and the memory usage of computing a scale
of 1 Namespace, 10k Pods, 10k NetworkPolicies. 1 NP per Pod, with one ingress rule. The reference value is:

NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   10000                  0                          0                        1.86       169          3281          3281 3282 3281
1            10000   10000                  0                          0                        2.20       170          2958          2958 2959 2958
1            10000   10000                  0                          0                        19.90      198          10001         10001 10001 10001
1            10000   10000                  0                          0                        24.97      185          10001         10001 10001 10001

The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithNetpolPerPod(t *testing.T) {
	namespaces, k8sNPs, pods := getXLargeScaleWithNetpolPerPod()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces[0:1], k8sNPs, nil, nil, pods)
}

func getXLargeScaleWithNetpolPerPod() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		app1 := rand.String(8)
		labels1 := map[string]string{"app": fmt.Sprintf("scale-%v", app1)}
		app2 := rand.String(8)
		labels2 := map[string]string{"app": fmt.Sprintf("scale-%v", app2)}
		k8sNPs := []*networkingv1.NetworkPolicy{
			newNetworkPolicy(namespace, "", labels1, labels2, nil, nil, nil),
			newNetworkPolicy(namespace, "", labels2, labels1, nil, nil, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "", labels1),
			newPod(namespace, "", labels2),
		}
		return namespaces, k8sNPs, pods
	}
	namespaces, k8sNPs, pods := getXObjects(5000, getObjects)
	return namespaces[0:1], k8sNPs, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   0                      10000                      0                        18.51      113          10001         10001 10001 10001
*/
func TestInitXLargeScaleWithNetpolPerPodACNP(t *testing.T) {
	namespaces, acnps, pods := getXLargeScaleWithNetpolPerPodACNP()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces[0:1], nil, acnps, nil, pods)
}

func getXLargeScaleWithNetpolPerPodACNP() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		app1 := rand.String(8)
		labels1 := map[string]string{"app": fmt.Sprintf("scale-%v", app1)}
		app2 := rand.String(8)
		labels2 := map[string]string{"app": fmt.Sprintf("scale-%v", app2)}
		acnps := []*v1alpha1.ClusterNetworkPolicy{
			newClusterNetworkPolicy("", "", 0, newCRDsPeer(labels1, nil), newCRDsPeer(labels2, nil), nil, &allowAction, nil),
			newClusterNetworkPolicy("", "", 0, newCRDsPeer(labels2, nil), newCRDsPeer(labels1, nil), nil, &allowAction, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "", labels1),
			newPod(namespace, "", labels2),
		}
		return namespaces, acnps, pods
	}
	namespaces, acnps, pods := getXObjectsACNP(5000, getObjects)
	return namespaces[0:1], acnps, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1            10000   0                      0                          10000                    21.79      113          10001         10001 10001 10001
*/
func TestInitXLargeScaleWithNetpolPerPodANP(t *testing.T) {
	namespaces, anps, pods := getXLargeScaleWithNetpolPerPodANP()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces[0:1], nil, nil, anps, pods)
}

func getXLargeScaleWithNetpolPerPodANP() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
	namespace := rand.String(8)
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
		namespaces := []*corev1.Namespace{newNamespace(namespace, map[string]string{"app": namespace})}
		app1 := rand.String(8)
		labels1 := map[string]string{"app": fmt.Sprintf("scale-%v", app1)}
		app2 := rand.String(8)
		labels2 := map[string]string{"app": fmt.Sprintf("scale-%v", app2)}
		anps := []*v1alpha1.NetworkPolicy{
			newAntreaNetworkPolicy(namespace, "", "", 0, newCRDsPeer(labels1, nil), newCRDsPeer(labels2, nil), nil, &allowAction, nil),
			newAntreaNetworkPolicy(namespace, "", "", 0, newCRDsPeer(labels2, nil), newCRDsPeer(labels1, nil), nil, &allowAction, nil),
		}
		pods := []*corev1.Pod{
			newPod(namespace, "", labels1),
			newPod(namespace, "", labels2),
		}
		return namespaces, anps, pods
	}
	namespaces, anps, pods := getXObjectsANP(5000, getObjects)
	return namespaces[0:1], anps, pods
}

/*
TestInitXLargeScaleWithClusterScopedNetpol* tests the execution time and the memory usage of computing a scale
of 1k Namespace, 100k Pods, 10k NetworkPolicies.
- 100 Pods, 10 NetworkPolicies per Namespace
- Each NetworkPolicy selects 100 Pods from 10 Namespaces as peers.
The reference value is:

NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1000         100000  10000                  0                          0                        0.85       903          11000         10001 10001 10001


The metrics are not accurate under the race detector, and will be skipped when testing with "-race".
*/
func TestInitXLargeScaleWithClusterScopedNetpol(t *testing.T) {
	namespaces, k8sNPs, pods := getXLargeScaleWithClusterScopedNetpol()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces, k8sNPs, nil, nil, pods)
}

func getXLargeScaleWithClusterScopedNetpol() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	i := 0
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		// There are 100 different namespace labels in total.
		company := fmt.Sprintf("company-%d", i%100)
		i += 1
		namespace := fmt.Sprintf("%v-%v", company, rand.String(8))
		namespaceLabels := map[string]string{"company": company}
		namespaces := []*corev1.Namespace{newNamespace(namespace, namespaceLabels)}
		var k8sNPs []*networkingv1.NetworkPolicy
		var pods []*corev1.Pod
		for j := 0; j < 10; j++ {
			labels := map[string]string{"app": fmt.Sprintf("scale-%d", j)}
			k8sNPs = append(k8sNPs, newNetworkPolicy(namespace, fmt.Sprintf("np-%d", j), labels, labels, namespaceLabels, nil, nil))
			for k := 0; k < 10; k++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", j, k), labels))
			}
		}
		return namespaces, k8sNPs, pods
	}
	namespaces, k8sNPs, pods := getXObjects(1000, getObjects)
	return namespaces, k8sNPs, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1000         100000  0                      10000                      0                        1.48       598          11000         10001 11 10001
*/
func TestInitXLargeScaleWithClusterScopedNetpolACNP(t *testing.T) {
	namespaces, acnps, pods := getXLargeScaleWithClusterScopedNetpolACNP()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces, nil, acnps, nil, pods)
}

func getXLargeScaleWithClusterScopedNetpolACNP() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
	i := 0
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
		// There are 100 different namespace labels in total.
		company := fmt.Sprintf("company-%d", i%100)
		i += 1
		namespace := fmt.Sprintf("%v-%v", company, rand.String(8))
		namespaceLabels := map[string]string{"company": company}
		namespaces := []*corev1.Namespace{newNamespace(namespace, namespaceLabels)}
		var acnps []*v1alpha1.ClusterNetworkPolicy
		var pods []*corev1.Pod
		for j := 0; j < 10; j++ {
			labels := map[string]string{"app": fmt.Sprintf("scale-%d", j)}
			acnps = append(acnps, newClusterNetworkPolicy(fmt.Sprintf("np-%d", j), "", 0, newCRDsPeer(labels, nil), newCRDsPeer(labels, namespaceLabels), nil, &allowAction, nil))
			for k := 0; k < 10; k++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", j, k), labels))
			}
		}
		return namespaces, acnps, pods
	}
	namespaces, acnps, pods := getXObjectsACNP(1000, getObjects)
	return namespaces, acnps, pods
}

/*
The reference value is:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
1000         100000  0                      0                          10000                    1.79       908          11000         10001 10001 10001
*/
func TestInitXLargeScaleWithClusterScopedNetpolANP(t *testing.T) {
	namespaces, anps, pods := getXLargeScaleWithClusterScopedNetpolANP()
	testComputeNetworkPolicy(t, 300*time.Second, namespaces, nil, nil, anps, pods)
}

func getXLargeScaleWithClusterScopedNetpolANP() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
	i := 0
	getObjects := func() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
		// There are 100 different namespace labels in total.
		company := fmt.Sprintf("company-%d", i%100)
		i += 1
		namespace := fmt.Sprintf("%v-%v", company, rand.String(8))
		namespaceLabels := map[string]string{"company": company}
		namespaces := []*corev1.Namespace{newNamespace(namespace, namespaceLabels)}
		var anps []*v1alpha1.NetworkPolicy
		var pods []*corev1.Pod
		for j := 0; j < 10; j++ {
			labels := map[string]string{"app": fmt.Sprintf("scale-%d", j)}
			anps = append(anps, newAntreaNetworkPolicy(namespace, fmt.Sprintf("np-%d", j), "", 0, newCRDsPeer(labels, nil), newCRDsPeer(labels, namespaceLabels), nil, &allowAction, nil))
			for k := 0; k < 10; k++ {
				pods = append(pods, newPod(namespace, fmt.Sprintf("pod-%d-%d", j, k), labels))
			}
		}
		return namespaces, anps, pods
	}
	namespaces, anps, pods := getXObjectsANP(1000, getObjects)
	return namespaces, anps, pods
}

func testComputeNetworkPolicy(t *testing.T, maxExecutionTime time.Duration, namespaces []*corev1.Namespace, k8sNPs []*networkingv1.NetworkPolicy, acnps []*v1alpha1.ClusterNetworkPolicy, anps []*v1alpha1.NetworkPolicy, pods []*corev1.Pod) {
	disableLogToStderr()

	objs := toRunTimeObjects(namespaces, k8sNPs, pods)
	_, c := newController(objs...)
	c.heartbeatCh = make(chan heartbeat, 1000)

	stopCh := make(chan struct{})

	// executionMetric is used to count the executions of each routine and to record the last execution time.
	type executionMetric struct {
		executions    int
		lastExecution time.Time
	}
	executionMetrics := map[string]*executionMetric{}

	// If we don't receive any heartbeat from NetworkPolicyController for 3 seconds, it means all computation
	// finished 3 seconds ago.
	idleTimeout := 3 * time.Second
	timer := time.NewTimer(idleTimeout)
	go func() {
		for {
			timer.Reset(idleTimeout)
			select {
			case heartbeat := <-c.heartbeatCh:
				m, ok := executionMetrics[heartbeat.name]
				if !ok {
					m = &executionMetric{}
					executionMetrics[heartbeat.name] = m
				}
				m.executions++
				m.lastExecution = heartbeat.timestamp
			case <-timer.C:
				// Send the stop signal if we don't receive any heartbeat for 3 seconds.
				close(stopCh)
				return
			}
		}
	}()

	var wg sync.WaitGroup

	// Stat how many events we will get during the computation.
	var addressGroupEvents, appliedToGroupEvents, networkPolicyEvents int32
	wg.Add(1)
	go func() {
		statEvents(c, &addressGroupEvents, &appliedToGroupEvents, &networkPolicyEvents, stopCh)
		wg.Done()
	}()

	// Stat the maximum heap allocation.
	var maxAlloc uint64
	wg.Add(1)
	go func() {
		statMaxMemAlloc(&maxAlloc, 500*time.Millisecond, stopCh)
		wg.Done()
	}()

	// Everything is ready, now start timing.
	start := time.Now()
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	go c.groupingController.Run(stopCh)
	go c.Run(stopCh)

	for _, acnp := range acnps {
		c.addACNP(acnp)
	}
	for _, anp := range anps {
		c.addANP(anp)
	}

	// Block until all computation is done.
	<-stopCh
	// Minus the idle time to get the actual execution time.
	executionTime := time.Since(start) - idleTimeout
	if executionTime > maxExecutionTime {
		t.Errorf("The actual execution time %v is greater than the maximum value %v", executionTime, maxExecutionTime)
	}
	totalExecution := 0
	for name, m := range executionMetrics {
		t.Logf("Execution metrics of %s, executions: %d, duration: %v", name, m.executions, m.lastExecution.Sub(start))
		totalExecution += m.executions
	}

	// Block until all statistics are done.
	wg.Wait()

	t.Logf(`Summary metrics:
NAMESPACES   PODS    K8s-NETWORK-POLICIES   CLUSTER-NETWORK-POLICIES   ANTREA-NETWORK-POLICES   TIME(s)    MEMORY(M)    EXECUTIONS    EVENTS(ag, atg, np)
%-12d %-7d %-22d %-26d %-24d %-10.2f %-12d %-13d %d %d %d
`, len(namespaces), len(pods), len(k8sNPs), len(acnps), len(anps), float64(executionTime)/float64(time.Second), maxAlloc/1024/1024, totalExecution, networkPolicyEvents, appliedToGroupEvents, networkPolicyEvents)
}

func statEvents(c *networkPolicyController, addressGroupEvents, appliedToGroupEvents, networkPolicyEvents *int32, stopCh chan struct{}) {
	addressGroupWatcher, _ := c.addressGroupStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	appliedToGroupWatcher, _ := c.appliedToGroupStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	networkPolicyWatcher, _ := c.internalNetworkPolicyStore.Watch(context.Background(), "", labels.Everything(), fields.Everything())
	for {
		select {
		case <-addressGroupWatcher.ResultChan():
			*addressGroupEvents++
		case <-appliedToGroupWatcher.ResultChan():
			*appliedToGroupEvents++
		case <-networkPolicyWatcher.ResultChan():
			*networkPolicyEvents++
		case <-stopCh:
			return
		}
	}
}

func statMaxMemAlloc(maxAlloc *uint64, interval time.Duration, stopCh chan struct{}) {
	var memStats goruntime.MemStats
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			goruntime.ReadMemStats(&memStats)
			if memStats.Alloc > *maxAlloc {
				*maxAlloc = memStats.Alloc
			}
		case <-stopCh:
			return
		}
	}
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func getRandomNodeName() string {
	return fmt.Sprintf("Node-%d", rand.Intn(1000))
}

// getXObjects calls the provided getObjectsFunc x times and aggregate the objects.
func getXObjects(x int, getObjectsFunc func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod)) ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
	var namespaces []*corev1.Namespace
	var networkPolicies []*networkingv1.NetworkPolicy
	var pods []*corev1.Pod
	for i := 0; i < x; i++ {
		newNamespaces, newNetworkPolicies, newPods := getObjectsFunc()
		namespaces = append(namespaces, newNamespaces...)
		networkPolicies = append(networkPolicies, newNetworkPolicies...)
		pods = append(pods, newPods...)
	}
	return namespaces, networkPolicies, pods
}

// getXObjectsACNP calls the provided getObjectsFunc x times and aggregate the objects.
func getXObjectsACNP(x int, getObjectsFunc func() ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod)) ([]*corev1.Namespace, []*v1alpha1.ClusterNetworkPolicy, []*corev1.Pod) {
	var namespaces []*corev1.Namespace
	var clusterNetworkPolicies []*v1alpha1.ClusterNetworkPolicy
	var pods []*corev1.Pod
	for i := 0; i < x; i++ {
		newNamespaces, newClusterNetworkPolicies, newPods := getObjectsFunc()
		namespaces = append(namespaces, newNamespaces...)
		clusterNetworkPolicies = append(clusterNetworkPolicies, newClusterNetworkPolicies...)
		pods = append(pods, newPods...)
	}
	return namespaces, clusterNetworkPolicies, pods
}

// getXObjectsANP calls the provided getObjectsFunc x times and aggregate the objects.
func getXObjectsANP(x int, getObjectsFunc func() ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod)) ([]*corev1.Namespace, []*v1alpha1.NetworkPolicy, []*corev1.Pod) {
	var namespaces []*corev1.Namespace
	var antreaNetworkPolicies []*v1alpha1.NetworkPolicy
	var pods []*corev1.Pod
	for i := 0; i < x; i++ {
		newNamespaces, newAntreaNetworkPolicies, newPods := getObjectsFunc()
		namespaces = append(namespaces, newNamespaces...)
		antreaNetworkPolicies = append(antreaNetworkPolicies, newAntreaNetworkPolicies...)
		pods = append(pods, newPods...)
	}
	return namespaces, antreaNetworkPolicies, pods
}

func toRunTimeObjects(namespaces []*corev1.Namespace, networkPolicies []*networkingv1.NetworkPolicy, pods []*corev1.Pod) []runtime.Object {
	objs := make([]runtime.Object, 0, len(namespaces)+len(networkPolicies)+len(pods))
	for i := range namespaces {
		objs = append(objs, namespaces[i])
	}
	for i := range networkPolicies {
		objs = append(objs, networkPolicies[i])
	}
	for i := range pods {
		objs = append(objs, pods[i])
	}
	return objs
}

func newNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
}

func newPod(namespace, name string, labels map[string]string) *corev1.Pod {
	if name == "" {
		name = "pod-" + rand.String(8)
	}
	podIP := getRandomIP()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String()), Labels: labels},
		Spec: corev1.PodSpec{
			NodeName:    getRandomNodeName(),
			HostNetwork: false,
		},
		Status: corev1.PodStatus{PodIP: podIP, PodIPs: []corev1.PodIP{{IP: podIP}}},
	}
	return pod
}

func newNetworkPolicy(namespace, name string, podSelector, ingressPodSelector, ingressNamespaceSelector, egressPodSelector, egressNamespaceSelector map[string]string) *networkingv1.NetworkPolicy {
	if name == "" {
		name = "np-" + rand.String(8)
	}
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String())},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podSelector},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
	if ingressPodSelector != nil || ingressNamespaceSelector != nil {
		peer := networkingv1.NetworkPolicyPeer{}
		if ingressPodSelector != nil {
			peer.PodSelector = &metav1.LabelSelector{MatchLabels: ingressPodSelector}
		}
		if ingressNamespaceSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: ingressNamespaceSelector}
		}
		policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{peer}}}
	}
	if egressPodSelector != nil || egressNamespaceSelector != nil {
		peer := networkingv1.NetworkPolicyPeer{}
		if egressPodSelector != nil {
			peer.PodSelector = &metav1.LabelSelector{MatchLabels: egressPodSelector}
		}
		if egressNamespaceSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: egressNamespaceSelector}
		}
		policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{peer}}}
	}
	return policy
}

func newCRDsPeer(podSelector map[string]string, namespaceSelector map[string]string) *v1alpha1.NetworkPolicyPeer {
	npPeer := v1alpha1.NetworkPolicyPeer{}
	if podSelector != nil {
		npPeer.PodSelector = &metav1.LabelSelector{MatchLabels: podSelector}
	}
	if namespaceSelector != nil {
		npPeer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: namespaceSelector}
	}
	return &npPeer
}

func newClusterNetworkPolicy(name, tier string, priority float64, appliedTo, ingressPeer, egressPeer *v1alpha1.NetworkPolicyPeer, ingressAction, egressAction *v1alpha1.RuleAction) *v1alpha1.ClusterNetworkPolicy {
	if name == "" {
		name = "acnp-" + rand.String(8)
	}
	policy := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uuid.New().String())},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     tier,
			Priority: priority,
		},
	}
	if appliedTo != nil {
		policy.Spec.AppliedTo = []v1alpha1.NetworkPolicyPeer{*appliedTo}
	}
	if ingressAction != nil {
		policy.Spec.Ingress = []v1alpha1.Rule{{Action: ingressAction}}
		if ingressPeer != nil {
			policy.Spec.Ingress[0].From = []v1alpha1.NetworkPolicyPeer{*ingressPeer}
		}
	}
	if egressAction != nil {
		policy.Spec.Egress = []v1alpha1.Rule{{Action: egressAction}}
		if egressPeer != nil {
			policy.Spec.Egress[0].To = []v1alpha1.NetworkPolicyPeer{*egressPeer}
		}
	}
	return policy
}

func newAntreaNetworkPolicy(namespace, name, tier string, priority float64, appliedTo, ingressPeer, egressPeer *v1alpha1.NetworkPolicyPeer, ingressAction, egressAction *v1alpha1.RuleAction) *v1alpha1.NetworkPolicy {
	if name == "" {
		name = "anp-" + rand.String(8)
	}
	policy := &v1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uuid.New().String())},
		Spec: v1alpha1.NetworkPolicySpec{
			Tier:     tier,
			Priority: priority,
		},
	}
	if appliedTo != nil {
		policy.Spec.AppliedTo = []v1alpha1.NetworkPolicyPeer{*appliedTo}
	}
	if ingressAction != nil {
		policy.Spec.Ingress = []v1alpha1.Rule{{Action: ingressAction}}
		if ingressPeer != nil {
			policy.Spec.Ingress[0].From = []v1alpha1.NetworkPolicyPeer{*ingressPeer}
		}
	}
	if egressAction != nil {
		policy.Spec.Egress = []v1alpha1.Rule{{Action: egressAction}}
		if egressPeer != nil {
			policy.Spec.Egress[0].To = []v1alpha1.NetworkPolicyPeer{*egressPeer}
		}
	}
	return policy
}

func BenchmarkSyncAddressGroup(b *testing.B) {
	namespace := "default"
	labels := map[string]string{"app-1": "scale-1"}
	getObjects := func() ([]*corev1.Namespace, []*networkingv1.NetworkPolicy, []*corev1.Pod) {
		namespaces := []*corev1.Namespace{newNamespace(namespace, nil)}
		networkPolicies := []*networkingv1.NetworkPolicy{newNetworkPolicy(namespace, "", labels, labels, nil, nil, nil)}
		pods := []*corev1.Pod{newPod(namespace, "", labels)}
		return namespaces, networkPolicies, pods
	}
	namespaces, networkPolicies, pods := getXObjects(1000, getObjects)
	objs := toRunTimeObjects(namespaces[0:1], networkPolicies, pods)
	stopCh := make(chan struct{})
	defer close(stopCh)
	_, c := newController(objs...)
	c.informerFactory.Start(stopCh)
	go c.groupingInterface.Run(stopCh)

	for c.appliedToGroupQueue.Len() > 0 {
		key, _ := c.appliedToGroupQueue.Get()
		c.syncAppliedToGroup(key.(string))
		c.appliedToGroupQueue.Done(key)
	}
	for c.internalNetworkPolicyQueue.Len() > 0 {
		key, _ := c.internalNetworkPolicyQueue.Get()
		c.syncInternalNetworkPolicy(key.(string))
		c.internalNetworkPolicyQueue.Done(key)
	}
	key, _ := c.addressGroupQueue.Get()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.syncAddressGroup(key.(string))
	}
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithSmallNamespaces-12    	       1	3370822184 ns/op	947740704 B/op	13934881 allocs/op
*/
func BenchmarkInitXLargeScaleWithSmallNamespaces(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithSmallNamespaces()
	benchmarkInit(b, namespaces, networkPolicies, nil, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithSmallNamespacesACNP-12    	       1	13267391150 ns/op	4773905112 B/op	 9334775 allocs/op
*/
func BenchmarkInitXLargeScaleWithSmallNamespacesACNP(b *testing.B) {
	namespaces, acnps, pods := getXLargeScaleWithSmallNamespacesACNP()
	benchmarkInit(b, namespaces, nil, acnps, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithSmallNamespacesANP-12    	       1	2657829793 ns/op	786859872 B/op	12032822 allocs/op
*/
func BenchmarkInitXLargeScaleWithSmallNamespacesANP(b *testing.B) {
	namespaces, anps, pods := getXLargeScaleWithSmallNamespacesANP()
	benchmarkInit(b, namespaces, nil, nil, anps, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithLargeNamespaces-12    	       1	1041444043 ns/op	329275456 B/op	 4713774 allocs/op
*/
func BenchmarkInitXLargeScaleWithLargeNamespaces(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithLargeNamespaces()
	benchmarkInit(b, namespaces, networkPolicies, nil, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithLargeNamespacesACNP-12    	       1	2326002605 ns/op	624753920 B/op	 3275468 allocs/op
*/
func BenchmarkInitXLargeScaleWithLargeNamespacesACNP(b *testing.B) {
	namespaces, acnps, pods := getXLargeScaleWithLargeNamespacesACNP()
	benchmarkInit(b, namespaces, nil, acnps, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithLargeNamespacesANP-12    	       4	 256732090 ns/op	69234354 B/op	 1023373 allocs/op
*/
func BenchmarkInitXLargeScaleWithLargeNamespacesANP(b *testing.B) {
	namespaces, anps, pods := getXLargeScaleWithLargeNamespacesANP()
	benchmarkInit(b, namespaces, nil, nil, anps, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithOneNamespace-12    	       1	2095352669 ns/op	927546712 B/op	 1539068 allocs/op
*/
func BenchmarkInitXLargeScaleWithOneNamespace(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithOneNamespace()
	benchmarkInit(b, namespaces, networkPolicies, nil, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithOneNamespaceACNP-12    	       1	2257050725 ns/op	921927048 B/op	 1490140 allocs/op
*/
func BenchmarkInitXLargeScaleWithOneNamespaceACNP(b *testing.B) {
	namespaces, acnps, pods := getXLargeScaleWithOneNamespaceACNP()
	benchmarkInit(b, namespaces, nil, acnps, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithOneNamespaceANP-12    	       1	2133466616 ns/op	923855064 B/op	 1549337 allocs/op
*/
func BenchmarkInitXLargeScaleWithOneNamespaceANP(b *testing.B) {
	namespaces, anps, pods := getXLargeScaleWithOneNamespaceANP()
	benchmarkInit(b, namespaces, nil, nil, anps, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithNetpolPerPod-12    	       1	26959864791 ns/op	137621168 B/op	 1984280 allocs/op
*/
func BenchmarkInitXLargeScaleWithNetpolPerPod(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithNetpolPerPod()
	benchmarkInit(b, namespaces, networkPolicies, nil, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithNetpolPerPodACNP-12    	       1	21762949381 ns/op	131031512 B/op	 1934354 allocs/op
*/
func BenchmarkInitXLargeScaleWithNetpolPerPodACNP(b *testing.B) {
	namespaces, acnps, pods := getXLargeScaleWithNetpolPerPodACNP()
	benchmarkInit(b, namespaces, nil, acnps, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithNetpolPerPodANP-12    	       1	24717836586 ns/op	133763984 B/op	 1994399 allocs/op
*/
func BenchmarkInitXLargeScaleWithNetpolPerPodANP(b *testing.B) {
	namespaces, anps, pods := getXLargeScaleWithNetpolPerPodANP()
	benchmarkInit(b, namespaces, nil, nil, anps, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithClusterScopedNetpol-12    	    5866	    175722 ns/op	   42809 B/op	     583 allocs/op
BenchmarkInitXLargeScaleWithClusterScopedNetpol-12    	       5	 203839366 ns/op	50210939 B/op	  684313 allocs/op
*/
func BenchmarkInitXLargeScaleWithClusterScopedNetpol(b *testing.B) {
	namespaces, networkPolicies, pods := getXLargeScaleWithClusterScopedNetpol()
	benchmarkInit(b, namespaces, networkPolicies, nil, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithClusterScopedNetpolACNP-12    	       1	3123453407 ns/op	1128695184 B/op	 3176599 allocs/op
*/
func BenchmarkInitXLargeScaleWithClusterScopedNetpolACNP(b *testing.B) {
	namespaces, acnps, pods := getXLargeScaleWithClusterScopedNetpolACNP()
	benchmarkInit(b, namespaces, nil, acnps, nil, pods)
}

/*
The reference value is:
BenchmarkInitXLargeScaleWithClusterScopedNetpolANP-12    	       4	 258883641 ns/op	61803398 B/op	  857878 allocs/op
BenchmarkInitXLargeScaleWithClusterScopedNetpolANP-12    	     258	   4064149 ns/op	  958257 B/op	   13299 allocs/op
BenchmarkInitXLargeScaleWithClusterScopedNetpolANP-12    	  397512	      3164 ns/op	     622 B/op	       8 allocs/op
*/
func BenchmarkInitXLargeScaleWithClusterScopedNetpolANP(b *testing.B) {
	namespaces, anps, pods := getXLargeScaleWithClusterScopedNetpolANP()
	benchmarkInit(b, namespaces, nil, nil, anps, pods)
}

func benchmarkInit(b *testing.B, namespaces []*corev1.Namespace, networkPolicies []*networkingv1.NetworkPolicy, acnps []*v1alpha1.ClusterNetworkPolicy, anps []*v1alpha1.NetworkPolicy, pods []*corev1.Pod) {
	disableLogToStderr()

	objs := toRunTimeObjects(namespaces, networkPolicies, pods)
	stopCh := make(chan struct{})
	defer close(stopCh)
	_, c := newControllerWithoutEventHandler(objs...)
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)

	b.ReportAllocs()
	b.ResetTimer()

	go c.groupingInterface.Run(stopCh)

	for _, namespace := range namespaces {
		c.groupingInterface.AddNamespace(namespace)
	}
	for _, pod := range pods {
		c.groupingInterface.AddPod(pod)
	}
	for _, networkPolicy := range networkPolicies {
		c.addNetworkPolicy(networkPolicy)
	}
	for _, acnp := range acnps {
		c.addACNP(acnp)
	}
	for _, anp := range anps {
		c.addANP(anp)
	}
	for c.appliedToGroupQueue.Len() > 0 {
		key, _ := c.appliedToGroupQueue.Get()
		c.syncAppliedToGroup(key.(string))
		c.appliedToGroupQueue.Done(key)
	}
	for c.internalNetworkPolicyQueue.Len() > 0 {
		key, _ := c.internalNetworkPolicyQueue.Get()
		c.syncInternalNetworkPolicy(key.(string))
		c.internalNetworkPolicyQueue.Done(key)
	}
	for c.addressGroupQueue.Len() > 0 {
		key, _ := c.addressGroupQueue.Get()
		c.syncAddressGroup(key.(string))
		c.addressGroupQueue.Done(key)
	}
}

func disableLogToStderr() {
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	klogFlagSet.Parse([]string{"-logtostderr=false"})
}
