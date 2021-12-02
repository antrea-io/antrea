// Copyright 2021 Antrea Authors
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

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/utils"
)

var (
	networkPolicyLabelKey = "antrea-scale-test-netpol"
)

func shuffle(s *[]corev1.Pod) {
	slice := *s
	n := len(slice)
	for i := range slice {
		j := int(utils.GenRandInt()) % n
		slice[i], slice[j] = slice[j], slice[i]
	}
	*s = slice
}

// Total NetworkPolicies number = 50% Pods number
//  5% NetworkPolicies cover 80% Pods = 2.5% Pods number
// 15% NetworkPolicies cover 13% Pods = 7.5% Pods number
// 80% NetworkPolicies cover 6% Pods  = 40%  Pods number
func generateNetpolTemplate(labelNum int, podName, ns string, isIngress bool) *netv1.NetworkPolicy {
	name := uuid.New().String()
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(80)
	policyPorts := []netv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}}
	policyPeer := []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": podName}}}}
	netpol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{networkPolicyLabelKey: ""},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: utils.PickLabels(labelNum, false)},
		},
	}
	if isIngress {
		netpol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeIngress}
		netpol.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{Ports: policyPorts, From: policyPeer}}
	} else {
		netpol.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
		netpol.Spec.Egress = []netv1.NetworkPolicyEgressRule{{Ports: policyPorts, To: policyPeer}}
	}
	return netpol
}

func generateP80NetworkPolicies(podName, ns string, isIngress bool) *netv1.NetworkPolicy {
	return generateNetpolTemplate(2, podName, ns, isIngress)
}
func generateP15NetworkPolicies(podName, ns string, isIngress bool) *netv1.NetworkPolicy {
	return generateNetpolTemplate(7, podName, ns, isIngress)
}
func generateP5NetworkPolicies(podName, ns string, isIngress bool) *netv1.NetworkPolicy {
	return generateNetpolTemplate(10, podName, ns, isIngress)
}

func generateNetworkPolicies(cs kubernetes.Interface, isIngress bool, npNum int, ns string) ([]*netv1.NetworkPolicy, error) {
	// NetworkPolicies num is about half num of all workload Pods
	p5 := npNum * 5 / 100   // 2.5% number of Pods
	p15 := npNum * 15 / 100 // 7.5% number of Pods
	p80 := npNum * 80 / 100 // 40% number of Pods
	var nps []*netv1.NetworkPolicy
	podList, err := cs.
		CoreV1().Pods(ns).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	shuffle(&podList.Items)

	items := podList.Items[:p5+p15+p80]
	for i := 0; i < p5; i++ {
		nps = append(nps, generateP80NetworkPolicies(items[i].Name, ns, isIngress))
	}
	for i := 0; i < p15; i++ {
		nps = append(nps, generateP15NetworkPolicies(items[i].Name, ns, isIngress))
	}
	for i := 0; i < p80; i++ {
		nps = append(nps, generateP5NetworkPolicies(items[i].Name, ns, isIngress))
	}
	return nps, nil
}

type NetworkPolicyInfo struct {
	Name      string
	Namespace string
	Spec      netv1.NetworkPolicySpec
}

func ScaleUp(ctx context.Context, num int, cs kubernetes.Interface, nss []string, ipv6 bool) (nps []NetworkPolicyInfo, err error) {
	// ScaleUp networkPolicies
	for _, ns := range nss {
		npsData, err := generateNetworkPolicies(cs, utils.GenRandInt()%2 == 0, num, ns)
		if err != nil {
			return nil, fmt.Errorf("error when generating network policies: %w", err)
		}
		klog.InfoS("Scale up NetworkPolicies", "Num", len(npsData))
		for _, np := range npsData {
			if err := utils.DefaultRetry(func() error {
				newNP, err := cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
				if err != nil {
					if errors.IsAlreadyExists(err) {
						newNP, _ = cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, np.Name, metav1.GetOptions{})
					} else {
						return err
					}
				}
				nps = append(nps, NetworkPolicyInfo{Name: newNP.Name, Namespace: newNP.Namespace, Spec: newNP.Spec})
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}
	return
}

func SelectConnectPod(ctx context.Context, cs kubernetes.Interface, ns string, np NetworkPolicyInfo) (fromPod *corev1.Pod, toPodIP string, err error) {
	klog.V(2).InfoS("Checking connectivity of the NetworkPolicy", "NetworkPolicyName", np.Name)
	podList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
	if err != nil {
		return nil, "", fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
	}
	if len(podList.Items) == 0 {
		klog.V(2).InfoS("No Pod is selected by the NetworkPolicy, skip", "NetworkPolicyName", np.Name)
		return nil, "", nil
	}
	var fromPods []corev1.Pod
	var toPods []corev1.Pod
	if len(np.Spec.Ingress) > 0 {
		toPods = podList.Items
		if err := utils.DefaultRetry(func() error {
			fromPodsList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(np.Spec.Ingress[0].From[0].PodSelector)})
			if err != nil {
				return err
			}
			fromPods = fromPodsList.Items
			return nil
		}); err != nil {
			return nil, "", fmt.Errorf("error when retrieving Pods: %w", err)
		}
	} else if len(np.Spec.Egress) > 0 {
		fromPods = podList.Items
		if err := utils.DefaultRetry(func() error {
			toPodsList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(np.Spec.Egress[0].To[0].PodSelector)})
			if err != nil {
				return err
			}
			toPods = toPodsList.Items
			return nil
		}); err != nil {
			return nil, "", fmt.Errorf("error when retrieving Pods: %w", err)
		}
	}

	if len(toPods) == 0 || len(fromPods) == 0 {
		klog.V(2).InfoS("Skipping the check of the NetworkPolicy, since the label selector does not match any Pod", "NetworkPolicy", np.Name)
		return nil, "", nil
	}
	fromPodsNum, toPodsNum := len(fromPods), len(toPods)
	klog.V(2).InfoS("Select test Pods", "fromPodsNum", fromPodsNum, "toPodsNum", toPodsNum)
	toPod := toPods[int(utils.GenRandInt())%toPodsNum]
	fromPod = &fromPods[int(utils.GenRandInt())%fromPodsNum]
	if toPod.Status.PodIP == "" {
		return nil, "", fmt.Errorf("podIP is nil, Namespace: %s, Name: %s", toPod.Namespace, toPod.Name)
	}
	toPodIP = toPod.Status.PodIP
	return
}

func SelectIsoPod(ctx context.Context, cs kubernetes.Interface, ns string, np NetworkPolicyInfo, clientPods []corev1.Pod) (fromPod *corev1.Pod, toPodIP string, err error) {
	klog.V(2).InfoS("Checking isolation of the NetworkPolicy", "NetworkPolicyName", np.Name)
	podList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
	if err != nil {
		return nil, "", fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
	}
	if len(podList.Items) == 0 || len(clientPods) == 0 {
		klog.V(2).InfoS("No Pod is selected by the NetworkPolicy, skip", "NetworkPolicyName", np.Name)
		return nil, "", nil
	}
	var toPod corev1.Pod
	if len(np.Spec.Ingress) > 0 {
		fromPod = &clientPods[int(utils.GenRandInt())%len(clientPods)]
		toPod = podList.Items[int(utils.GenRandInt())%len(podList.Items)]
	} else if len(np.Spec.Egress) > 0 {
		fromPod = &podList.Items[int(utils.GenRandInt())%len(podList.Items)]
		toPod = clientPods[int(utils.GenRandInt())%len(clientPods)]
	}
	if toPod.Status.PodIP == "" {
		return nil, "", fmt.Errorf("podIP is nil, Namespace: %s, Name: %s", toPod.Namespace, toPod.Name)
	}
	return
}
