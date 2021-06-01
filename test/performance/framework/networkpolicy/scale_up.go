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
	"time"

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

func generateNetpolTemplate(labelNum int, ns string, isIngress bool) *netv1.NetworkPolicy {
	name := uuid.New().String()
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt(80)
	policyPorts := []netv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}}
	policyPeer := []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"namespace": ns}}}}
	netpol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{networkPolicyLabelKey: ""},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{
				fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, labelNum): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, labelNum),
			}},
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

func generateIngressNP(labelNum int, ns string) *netv1.NetworkPolicy {
	return generateNetpolTemplate(labelNum, ns, true)
}

func generateEgressNP(labelNum int, ns string) *netv1.NetworkPolicy {
	return generateNetpolTemplate(labelNum, ns, false)
}

func generateNetworkPolicies(ns string, num int) ([]*netv1.NetworkPolicy, error) {
	var nps []*netv1.NetworkPolicy

	for i := 0; i < num; i++ {
		if i%2 == 0 {
			nps = append(nps, generateIngressNP(i/2+1, ns))
		} else {
			nps = append(nps, generateEgressNP(i/2+1, ns))
		}
	}
	return nps, nil
}

type NetworkPolicyInfo struct {
	Name      string
	Namespace string
	Spec      netv1.NetworkPolicySpec
}

func ScaleUp(ctx context.Context, cs kubernetes.Interface, nss []string, numPerNs int, ipv6 bool) (nps []NetworkPolicyInfo, err error) {
	// ScaleUp networkPolicies
	start := time.Now()
	for _, ns := range nss {
		npsData, err := generateNetworkPolicies(ns, numPerNs)
		if err != nil {
			return nil, fmt.Errorf("error when generating network policies: %w", err)
		}
		klog.InfoS("Scale up NetworkPolicies", "Num", len(npsData), "Namespace", ns)
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
	klog.InfoS("Scale up NetworkPolicies", "Duration", time.Since(start), "count", len(nps))
	return
}

func SelectConnectPod(ctx context.Context, cs kubernetes.Interface, ns string, np *NetworkPolicyInfo) (fromPod *corev1.Pod, toPodIP string, err error) {
	klog.V(2).InfoS("Checking connectivity of the NetworkPolicy", "NetworkPolicyName", np.Name, "Namespace", np.Namespace)
	if _, ok := np.Spec.PodSelector.MatchLabels[utils.PodOnRealNodeLabelKey]; !ok {
		np.Spec.PodSelector.MatchLabels[utils.PodOnRealNodeLabelKey] = ""
	}
	klog.InfoS("Podselect", "PodSelector", np.Spec.PodSelector)
	podList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
	if err != nil {
		return nil, "", fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
	}
	if len(podList.Items) == 0 {
		klog.V(2).InfoS("No Pod is selected by the NetworkPolicy, skip", "NetworkPolicyName", np.Name, "Namespace", np.Namespace)
		return nil, "", nil
	}
	var fromPods []corev1.Pod
	var toPods []corev1.Pod
	if len(np.Spec.Ingress) > 0 {
		toPods = podList.Items
		if err := utils.DefaultRetry(func() error {
			podSelector := np.Spec.Ingress[0].From[0].PodSelector
			podSelector.MatchLabels[utils.PodOnRealNodeLabelKey] = ""
			fromPodsList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(podSelector)})
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
			podSelector := np.Spec.Egress[0].To[0].PodSelector
			podSelector.MatchLabels[utils.PodOnRealNodeLabelKey] = ""
			toPodsList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(podSelector)})
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
	klog.V(2).InfoS("Checking isolation of the NetworkPolicy", "NetworkPolicyName", np.Name, "Namespace", np.Namespace)
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
