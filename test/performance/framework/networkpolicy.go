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

package framework

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/client_pod"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleNetworkPolicy", ScaleNetworkPolicy)
}

func ScaleNetworkPolicy(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	nps := networkPolicies{
		ch:   ch,
		data: data,
	}
	checkCount, err := nps.scaleUp(ctx)
	if err != nil {
		res.err = fmt.Errorf("scale up NetworkPolicies error: %v", err)
		return
	}
	res.scaleNum = len(data.namespaces) * data.Specification.NpNumPerNs
	res.actualCheckNum = checkCount

	defer func() {
		for {
			if len(ch) >= res.actualCheckNum {
				break
			}
			klog.InfoS("Waiting the check goroutine finish", "actualCheckNum", res.actualCheckNum, "channel length", len(ch))
			time.Sleep(time.Second)
		}
		if err := nps.scaleDown(ctx); err != nil {
			klog.ErrorS(err, "Scale down NetworkPolicies failed")
		}
	}()

	res.actualCheckNum = checkCount
	return
}

func unmarshallNetworkPolicy(yamlFile string) (*netv1.NetworkPolicy, error) {
	klog.InfoS("ReadYamlFile", "yamlFile", yamlFile)
	podBytes, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %+v", err)
	}
	np := &netv1.NetworkPolicy{}

	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(podBytes), 100)

	if err := decoder.Decode(np); err != nil {
		return nil, fmt.Errorf("error decoding YAML file: %+v", err)
	}
	return np, nil
}

func renderNetworkPolicies(templatePath string, ns string, num int) (nps []*netv1.NetworkPolicy, err error) {
	yamlFile := path.Join(templatePath, "networkpolicy/networkpolicy.yaml")
	npTemplate, err := unmarshallNetworkPolicy(yamlFile)
	if err != nil {
		err = fmt.Errorf("error reading Service template: %+v", err)
		return
	}

	for i := 0; i < num; i++ {
		np := &netv1.NetworkPolicy{}
		np.Spec = npTemplate.Spec
		np.Name = fmt.Sprintf("antrea-scale-test-np-%s", uuid.New().String()[:8])
		np.Namespace = ns
		np.Spec.Ingress[0].From[0].PodSelector.MatchLabels = map[string]string{"namespace": ns}
		np.Spec.PodSelector.MatchLabels = map[string]string{
			fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, i): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, i),
		}
		nps = append(nps, np)
	}

	return
}

type NetworkPolicyInfo struct {
	Name      string
	Namespace string
	Spec      netv1.NetworkPolicySpec
}

type networkPolicies struct {
	ch   chan time.Duration
	data *ScaleData
}

func (nps networkPolicies) scaleUp(ctx context.Context) (actualCheckNum int, err error) {
	cs := nps.data.kubernetesClientSet
	nss := nps.data.namespaces
	numPerNs := nps.data.Specification.NpNumPerNs
	ch := nps.ch
	// ScaleUp networkPolicies
	start := time.Now()
	for _, ns := range nss {
		npsData, err := renderNetworkPolicies(nps.data.templateFilesPath, ns, numPerNs)
		if err != nil {
			return 0, fmt.Errorf("error when generating network policies: %w", err)
		}
		klog.InfoS("Scale up NetworkPolicies", "Num", len(npsData), "Namespace", ns)
		for _, np := range npsData {
			npInfo := NetworkPolicyInfo{Name: np.Name, Namespace: np.Namespace, Spec: np.Spec}
			shouldCheck := actualCheckNum < cap(ch)
			var clientPod *corev1.Pod
			var serverIP string
			if shouldCheck {
				serverIP, err = selectServerPod(ctx, cs, ns, npInfo)
				klog.InfoS("Select server Pod", "serverIP", serverIP, "error", err)
				if err != nil {
					klog.ErrorS(err, "selectServerPod")
					return 0, fmt.Errorf("select server Pod error: %+v", err)
				}
				clientPod, err = client_pod.CreatePod(ctx, cs, []string{fmt.Sprintf("%s:%d", serverIP, 80)}, client_pod.ScaleClientPodProbeContainer, client_pod.ClientPodsNamespace)
				if err != nil {
					klog.ErrorS(err, "Create client test Pod failed")
					return 0, fmt.Errorf("create client test Pod failed: %+v", err)
				}
			}
			if err := utils.DefaultRetry(func() error {
				startTime0 := time.Now().UnixNano()
				_, err := cs.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
				if err != nil {
					if errors.IsAlreadyExists(err) {
						_, _ = cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, np.Name, metav1.GetOptions{})
					} else {
						return err
					}
				}
				if shouldCheck && clientPod != nil && serverIP != "" {
					startTimeStamp := time.Now().UnixNano()
					klog.InfoS("Networkpolicy creating operate time", "Duration(ms)", (startTimeStamp-startTime0)/1000000)
					actualCheckNum++
					go func() {
						klog.InfoS("Update test Pod to check NetworkPolicy", "serverIP", serverIP, "StartTimeStamp", startTimeStamp)
						key := "up to down"
						if err := utils.FetchTimestampFromLog(ctx, cs, clientPod.Namespace, clientPod.Name, client_pod.ScaleClientPodProbeContainer, ch, startTimeStamp, key); err != nil {
							klog.ErrorS(err, "Checking the validity the NetworkPolicy error", "ClientPodName", clientPod.Name, "NetworkPolicy", npInfo)
						}
					}()
				}
				return nil
			}); err != nil {
				return 0, err
			}
			klog.InfoS("Create new NetworkPolicy", "npInfo", npInfo)
		}
	}
	klog.InfoS("Scale up NetworkPolicies", "Duration", time.Since(start), "actualCheckNum", actualCheckNum)
	return
}

func selectServerPod(ctx context.Context, cs kubernetes.Interface, ns string, np NetworkPolicyInfo) (toPodIP string, err error) {
	klog.V(2).InfoS("Checking isolation of the NetworkPolicy", "NetworkPolicyName", np.Name, "Namespace", np.Namespace)
	podList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&np.Spec.PodSelector)})
	if err != nil {
		return "", fmt.Errorf("error when selecting networkpolicy applied to pods: %w", err)
	}
	if len(podList.Items) == 0 {
		klog.V(2).InfoS("No Pod is selected by the NetworkPolicy, skip", "NetworkPolicyName", np.Name)
		return "", nil
	}
	var toPod corev1.Pod
	if len(np.Spec.Ingress) > 0 {
		toPod = podList.Items[int(utils.GenRandInt())%len(podList.Items)]
	} else {
		klog.V(2).InfoS("Not Ingress NetworkPolicy, skip check")
		return "", nil
	}
	if toPod.Status.PodIP == "" {
		return "", fmt.Errorf("podIP is nil, Namespace: %s, Name: %s", toPod.Namespace, toPod.Name)
	}
	return toPod.Status.PodIP, nil
}

// scaleDown clean up NetworkPolicies in the namespaces list nss
func (nps networkPolicies) scaleDown(ctx context.Context) error {
	nss := nps.data.namespaces
	cs := nps.data.kubernetesClientSet
	for _, ns := range nss {
		if err := cs.NetworkingV1().NetworkPolicies(ns).DeleteCollection(
			ctx, metav1.DeleteOptions{}, metav1.ListOptions{}); err != nil {
			klog.ErrorS(err, "Deleted NetworkPolicies error", "namespace", ns)
		}
		klog.V(2).InfoS("Deleted NetworkPolicies", "namespace", ns)
	}

	return wait.PollImmediateUntil(config.WaitInterval, func() (done bool, err error) {
		cleanCount := 0
		staleNpNum := 0
		for _, ns := range nss {
			staleNpNum = 0
			nps, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}
			if len(nps.Items) == 0 {
				cleanCount++
				continue
			}
			staleNpNum += len(nps.Items)
			if err := cs.NetworkingV1().NetworkPolicies(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{}); err != nil {
				return false, err
			}
		}
		klog.InfoS("Scale down NetworkPolicies", "CleanedNamespaceNum", cleanCount, "staleNpNum", staleNpNum)
		return cleanCount == len(nss), nil
	}, ctx.Done())
}
