// Copyright 2024 Antrea Authors
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
	"context"
	"fmt"
	"time"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	antreaapis "antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/clientpod"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleRestartAgent", ScaleRestartAgent)
	RegisterFunc("RestartController", RestartController)
}

// ScaleRestartAgent restart the antrea agent service on the Cluster, and measure the average time taken for the agent service to become effective again after the restart.
func ScaleRestartAgent(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error
	res.scaleNum = data.nodesNum

	probeURL := fmt.Sprintf("%s:%d", "", antreaapis.AntreaAgentAPIPort)

	expectPodNum := data.nodesNum - data.simulateNodesNum
	_, err = clientpod.Update(ctx, data.kubernetesClientSet, clientpod.ClientPodsNamespace, clientpod.ScaleTestClientDaemonSet, []string{probeURL}, clientpod.ScaleAgentProbeContainerName, expectPodNum)
	if err != nil {
		return
	}

	err = data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).
		DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-agent"})
	if err != nil {
		return
	}
	startTime := time.Now().UnixNano()

	err = wait.PollUntilContextTimeout(ctx, config.WaitInterval, config.DefaultTimeout, true, func(ctx context.Context) (bool, error) {
		var ds *appv1.DaemonSet
		if err := utils.DefaultRetry(func() error {
			var err error
			ds, err = data.kubernetesClientSet.AppsV1().DaemonSets(metav1.NamespaceSystem).Get(ctx, "antrea-agent", metav1.GetOptions{})
			return err
		}); err != nil {
			return false, err
		}
		klog.V(2).InfoS("Check agent restart", "DesiredNumberScheduled", ds.Status.DesiredNumberScheduled,
			"NumberAvailable", ds.Status.NumberAvailable)
		return ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable, nil
	})

	go func() {
		podList, err := data.kubernetesClientSet.CoreV1().Pods(clientpod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: clientpod.ScaleClientPodTemplateName})
		if err != nil {
			klog.ErrorS(err, "error when getting scale test client pods")
			return
		}
		for _, pod := range podList.Items {
			if pod.Status.Phase != corev1.PodRunning {
				continue
			}
			key := utils.DownToUp
			if err := utils.FetchTimestampFromLog(ctx, data.kubernetesClientSet, pod.Namespace, pod.Name, clientpod.ScaleAgentProbeContainerName, ch, startTime, key); err != nil {
				klog.ErrorS(err, "Checking antrea agent restart time error", "ClientPodName", pod.Name)
			}
		}
	}()

	defer func() {
		res.err = err
		if err == nil {
			for {
				klog.InfoS("Waiting for the check goroutine to finish", "expectPodNum", expectPodNum, "len(ch)", len(ch))
				if len(ch) == expectPodNum {
					break
				}
				time.Sleep(time.Second)
			}
		}
	}()

	res.actualCheckNum = expectPodNum
	return
}

func getControllerPod(data *ScaleData, ctx context.Context) (controllerPod *corev1.Pod, err error) {
	if err := wait.PollUntilContextTimeout(ctx, config.WaitInterval, config.DefaultTimeout, false, func(ctx context.Context) (done bool, err error) {
		controllerPods, err := data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-controller"})
		if err != nil {
			return false, err
		}
		if len(controllerPods.Items) != 1 || controllerPods.Items[0].Status.Phase != corev1.PodRunning {
			return false, nil
		}
		controllerPod = &controllerPods.Items[0]
		return true, nil
	}); err != nil {
		return nil, err
	}
	return
}

// RestartController restart the antrea controller on the Cluster, and measure the average time taken for the controller service to become effective again after the restart.
func RestartController(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error
	res.scaleNum = 1
	defer func() {
		res.err = err
		if err == nil {
			for {
				klog.InfoS("Waiting for the check goroutine to finish", "len(ch)", len(ch))
				if len(ch) == 1 {
					break
				}
				time.Sleep(time.Second)
			}
		}
	}()

	probeURL := fmt.Sprintf("%s:%d", "", antreaapis.AntreaControllerAPIPort)

	expectPodNum := data.nodesNum - data.simulateNodesNum
	_, err = clientpod.Update(ctx, data.kubernetesClientSet, clientpod.ClientPodsNamespace, clientpod.ScaleTestClientDaemonSet, []string{probeURL}, clientpod.ScaleControllerProbeContainerName, expectPodNum)
	if err != nil {
		return
	}

	startTime0 := time.Now().UnixNano()
	err = data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-controller"})
	if err != nil {
		return
	}
	startTime := time.Now().UnixNano()
	klog.InfoS("Deleting operate time", "Duration(ms)", (startTime-startTime0)/1000000)

	err = wait.PollUntilContextTimeout(ctx, config.WaitInterval, config.DefaultTimeout, true, func(ctx context.Context) (bool, error) {
		var dp *appv1.Deployment
		if err := utils.DefaultRetry(func() error {
			var err error
			dp, err = data.kubernetesClientSet.AppsV1().Deployments(metav1.NamespaceSystem).Get(ctx, "antrea-controller", metav1.GetOptions{})
			return err
		}); err != nil {
			return false, err
		}
		return dp.Status.ObservedGeneration == dp.Generation && dp.Status.ReadyReplicas == *dp.Spec.Replicas, nil
	})

	go func() {
		controllerPod, err := getControllerPod(data, ctx)
		if err != nil {
			klog.ErrorS(err, "error when get Antrea controller Pod")
			return
		}
		podList, err := data.kubernetesClientSet.CoreV1().Pods(clientpod.ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: clientpod.ScaleClientPodTemplateName})
		if err != nil {
			klog.ErrorS(err, "error when getting scale test client Pods")
			return
		}
		for _, pod := range podList.Items {
			if pod.Spec.NodeName == controllerPod.Spec.NodeName {
				key := "down to up"
				downToUpErr := utils.FetchTimestampFromLog(ctx, data.kubernetesClientSet, pod.Namespace, pod.Name, clientpod.ScaleControllerProbeContainerName, ch, startTime, key)
				key = "unknown to up"
				unknownToUpErr := utils.FetchTimestampFromLog(ctx, data.kubernetesClientSet, pod.Namespace, pod.Name, clientpod.ScaleControllerProbeContainerName, ch, startTime, key)
				if downToUpErr != nil && unknownToUpErr != nil {
					klog.ErrorS(err, "Checking antrea controller restart time error", "ClientPodName", pod.Name)
				}
				return
			}
		}
		klog.ErrorS(nil, "cannot find a test client Pods on the same Node on which Antrea controller is running")
	}()

	res.actualCheckNum = 1
	return
}
