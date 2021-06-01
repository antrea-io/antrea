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
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleUpWorkloadPods", ScaleUpWorkloadPods)
}

const (
	workloadPodLabelKey   = "antrea-scale-workload-pod"
	workloadPodLabelValue = ""
)

var (
	workloadPodContainer = corev1.Container{
		Name:            "busybox",
		Image:           "busybox",
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"httpd", "-f"},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("64Mi"),
				corev1.ResourceCPU:    resource.MustParse("20m"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("32Mi"),
				corev1.ResourceCPU:    resource.MustParse("10m"),
			},
		},
	}
)

func workloadPodTemplate(podName, ns string, labels map[string]string, onRealNode bool) *corev1.Pod {
	var affinity *corev1.Affinity
	var tolerations []corev1.Toleration
	if onRealNode {
		affinity = &RealNodeAffinity
		tolerations = append(tolerations, MasterToleration)
	} else {
		affinity = &SimulateAffinity
		tolerations = append(tolerations, SimulateToleration)
	}
	labels[workloadPodLabelKey] = workloadPodLabelValue
	labels["name"] = podName
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Affinity:      affinity,
			Containers:    []corev1.Container{workloadPodContainer},
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations:   tolerations,
		},
	}
}

func newWorkloadPod(podName, ns string, onRealNode bool, labelNum int) *corev1.Pod {
	labels := map[string]string{
		AppLabelKey: AppLabelValue,
		"namespace": ns,
		fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, labelNum): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, labelNum),
	}
	if onRealNode {
		labels[utils.PodOnRealNodeLabelKey] = ""
	}
	return workloadPodTemplate(podName, ns, labels, onRealNode)
}

func ScaleUpWorkloadPods(ctx context.Context, data *ScaleData) error {
	if data.Specification.SkipDeployWorkload {
		klog.V(2).InfoS("Skip creating workload Pods", "SkipDeployWorkload", data.Specification.SkipDeployWorkload)
		return nil
	}
	// Creating workload Pods
	start := time.Now()
	podNum := data.Specification.PodsNumPerNs
	for _, ns := range data.namespaces {
		gErr, _ := errgroup.WithContext(context.Background())
		for i := 0; i < podNum; i++ {
			// index := i
			time.Sleep(time.Duration(utils.GenRandInt()%100) * time.Millisecond)
			labelNum := i/2 + 1
			gErr.Go(func() error {
				podName := fmt.Sprintf("antrea-scale-test-pod-%s", uuid.New().String())
				pod := newWorkloadPod(podName, ns, true, labelNum)
				// if !data.Specification.RealNode {
				// 	onRealNode := (index % data.nodesNum) >= data.simulateNodesNum
				// 	pod = newWorkloadPod(podName, ns, onRealNode, labelNum)
				// }
				if _, err := data.kubernetesClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
					return err
				}
				return nil
			})
		}
		klog.V(2).InfoS("Create workload Pods", "PodNum", podNum, "Namespace", ns)
		if err := gErr.Wait(); err != nil {
			return err
		}

		// Waiting scale workload Pods to be ready
		err := wait.PollUntil(config.WaitInterval, func() (bool, error) {
			podsResult, err := data.kubernetesClientSet.
				CoreV1().Pods(ns).
				List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", AppLabelKey, AppLabelValue)})
			if err != nil {
				klog.ErrorS(err, "Error when listing Pods")
			} else {
				var count int
				for _, pod := range podsResult.Items {
					if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
						count += 1
					}
				}
				klog.V(2).InfoS("Check Pod num", "Running Pod num", count, "expect Pod num", data.podsNumPerNs)
				return count >= data.podsNumPerNs, nil
			}
			return false, nil
		}, ctx.Done())
		if err != nil {
			return err
		}
	}
	klog.InfoS("Scaled up Pods", "Duration", time.Since(start), "count", podNum*len(data.namespaces))
	return nil
}
