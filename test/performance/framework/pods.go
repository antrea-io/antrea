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

func workloadPodTemplate(podName string, labels map[string]string, onRealNode bool) *corev1.Pod {
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
			Namespace: ScaleTestNamespacePrefix,
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

func newWorkloadPod(podName string, onRealNode bool) *corev1.Pod {
	labels := map[string]string{
		AppLabelKey: AppLabelValue,
	}
	for len(labels) == 1 { // must generate at least one label.
		for _, l := range utils.LabelCandidates {
			if utils.GenRandInt()%10 < 8 {
				labels[l] = ""
			}
		}
	}
	if onRealNode {
		labels[utils.PodOnRealNodeLabelKey] = ""
	}
	return workloadPodTemplate(podName, labels, onRealNode)
}

func ScaleUpWorkloadPods(ctx context.Context, data *ScaleData) error {
	// Creating workload Pods
	podNum := data.nodesNum * data.Specification.PodsNumPerNode
	gErr, _ := errgroup.WithContext(context.Background())
	for i := 0; i < podNum; i++ {
		index := i
		gErr.Go(func() error {
			podName := fmt.Sprintf("antrea-scale-test-pod-%s", uuid.New().String())
			pod := newWorkloadPod(podName, true)
			if !data.Specification.RealNode {
				onRealNode := (index % data.nodesNum) >= data.simulateNodesNum
				pod = newWorkloadPod(podName, onRealNode)
			}
			klog.V(2).InfoS("Creating Pods", "onRealNode", data.Specification.RealNode)
			if _, err := data.kubernetesClientSet.CoreV1().
				Pods(ScaleTestNamespacePrefix).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
				return err
			}
			return nil
		})
	}
	klog.InfoS("Create workload Pods", "PodNum", podNum)
	if err := gErr.Wait(); err != nil {
		return err
	}

	// Waiting scale workload Pods to be ready
	return wait.PollUntil(config.WaitInterval, func() (bool, error) {
		podsResult, err := data.kubernetesClientSet.
			CoreV1().Pods(ScaleTestNamespacePrefix).
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
			return count >= data.podsNum, nil
		}
		return false, nil
	}, ctx.Done())
}
