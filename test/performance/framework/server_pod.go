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
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/client_pod"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleUpWorkloadPods", ScaleUpWorkloadPods)
}

const (
	workloadPodLabelKey   = "antrea-scale-workload-pod"
	workloadPodLabelValue = ""
)

func unmarshallServerPod(yamlFile string) (*corev1.Pod, error) {
	klog.InfoS("ReadYamlFile", "yamlFile", yamlFile)
	podBytes, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("error reading YAML file: %+v", err)
	}
	pod := &corev1.Pod{}

	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(podBytes), 100)

	if err := decoder.Decode(pod); err != nil {
		return nil, fmt.Errorf("error decoding YAML file: %+v", err)
	}
	return pod, nil
}

func renderServerPods(templatePath string, ns string, num, serviceNum int) (serverPods []*corev1.Pod, err error) {
	yamlFile := path.Join(templatePath, "service/server_pod.yaml")
	podTemplate, err := unmarshallServerPod(yamlFile)
	if err != nil {
		err = fmt.Errorf("error reading Service template: %+v", err)
		return
	}

	for i := 0; i < num; i++ {
		labelNum := i % serviceNum
		podName := fmt.Sprintf("antrea-scale-test-pod-server-%s", uuid.New().String()[:8])
		serverPod := &corev1.Pod{Spec: podTemplate.Spec}
		serverPod.Name = podName
		serverPod.Namespace = ns
		serverPod.Labels = map[string]string{
			"name":                      podName,
			utils.PodOnRealNodeLabelKey: "",
			client_pod.AppLabelKey:      client_pod.AppLabelValue,
			workloadPodLabelKey:         workloadPodLabelValue,
			fmt.Sprintf("%s%d", utils.SelectorLabelKeySuffix, labelNum): fmt.Sprintf("%s%d", utils.SelectorLabelValueSuffix, labelNum),
		}
		serverPod.Spec.Affinity = &client_pod.RealNodeAffinity
		serverPods = append(serverPods, serverPod)
	}

	return
}

func ScaleUpWorkloadPods(ctx context.Context, ch chan time.Duration, data *ScaleData) (res ScaleResult) {
	var err error
	defer func() {
		res.err = err
	}()
	if data.Specification.SkipDeployWorkload {
		klog.V(2).InfoS("Skip creating workload Pods", "SkipDeployWorkload", data.Specification.SkipDeployWorkload)
		return
	}
	// Creating workload Pods
	start := time.Now()
	podNum := data.Specification.PodsNumPerNs
	res.scaleNum = len(data.namespaces) * podNum
	serviceNumPerNs := data.Specification.SvcNumPerNs
	count := 0
	for _, ns := range data.namespaces {
		gErr, _ := errgroup.WithContext(context.Background())
		var pods []*corev1.Pod
		pods, err = renderServerPods(data.templateFilesPath, ns, podNum, serviceNumPerNs)
		if err != nil {
			return
		}
		for i := range pods {
			pod := pods[i]
			gErr.Go(func() error {
				if _, err := data.kubernetesClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
					return err
				}
				return nil
			})
		}
		klog.V(2).InfoS("Create workload Pods", "PodNum", podNum, "Namespace", ns, "Pods", len(pods))
		if err = gErr.Wait(); err != nil {
			return
		}

		// Waiting scale workload Pods to be ready
		err = wait.PollUntil(config.WaitInterval, func() (bool, error) {
			podsResult, err := data.kubernetesClientSet.
				CoreV1().Pods(ns).
				List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", client_pod.AppLabelKey, client_pod.AppLabelValue)})
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
			return
		}

		if count < data.maxCheckNum {
			ch <- time.Since(start)
			count++
		}
	}
	res.actualCheckNum = count
	klog.InfoS("Scaled up Pods", "Duration", time.Since(start), "count", podNum*len(data.namespaces))
	return res
}
