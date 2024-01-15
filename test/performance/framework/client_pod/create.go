// Copyright 2024 Antrea Authors.
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

package client_pod

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

const (
	ScaleClientPodServerContainer          = "client-pod-server"
	ScaleClientPodProbeContainer           = "networkpolicy-client-probe"
	ScaleClientPodControllerProbeContainer = "controller-client-probe"
	ScaleTestPodProbeContainerName         = "antrea-scale-client-pod-probe"
)

func CreatePod(ctx context.Context, kClient kubernetes.Interface, probes []string, containerName, namespace string) (*corev1.Pod, error) {
	var err error
	var newPod *corev1.Pod
	podName := ScaleTestClientPodNamePrefix + uuid.New().String()[:6]
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		newPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
			},
			Spec: corev1.PodSpec{
				Affinity:    &RealNodeAffinity,
				Tolerations: []corev1.Toleration{MasterToleration},
				Containers: []corev1.Container{
					{
						Name:            ScaleClientPodServerContainer,
						Image:           "busybox",
						Command:         []string{"nc", "-lk", "-p", "80"},
						ImagePullPolicy: corev1.PullIfNotPresent,
					},
				},
			},
		}
		var containers []corev1.Container
		for _, probe := range probes {
			l := strings.Split(probe, ":")
			server, port := l[0], l[1]
			if server == "" {
				server = "$NODE_IP"
			}

			containers = append(containers, corev1.Container{
				Name:  containerName,
				Image: "busybox",
				// read up rest </proc/uptime; t1="${up%.*}${up#*.}"
				Command:         []string{"/bin/sh", "-c", fmt.Sprintf("server=%s; output_file=\"ping_log.txt\"; if [ ! -e \"$output_file\" ]; then touch \"$output_file\"; fi; last_status=\"unknown\"; last_change_time=$(adjtimex | awk '/(time.tv_sec|time.tv_usec):/ { printf(\"%%06d\", $2) }' && printf \"\\n\"); while true; do current_time=$(adjtimex | awk '/(time.tv_sec|time.tv_usec):/ { printf(\"%%06d\", $2) }' && printf \"\\n\"); status=$(nc -vz -w 1 \"$server\" %s > /dev/null && echo \"up\" || echo \"down\"); time_diff=$((current_time - last_change_time)); if [ \"$status\" != \"$last_status\" ]; then echo \"$current_time Status changed from $last_status to $status after ${time_diff} nanoseconds\"; echo \"$current_time Status changed from $last_status to $status after ${time_diff} nanoseconds\" >> \"$output_file\"; last_change_time=$current_time; last_status=$status; fi; sleep 0.1; done\n", server, port)},
				ImagePullPolicy: corev1.PullIfNotPresent,
				Env: []corev1.EnvVar{
					{
						Name: "NODE_IP",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "status.hostIP",
							},
						},
					},
				},
			})
		}

		newPod.Spec.Containers = append(newPod.Spec.Containers, containers...)

		_, err = kClient.CoreV1().Pods(namespace).Create(ctx, newPod, metav1.CreateOptions{})
		return err
	})
	if err != nil {
		return nil, err
	}

	err = wait.PollWithContext(ctx, 3*time.Second, 60*time.Second, func(ctx context.Context) (bool, error) {
		pod, err := kClient.CoreV1().Pods(namespace).Get(ctx, newPod.Name, metav1.GetOptions{})
		klog.V(4).InfoS("Checking client Pod status", "Name", newPod.Name, "Namespace", namespace, "Status", pod.Status)
		if err != nil {
			return false, err
		}
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		return nil, err
	}

	klog.InfoS("Create Client Pod successfully!")
	return newPod, nil
}

//
// func CreateClientPod(ctx context.Context, kClient kubernetes.Interface, namespace, podName string, probes []string, containerName string) (*corev1.Pod, error) {
//	var err error
//	expectContainerNum := 0
//	var newPod *corev1.Pod
//	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
//		pod, err := kClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
//		if err != nil {
//			return err
//		}
//		var containers []corev1.Container
//		for _, probe := range probes {
//			l := strings.Split(probe, ":")
//			server, port := l[0], l[1]
//			if server == "" {
//				server = "$NODE_IP"
//			}
//
//			containers = append(containers, corev1.Container{
//				Name:  containerName,
//				Image: "busybox",
//				// read up rest </proc/uptime; t1="${up%.*}${up#*.}"
//				Command:         []string{"/bin/sh", "-c", fmt.Sprintf("server=%s; output_file=\"ping_log.txt\"; if [ ! -e \"$output_file\" ]; then touch \"$output_file\"; fi; last_status=\"unknown\"; last_change_time=$(adjtimex | awk '/(time.tv_sec|time.tv_usec):/ { printf(\"%%06d\", $2) }' && printf \"\\n\"); while true; do current_time=$(adjtimex | awk '/(time.tv_sec|time.tv_usec):/ { printf(\"%%06d\", $2) }' && printf \"\\n\"); status=$(nc -vz -w 1 \"$server\" %s > /dev/null && echo \"up\" || echo \"down\"); time_diff=$((current_time - last_change_time)); if [ \"$status\" != \"$last_status\" ]; then echo \"$current_time Status changed from $last_status to $status after ${time_diff} nanoseconds\"; echo \"$current_time Status changed from $last_status to $status after ${time_diff} nanoseconds\" >> \"$output_file\"; last_change_time=$current_time; last_status=$status; fi; sleep 0.1; done\n", server, port)},
//				ImagePullPolicy: corev1.PullIfNotPresent,
//				Env: []corev1.EnvVar{
//					{
//						Name: "NODE_IP",
//						ValueFrom: &corev1.EnvVarSource{
//							FieldRef: &corev1.ObjectFieldSelector{
//								FieldPath: "status.hostIP",
//							},
//						},
//					},
//				},
//			})
//		}
//
//		pod.Spec.Containers = append(pod.Spec.Containers, containers...)
//		expectContainerNum = len(pod.Spec.Containers)
//
//		newPod = &corev1.Pod{
//			ObjectMeta: metav1.ObjectMeta{
//				Name:      strings.Replace(pod.Name, "server", "client", 1),
//				Namespace: pod.Namespace,
//				Labels:    pod.Labels,
//			},
//			Spec: pod.Spec,
//		}
//
//		_, err = kClient.CoreV1().Pods(namespace).Create(ctx, newPod, metav1.CreateOptions{})
//		return err
//	})
//	if err != nil {
//		return nil, err
//	}
//
//	err = wait.PollWithContext(ctx, 3*time.Second, 60*time.Second, func(ctx context.Context) (bool, error) {
//		pod, err := kClient.CoreV1().Pods(namespace).Get(ctx, newPod.Name, metav1.GetOptions{})
//		if err != nil {
//			return false, err
//		}
//
//		if expectContainerNum == len(pod.Spec.Containers) && pod.Status.Phase == corev1.PodRunning {
//			return true, nil
//		}
//		return false, nil
//	})
//
//	if err != nil {
//		return nil, err
//	}
//	klog.InfoS("Create Client Pod successfully!")
//	return newPod, nil
// }
