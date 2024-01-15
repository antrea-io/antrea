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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"k8s.io/kubectl/pkg/util/podutils"

	"antrea.io/antrea/test/performance/config"
)

func Update(ctx context.Context, kClient kubernetes.Interface, ns, clientDaemonSetName string, probes []string, containerName string, desiredNum int) (clientPods []corev1.Pod, err error) {
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		daemonSet, err := kClient.AppsV1().DaemonSets(ns).Get(context.TODO(), clientDaemonSetName, metav1.GetOptions{})
		if err != nil {
			klog.ErrorS(err, "Error getting DaemonSet", "Name", clientDaemonSetName)
			return err
		}
		for _, existedContainer := range daemonSet.Spec.Template.Spec.Containers {
			if existedContainer.Name == containerName {
				klog.InfoS("Container already existed", "ContainerName", containerName, "DaemonSet", clientDaemonSetName)
				return nil
			}
		}
		var containers []corev1.Container
		for _, probe := range probes {
			l := strings.Split(probe, ":")
			server, port := l[0], l[1]
			if server == "" {
				server = "$NODE_IP"
			}
			containers = append(containers, corev1.Container{
				Name:            containerName,
				Image:           "busybox",
				Command:         []string{"/bin/sh", "-c", fmt.Sprintf("server=%s; output_file=\"ping_log.txt\"; if [ ! -e \"$output_file\" ]; then touch \"$output_file\"; fi; last_status=\"unknown\"; last_change_time=$(adjtimex | awk '/(time.tv_sec|time.tv_usec):/ { printf(\"%%06d\", $2) }' && printf \"\\n\"); while true; do status=$(nc -vz -w 1 \"$server\" %s > /dev/null && echo \"up\" || echo \"down\"); current_time=$(adjtimex | awk '/(time.tv_sec|time.tv_usec):/ { printf(\"%%06d\", $2) }' && printf \"\\n\"); time_diff=$((current_time - last_change_time)); if [ \"$status\" != \"$last_status\" ]; then echo \"$current_time Status changed from $last_status to $status after ${time_diff} seconds\"; echo \"$current_time Status changed from $last_status to $status after ${time_diff} seconds\" >> \"$output_file\"; last_change_time=$current_time; last_status=$status; fi; sleep 0.1; done\n", server, port)},
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
		daemonSet.Spec.Template.Spec.Containers = append(daemonSet.Spec.Template.Spec.Containers, containers...)

		_, err = kClient.AppsV1().DaemonSets(ns).Update(context.TODO(), daemonSet, metav1.UpdateOptions{})
		return err
	})

	if err != nil {
		klog.ErrorS(err, "Error updating DaemonSet", "Name", clientDaemonSetName)
		return
	}

	klog.InfoS("DaemonSet updated successfully!", "Name", clientDaemonSetName)

	if err := wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
		ds, err := kClient.AppsV1().DaemonSets(ns).Get(ctx, clientDaemonSetName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if ds.Generation != ds.Status.ObservedGeneration {
			return false, nil
		}
		if ds.Status.DesiredNumberScheduled != ds.Status.NumberAvailable {
			return false, nil
		}
		podList, err := kClient.CoreV1().Pods(ClientPodsNamespace).List(ctx, metav1.ListOptions{LabelSelector: ScaleClientPodTemplateName})
		if err != nil {
			return false, fmt.Errorf("error when getting scale test client pods: %w", err)
		}
		if len(podList.Items) != desiredNum {
			return false, nil
		}
		for i := range podList.Items {
			pod := podList.Items[i]
			if pod.DeletionTimestamp != nil || !podutils.IsPodReady(&pod) {
				return false, nil
			}
		}
		clientPods = podList.Items
		klog.InfoS("All Pods in DaemonSet updated successfully!", "Name", clientDaemonSetName, "PodNum", len(podList.Items))
		return true, nil
	}, ctx.Done()); err != nil {
		return nil, fmt.Errorf("error when waiting scale test clients to be ready: %w", err)
	}
	return
}
