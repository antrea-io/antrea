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

package k8s

import (
	"context"
	"fmt"
	"time"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// IsPodTerminated returns true if a pod is terminated, all containers are stopped and cannot ever regress.
func IsPodTerminated(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodFailed || pod.Status.Phase == v1.PodSucceeded
}

// GetPodContainersNames returns all the container names in a Pod, including init containers.
func GetPodContainerNames(pod *v1.Pod) []string {
	var names []string
	for _, c := range pod.Spec.InitContainers {
		names = append(names, c.Name)
	}
	for _, c := range pod.Spec.Containers {
		names = append(names, c.Name)
	}
	return names
}

var (
	netdefutilsSetNetworkStatus = netdefutils.SetNetworkStatus
	netdefutilsGetNetworkStatus = netdefutils.GetNetworkStatus
)

func UpdatePodAnnotation(kubeClient clientset.Interface, ctx context.Context, netStatus []netdefv1.NetworkStatus, podName, podNamespace string, isPrimary bool) error {
	// Update the Pod's network status annotation
	if netStatus == nil {
		return nil
	}
	var podItem *v1.Pod
	if err := wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Second, true, func(ctx context.Context) (done bool, err error) {
		podItem, err = kubeClient.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			klog.V(2).InfoS("Get Pod error", "Pod", klog.KRef(podNamespace, podName), "error", err)
			if errors.IsNotFound(err) {
				return false, err
			}
			return false, nil
		}
		return true, nil
	}); err != nil {
		klog.ErrorS(err, "Failed to get Pod after retries", "Pod", klog.KRef(podNamespace, podName))
		return err
	}

	if isPrimary {
		annotations := podItem.GetAnnotations()
		if annotations == nil {
			return fmt.Errorf("skipping network status update as the Pod annotation is nil")
		}
		_, netObjExist := annotations[netdefv1.NetworkAttachmentAnnot]
		if !netObjExist {
			klog.V(2).InfoS("Skipping network status update for Pod without annotation "+netdefv1.NetworkAttachmentAnnot,
				"Pod", klog.KRef(podNamespace, podName))
			return fmt.Errorf("skipping network status update as the Pod without annotation %s", netdefv1.NetworkAttachmentAnnot)
		}
	} else {
		oldNetworkStatus, err := netdefutilsGetNetworkStatus(podItem)
		if err != nil {
			klog.ErrorS(err, "Error getting Pod network status annotation", "Pod", klog.KRef(podNamespace, podName))
		} else {
			netStatus = append(netStatus, oldNetworkStatus...)
		}
	}

	if err := netdefutilsSetNetworkStatus(kubeClient, podItem, netStatus); err != nil {
		klog.ErrorS(err, "Error setting Pod network status annotation", "Pod", klog.KRef(podNamespace, podName))
	} else {
		klog.V(2).InfoS("Pod network status annotation updated", "Pod", klog.KRef(podNamespace, podName), "NetworkStatus", netStatus)
	}
	return nil
}
