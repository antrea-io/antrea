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

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// IsPodTerminated returns true if a pod is terminated, all containers are stopped and cannot ever regress.
func IsPodTerminated(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodFailed || pod.Status.Phase == v1.PodSucceeded
}

// GetPodContainerNames returns all the container names in a Pod, including init containers.
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

// UpdatePodNetworkStatusAnnotation update the Pod's network status annotation
func UpdatePodNetworkStatusAnnotation(kubeClient clientset.Interface, ctx context.Context, netStatus []netdefv1.NetworkStatus, podName, podNamespace string, isPrimary bool) error {
	if len(netStatus) == 0 {
		return nil
	}
	podItem, err := kubeClient.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get Pod:%w", err)
	}

	if isPrimary {
		// The secondary network Pod should have the k8s.v1.cni.cncf.io/networks annotation; otherwise, return directly without updating the annotation.
		annotations := podItem.GetAnnotations()
		if annotations == nil {
			klog.V(2).InfoS("Skipping network status update for the Pod annotation is nil", "Pod", klog.KRef(podNamespace, podName))
			return nil
		}
		_, netObjExist := annotations[netdefv1.NetworkAttachmentAnnot]
		if !netObjExist {
			klog.V(2).InfoS("Skipping network status update for Pod without annotation "+netdefv1.NetworkAttachmentAnnot,
				"Pod", klog.KRef(podNamespace, podName))
			return nil
		}
	} else {
		oldNetworkStatus, err := netdefutilsGetNetworkStatus(podItem)
		if err != nil {
			return fmt.Errorf("error getting Pod network status annotation: %w", err)
		}
		netStatus = append(netStatus, oldNetworkStatus...)
	}

	if err := netdefutilsSetNetworkStatus(kubeClient, podItem, netStatus); err != nil {
		return fmt.Errorf("error setting Pod network status annotation: %w", err)
	}
	klog.V(2).InfoS("Pod network status annotation updated", "Pod", klog.KRef(podNamespace, podName), "NetworkStatus", netStatus)
	return nil
}
