// +build !windows

// Copyright 2020 Antrea Authors
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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

func (c *Controller) addRuleForPod(pod *corev1.Pod) {
	podIP, nodeIP := pod.Status.PodIP, pod.Status.HostIP
	if podIP == "" || nodeIP == "" {
		return
	}
	podContainers := pod.Spec.Containers

	for _, container := range podContainers {
		for _, cport := range container.Ports {
			port := fmt.Sprint(cport.ContainerPort)
			nodePort, ok := c.portTable.AddRule(podIP, int(cport.ContainerPort))
			if !ok {
				klog.Warningf("Failed to add rule for podIP: %s, port: %d", podIP, cport.ContainerPort)
				continue
			}
			assignPodAnnotation(pod, port, nodeIP, fmt.Sprint(nodePort))
		}
	}
}

// HandleAddPod handles Pod annotations in NPL for an added pod.
func (c *Controller) HandleAddPod(obj interface{}) {
	klog.Infof("Got add pod")
	pod := obj.(*corev1.Pod).DeepCopy()
	klog.Infof("Got add event for pod: %s/%s", pod.Namespace, pod.Name)
	c.addRuleForPod(pod)
	if pod.Annotations[NPLAnnotationStr] != "" {
		c.updatePodAnnotation(pod)
	}
}

// HandleDeletePod handles pod annotations for a deleted pod.
func (c *Controller) HandleDeletePod(obj interface{}) {
	pod := obj.(*corev1.Pod).DeepCopy()
	klog.Infof("Got delete event for pod: %s/%s", pod.Namespace, pod.Name)
	podIP := pod.Status.PodIP
	if podIP == "" {
		klog.Infof("ip address not found for pod: %s/%s", pod.Namespace, pod.Name)
		return
	}

	for _, container := range pod.Spec.Containers {
		for _, cport := range container.Ports {
			c.portTable.DeleteRule(podIP, int(cport.ContainerPort))
		}
	}
}

// HandleUpdatePod handles pod annotations for a updated pod.
func (c *Controller) HandleUpdatePod(oldObj, newObj interface{}) {
	oldPod := oldObj.(*corev1.Pod).DeepCopy()
	newPod := newObj.(*corev1.Pod).DeepCopy()

	klog.Infof("Got update for pod: %s/%s", newPod.Namespace, newPod.Name)
	podIP := newPod.Status.PodIP

	if podIP == "" {
		return
	}

	newPodPorts := make(map[string]struct{})
	newPodContainers := newPod.Spec.Containers
	for _, container := range newPodContainers {
		for _, cport := range container.Ports {
			port := fmt.Sprint(cport.ContainerPort)
			newPodPorts[port] = struct{}{}
			//newPodPorts = append(newPodPorts, port)
			if !c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				c.addRuleForPod(newPod)
			}
		}
	}

	// Example - oldPodPorts: [8080, 8081], newPodPorts: [8082, 8081], portsToRemove should have: [8080].
	oldPodContainers := oldPod.Spec.Containers
	oldPodIP := oldPod.Status.PodIP

	if oldPodIP != "" {
		for _, container := range oldPodContainers {
			for _, cport := range container.Ports {
				port := fmt.Sprint(cport.ContainerPort)

				if _, ok := newPodPorts[port]; !ok {
					// The port has been removed.
					nodePort := getNodeportFromPodAnnotation(newPod, port)
					if nodePort == "" && c.portTable.GetEntryByPodIPPort(oldPodIP, int(cport.ContainerPort)) == nil {
						break
					}
					ok := c.portTable.DeleteRule(podIP, int(cport.ContainerPort))
					if ok {
						removeFromPodAnnotation(newPod, port)
					}
				}
			}
		}
	}
	if podAnnotationChanged(newPod, oldPod) {
		c.updatePodAnnotation(newPod)
	}
}

func podAnnotationChanged(newPod, oldPod *corev1.Pod) bool {
	if newPod.Annotations[NPLAnnotationStr] != oldPod.Annotations[NPLAnnotationStr] {
		return true
	}
	return false
}
