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

func (c *Controller) addRuleForPod(pod *corev1.Pod) error {
	podIP, nodeIP := pod.Status.PodIP, pod.Status.HostIP
	if podIP == "" || nodeIP == "" {
		return nil
	}
	podContainers := pod.Spec.Containers

	for _, container := range podContainers {
		for _, cport := range container.Ports {
			if c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				continue
			}
			port := fmt.Sprint(cport.ContainerPort)
			nodePort, err := c.portTable.AddRule(podIP, int(cport.ContainerPort))
			if err != nil {
				return err
			}
			assignPodAnnotation(pod, port, nodeIP, fmt.Sprint(nodePort))
		}
	}
	return nil
}

// HandleAddPod handles Pod annotations in NPL for an added pod.
func (c *Controller) HandleAddPod(key string, obj interface{}) error {
	oldObj, exists, _ := c.OldObjStore.GetByKey(key)
	if exists {
		defer c.OldObjStore.Delete(oldObj)
		return c.HandleUpdatePod(oldObj, obj)
	}

	pod := obj.(*corev1.Pod).DeepCopy()
	klog.Infof("Got add event for pod: %s/%s", pod.Namespace, pod.Name)
	err := c.addRuleForPod(pod)
	if err != nil {
		return err
	}
	if pod.Annotations[NPLAnnotationStr] != "" {
		return c.updatePodAnnotation(pod)
	}
	return nil
}

// HandleDeletePod handles pod annotations for a deleted pod.
func (c *Controller) HandleDeletePod(key string) error {
	obj, exists, err := c.OldObjStore.GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		klog.Infof("Could not find old object for key: %v", key)
		return nil
	}
	defer c.OldObjStore.Delete(obj)
	pod := obj.(*corev1.Pod)
	klog.Infof("Got delete event for pod: %s/%s", pod.Namespace, pod.Name)
	podIP := pod.Status.PodIP
	if podIP == "" {
		klog.Infof("IP address not found for pod: %s/%s", pod.Namespace, pod.Name)
		return nil
	}

	for _, container := range pod.Spec.Containers {
		for _, cport := range container.Ports {
			err = c.portTable.DeleteRule(podIP, int(cport.ContainerPort))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// HandleUpdatePod handles pod annotations for a updated pod.
func (c *Controller) HandleUpdatePod(oldObj, newObj interface{}) error {
	oldPod := oldObj.(*corev1.Pod)
	newPod := newObj.(*corev1.Pod).DeepCopy()

	klog.Infof("Got update for pod: %s/%s", newPod.Namespace, newPod.Name)
	podIP := newPod.Status.PodIP

	if podIP == "" {
		klog.Infof("IP address not found for pod: %s/%s", newPod.Namespace, newPod.Name)
		return nil
	}

	var err error
	newPodPorts := make(map[string]struct{})
	newPodContainers := newPod.Spec.Containers
	for _, container := range newPodContainers {
		for _, cport := range container.Ports {
			port := fmt.Sprint(cport.ContainerPort)
			newPodPorts[port] = struct{}{}
			if !c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				err = c.addRuleForPod(newPod)
				if err != nil {
					return err
				}
			}
		}
	}

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
					err := c.portTable.DeleteRule(podIP, int(cport.ContainerPort))
					if err != nil {
						return err
					}
					removeFromPodAnnotation(newPod, port)
				}
			}
		}
	}
	if podAnnotationChanged(newPod, oldPod) {
		return c.updatePodAnnotation(newPod)
	}
	return nil
}

func podAnnotationChanged(newPod, oldPod *corev1.Pod) bool {
	if newPod.Annotations[NPLAnnotationStr] != oldPod.Annotations[NPLAnnotationStr] {
		return true
	}
	return false
}
