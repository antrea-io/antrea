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
	"encoding/json"

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
			port := int(cport.ContainerPort)
			if c.portTable.RuleExists(podIP, port) {
				continue
			}
			nodePort, err := c.portTable.AddRule(podIP, port)
			if err != nil {
				return err
			}
			assignPodAnnotation(pod, nodeIP, port, nodePort)
		}
	}
	return nil
}

// HandleDeletePod handles pod annotations for a deleted pod.
func (c *Controller) HandleDeletePod(key string) error {
	klog.Infof("Got delete event for pod: %s", key)
	podIP, found := c.PodToIP[key]
	if !found {
		klog.Infof("IP address not found for pod: %s", key)
		return nil
	}
	data := c.portTable.GetDataForPodIP(podIP)
	for _, d := range data {
		err := c.portTable.DeleteRule(d.PodIP, int(d.PodPort))
		if err != nil {
			return err
		}
	}
	return nil
}

// HandleAddUpdatePod handles Pod Add, Update events and updates annotation is required
func (c *Controller) HandleAddUpdatePod(key string, obj interface{}) error {
	newPod := obj.(*corev1.Pod).DeepCopy()
	klog.Infof("Got add/update event for pod: %s", key)

	podIP := newPod.Status.PodIP
	if podIP == "" {
		klog.Infof("IP address not found for pod: %s/%s", newPod.Namespace, newPod.Name)
		return nil
	}
	c.PodToIP[key] = podIP

	var err error
	var updatePodAnnotation bool
	newPodPorts := make(map[int]struct{})
	newPodContainers := newPod.Spec.Containers
	for _, container := range newPodContainers {
		for _, cport := range container.Ports {
			port := int(cport.ContainerPort)
			newPodPorts[port] = struct{}{}
			if !c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				err = c.addRuleForPod(newPod)
				if err != nil {
					return err
				}
				updatePodAnnotation = true
			}
		}
	}

	var annotations []NPLAnnotation
	podAnnotation := newPod.GetAnnotations()
	entries := c.portTable.GetDataForPodIP(podIP)
	if podAnnotation != nil {
		if err := json.Unmarshal([]byte(podAnnotation[NPLAnnotationStr]), &annotations); err != nil {
			klog.Warningf("Unable to unmarshal NPLEP annotation")
			return nil
		}
		for _, data := range entries {
			if _, exists := newPodPorts[data.PodPort]; !exists {
				removeFromPodAnnotation(newPod, data.PodPort)
				err := c.portTable.DeleteRule(podIP, int(data.PodPort))
				if err != nil {
					return err
				}
				updatePodAnnotation = true
			}
		}
	}

	if updatePodAnnotation {
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
