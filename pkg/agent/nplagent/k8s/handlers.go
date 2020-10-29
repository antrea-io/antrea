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

	nplutils "github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/portcache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
)

var portTable *portcache.PortTable

func (c *Controller) addRuleForPod(pod *corev1.Pod) {
	podIP, nodeIP := pod.Status.PodIP, pod.Status.HostIP
	if podIP == "" || nodeIP == "" {
		return
	}
	podContainers := pod.Spec.Containers

	for _, container := range podContainers {
		for _, cport := range container.Ports {
			port := fmt.Sprint(cport.ContainerPort)
			nodePort, ok := c.PortTable.AddRule(podIP, int(cport.ContainerPort))
			if !ok {
				klog.Warningf("failed to add rule for podIP: %s, port: %d", podIP, cport.ContainerPort)
				continue
			}
			assignPodAnnotation(pod, port, nodeIP, fmt.Sprint(nodePort))
		}
	}
}

// HandleAddPod handles pod annotations in NPL for an added pod
func (c *Controller) HandleAddPod(pod *corev1.Pod) {
	klog.Infof("Got add event for pod: %s/%s", pod.Namespace, pod.Name)
	c.addRuleForPod(pod)
	c.updatePodAnnotation(pod)
}

// HandleDeletePod handles pod annotations for a deleted pod
func (c *Controller) HandleDeletePod(pod *corev1.Pod) {
	klog.Infof("Got delete event for pod: %s/%s", pod.Namespace, pod.Name)
	podIP := pod.Status.PodIP

	for _, container := range pod.Spec.Containers {
		for _, cport := range container.Ports {
			c.PortTable.DeleteRule(podIP, int(cport.ContainerPort))
		}
	}
}

// HandleUpdatePod handles pod annotations for a updated pod
func (c *Controller) HandleUpdatePod(old, newp *corev1.Pod) {
	klog.Infof("Got update for pod: %s/%s", newp.Namespace, newp.Name)
	podIP := newp.Status.PodIP

	// if the namespace of the pod has changed and has gone out of our scope, we need to delete it
	if old.Namespace != newp.Namespace {
		c.HandleDeletePod(newp)
		return
	}

	var newPodPorts []string
	newPodContainers := newp.Spec.Containers
	for _, container := range newPodContainers {
		for _, cport := range container.Ports {
			port := fmt.Sprint(cport.ContainerPort)
			newPodPorts = append(newPodPorts, port)
			if !c.PortTable.RuleExists(podIP, int(cport.ContainerPort)) {
				c.addRuleForPod(newp)
			}
		}
	}

	// oldPodPorts: [8080, 8081] newPodPorts: [8082, 8081] portsToRemove should have: [8080]
	oldPodContainers := old.Spec.Containers
	oldPodIP := old.Status.PodIP
	for _, container := range oldPodContainers {
		for _, cport := range container.Ports {
			port := fmt.Sprint(cport.ContainerPort)
			if !nplutils.HasElem(newPodPorts, port) {
				// removed port
				nodePort := getNodeportFromPodAnnotation(newp, port)
				if nodePort == "" && c.PortTable.GetEntryByPodIPPort(oldPodIP, int(cport.ContainerPort)) == nil {
					break
				}
				ok, _ := c.PortTable.DeleteRule(podIP, int(cport.ContainerPort))
				if ok {
					removeFromPodAnnotation(newp, port)
				}
			}
		}
	}
	c.updatePodAnnotation(newp)
}
