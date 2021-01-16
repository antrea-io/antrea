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
	"context"
	"encoding/json"
	"fmt"

	"github.com/vmware-tanzu/antrea/pkg/util/env"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

const (
	NPLAnnotationKey          = "nodeportlocal.antrea.io"
	NPLEnabledAnnotationKey   = "nodeportlocal.antrea.io/enabled"
	NPLEnabledAnnotationIndex = "nplEnabledAnnotation"
)

// NPLAnnotation is the structure used for setting NodePortLocal annotation on the Pods.
type NPLAnnotation struct {
	PodPort  int    `json:"podPort"`
	NodeIP   string `json:"nodeIP"`
	NodePort int    `json:"nodePort"`
}

// ParsePodNPLAnnotations parses a Pod's annotation belonging to NPL and returns
// a list of NPLAnnotation. Returns an error if no NPL annotation is found for a Pod
func ParsePodNPLAnnotations(pod corev1.Pod) ([]NPLAnnotation, error) {
	var result []NPLAnnotation
	annotations := pod.GetAnnotations()
	nplAnnotation, ok := annotations[NPLAnnotationKey]
	if !ok {
		return result, fmt.Errorf("Pod %s/%s doesn't contain NPL annotation", pod.Namespace, pod.Name)
	}
	if err := json.Unmarshal([]byte(nplAnnotation), &result); err != nil {
		return result, fmt.Errorf("NPL annotations for Pod %s/%s couldn't be parsed with error %s",
			pod.Namespace, pod.Name, err.Error())
	}
	return result, nil
}

// IsAnnotationDifferent compares two sets of NPL Annotations. If there's any difference, we
// return true, else false
func IsAnnotationDifferent(old, new []NPLAnnotation) bool {
	type NodeIPPort struct {
		NodeIP   string
		NodePort int
	}
	if len(old) != len(new) {
		return true
	}
	visitedPorts := make(map[int]NodeIPPort)
	for _, ann := range old {
		visitedPorts[ann.PodPort] = NodeIPPort{
			NodeIP:   ann.NodeIP,
			NodePort: ann.NodePort,
		}
	}
	for _, ann := range new {
		if np, ok := visitedPorts[ann.PodPort]; ok {
			if np.NodeIP != ann.NodeIP || np.NodePort != ann.NodePort {
				return true
			}
			continue
		}
		return true
	}
	return false
}

func toJSON(serialize interface{}) string {
	jsonMarshalled, _ := json.Marshal(serialize)
	return string(jsonMarshalled)
}

func isNodePortInAnnotation(s []NPLAnnotation, nodeport, cport int) bool {
	for _, i := range s {
		if i.NodePort == nodeport {
			if i.PodPort == cport {
				return true
			}
		}
	}
	return false
}

// PodNodePort is a mapping of NodePort assigned for a PodPort.
type PodNodePort struct {
	NodePort int
	PodPort  int
}

// AssignPodAnnotation creates an annotation for a Pod with the assigned nodePort, and
// updates it into the Pod, it returns true if an update to the Pod is required
func AssignPodAnnotation(pod *corev1.Pod, nodeIP string, containerPort, nodePort int) bool {
	var err error
	current := pod.Annotations
	if current == nil {
		current = make(map[string]string)
	}

	klog.V(2).Infof("Building annotation for Pod: %s\tport: %v --> %v:%v", pod.Name, containerPort, nodeIP, nodePort)

	var annotations []NPLAnnotation
	if current[NPLAnnotationKey] != "" {
		if err = json.Unmarshal([]byte(current[NPLAnnotationKey]), &annotations); err != nil {
			klog.Warningf("Unable to unmarshal NodePortLocal annotation: %v", current[NPLAnnotationKey])
		}

		if isNodePortInAnnotation(annotations, nodePort, containerPort) {
			// no updates required to the pod
			return false
		}

		annotations = append(annotations, NPLAnnotation{
			PodPort:  containerPort,
			NodeIP:   nodeIP,
			NodePort: nodePort,
		})
	} else {
		annotations = []NPLAnnotation{{
			PodPort:  containerPort,
			NodeIP:   nodeIP,
			NodePort: nodePort,
		}}
	}

	current[NPLAnnotationKey] = toJSON(annotations)
	pod.Annotations = current
	return true
}

func removePodAnnotation(pod *corev1.Pod) {
	klog.V(2).Infof("Removing entire NodePortLocal annotation from Pod: %s/%s", pod.Namespace, pod.Name)
	delete(pod.Annotations, NPLAnnotationKey)
}

func removeFromPodAnnotation(pod *corev1.Pod, containerPort int) {
	var err error
	current := pod.Annotations

	klog.V(2).Infof("Removing NodePortLocal annotation from Pod: %s/%s\tport: %v", pod.Namespace, pod.Name, containerPort)
	var annotations []NPLAnnotation
	if err = json.Unmarshal([]byte(current[NPLAnnotationKey]), &annotations); err != nil {
		klog.Warningf("Unable to unmarshal NodePortLocal annotation: %v", current[NPLAnnotationKey])
		return
	}

	for i, ann := range annotations {
		if ann.PodPort == containerPort {
			annotations = append(annotations[:i], annotations[i+1:]...)
			break
		}
	}

	current[NPLAnnotationKey] = toJSON(annotations)
	pod.Annotations = current
}

// RemoveNPLAnnotationFromPods removes npl annotations from all Pods.
func (c *NPLController) RemoveNPLAnnotationFromPods() {
	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Warningf("Failed to get Node's name, NodePortLocal annotation cannot be removed for Pods scheduled to this Node")
		return
	}
	podList, err := c.kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{
		FieldSelector:   "spec.nodeName=" + nodeName,
		ResourceVersion: "0",
	})
	if err != nil {
		klog.Warningf("Unable to list Pods, err: %v", err)
		return
	}
	for i, pod := range podList.Items {
		if _, exists := pod.Annotations[NPLAnnotationKey]; !exists {
			continue
		}
		removePodAnnotation(&podList.Items[i])
		c.updatePodAnnotation(&podList.Items[i])
	}
	klog.Infof("Removed all NodePortLocal annotations from all Pods")
}

func (c *NPLController) updatePodAnnotation(pod *corev1.Pod) error {
	if _, err := c.kubeClient.CoreV1().Pods(pod.Namespace).Update(context.TODO(), pod, metav1.UpdateOptions{}); err != nil {
		klog.Warningf("Unable to update annotation for Pod %s/%s, error: %v", pod.Namespace, pod.Name, err)
		return err
	}
	klog.V(2).Infof("Successfully updated annotation for Pod %s/%s", pod.Namespace, pod.Name)
	return nil
}
