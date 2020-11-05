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

	"github.com/vmware-tanzu/antrea/pkg/util/env"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

const NPLAnnotationStr = "npl.antrea.io"

type NPLEPAnnotation struct {
	PodPort  string `json:"Podport"`
	NodeIP   string `json:"Nodeip"`
	NodePort string `json:"Nodeport"`
}

func Stringify(serialize interface{}) string {
	json_marshalled, _ := json.Marshal(serialize)
	return string(json_marshalled)
}

func IsNodePortInAnnotation(s []NPLEPAnnotation, nodeport string) bool {
	for _, i := range s {
		if i.NodePort == nodeport {
			return true
		}
	}
	return false
}

func assignPodAnnotation(pod *corev1.Pod, containerPort, nodeIP, nodePort string) {
	var err error
	current := make(map[string]string)
	if pod.Annotations != nil {
		current = pod.Annotations
	}

	klog.Infof("Building annotation for pod: %s\tport: %s --> %s:%s", pod.Name, containerPort, nodeIP, nodePort)

	var annotations []NPLEPAnnotation
	// nplEP annotation exists
	if current[NPLAnnotationStr] != "" {
		if err = json.Unmarshal([]byte(current[NPLAnnotationStr]), &annotations); err != nil {
			klog.Warningf("Unable to unmarshal NPLEP annotation")
		}

		if !IsNodePortInAnnotation(annotations, nodePort) {
			annotations = append(annotations, NPLEPAnnotation{
				PodPort:  containerPort,
				NodeIP:   nodeIP,
				NodePort: nodePort,
			})
		} else {
			// mapping for the containerPort already exists
			// TODO
		}
	} else {
		annotations = []NPLEPAnnotation{NPLEPAnnotation{
			PodPort:  containerPort,
			NodeIP:   nodeIP,
			NodePort: nodePort,
		}}
	}

	current[NPLAnnotationStr] = Stringify(annotations)
	pod.Annotations = current
}

func removeFromPodAnnotation(pod *corev1.Pod, containerPort string) {
	var err error
	current := pod.Annotations

	klog.Infof("Removing annotation from pod: %s\tport: %s", pod.Name, containerPort)
	var annotations []NPLEPAnnotation
	if err = json.Unmarshal([]byte(current[NPLAnnotationStr]), &annotations); err != nil {
		klog.Warningf("Unable to unmarshal NPLEP annotation")
		return
	}

	for i, ann := range annotations {
		if ann.PodPort == containerPort {
			annotations = append(annotations[:i], annotations[i+1:]...)
			break
		}
	}

	current[NPLAnnotationStr] = Stringify(annotations)
	pod.Annotations = current
}

// RemoveNPLAnnotationFromPods : Removes npl annotations from all pods
func (c *Controller) RemoveNPLAnnotationFromPods() {
	podList, err := c.KubeClient.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.Warningf("Unable to list Pods")
		return
	}
	nodeName, err := env.GetNodeName()
	if err != nil {
		klog.Warningf("Failed to get nodename, NPL annotation can not be removed for pods")
		return
	}
	for _, pod := range podList.Items {
		if nodeName != pod.Spec.NodeName {
			continue
		}
		podAnnotation := pod.GetAnnotations()
		if podAnnotation == nil {
			continue
		}
		klog.Infof("Removing all NPL annotation from pod: %s, ns: %s", pod.Name, pod.Namespace)
		delete(podAnnotation, NPLAnnotationStr)
		pod.Annotations = podAnnotation
		c.KubeClient.CoreV1().Pods(pod.Namespace).Update(context.TODO(), &pod, metav1.UpdateOptions{})
	}
}

func (c *Controller) updatePodAnnotation(pod *corev1.Pod) error {
	if _, err := c.KubeClient.CoreV1().Pods(pod.Namespace).Update(context.TODO(), pod, metav1.UpdateOptions{}); err != nil {
		klog.Warningf("Unable to update pod %s with annotation: %+v", pod.Name, err)
		return err
	}
	klog.Infof("Successfully updated pod %s %s annotation", pod.Name, pod.Namespace)
	return nil
}

// returns nodeport for podport
func getNodeportFromPodAnnotation(pod *corev1.Pod, port string) string {
	current := pod.Annotations
	var annotations []NPLEPAnnotation
	if err := json.Unmarshal([]byte(current[NPLAnnotationStr]), &annotations); err != nil {
		klog.Warningf("Unable to unmarshal NPLEP annotation")
		return ""
	}

	for _, i := range annotations {
		if i.PodPort == port {
			return i.NodePort
		}
	}

	klog.Warningf("Corresponding nodeport for pod: %s port: %s Not found", pod.Name, port)
	return ""
}
