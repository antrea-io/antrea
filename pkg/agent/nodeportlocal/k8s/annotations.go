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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
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

func toJSON(serialize interface{}) string {
	jsonMarshalled, _ := json.Marshal(serialize)
	return string(jsonMarshalled)
}

func isNodePortInAnnotation(s []NPLAnnotation, nodeport, cport int) bool {
	for _, i := range s {
		if i.NodePort == nodeport && i.PodPort == cport {
			return true
		}
	}
	return false
}

// IsNPLAnnotationRequired returns true if a new NodePortLocal annotation value is required. It
// checks for the Container Port, Node Port and the Pod IP in the existing list of the
// NodePortLocal annotation of the Pod.
func IsNPLAnnotationRequired(annotations map[string]string, nodeIP string, containerPort, nodePort int) bool {
	var nplAnnotations []NPLAnnotation
	if annotations[NPLAnnotationKey] != "" {
		if err := json.Unmarshal([]byte(annotations[NPLAnnotationKey]), &nplAnnotations); err != nil {
			klog.Warningf("Unable to unmarshal NodePortLocal annotation: %v", annotations[NPLAnnotationKey])
		}
	}
	if isNodePortInAnnotation(nplAnnotations, nodePort, containerPort) {
		// no updates required to the Pod
		return false
	}
	return true
}

func removeFromNPLAnnotation(annotations []NPLAnnotation, containerPort int) []NPLAnnotation {
	for i, ann := range annotations {
		if ann.PodPort == containerPort {
			annotations = append(annotations[:i], annotations[i+1:]...)
			break
		}
	}
	return annotations
}

func (c *NPLController) updatePodNPLAnnotation(pod *corev1.Pod, annotations []NPLAnnotation) error {
	if err := patchPod(annotations, pod, c.kubeClient); err != nil {
		klog.Warningf("Unable to patch NodePortLocal annotation for Pod %s/%s: %s", pod.Namespace, pod.Name, err.Error())
	}
	klog.V(2).Infof("Successfully updated NodePortLocal annotation for Pod %s/%s", pod.Namespace, pod.Name)
	return nil
}

func patchPod(value []NPLAnnotation, pod *corev1.Pod, kubeClient clientset.Interface) error {
	payloadValue := make(map[string]*string)
	if len(value) > 0 {
		valueStr := string(toJSON(value))
		payloadValue[NPLAnnotationKey] = &valueStr
	} else {
		payloadValue[NPLAnnotationKey] = nil
	}

	newPayload := map[string]interface{}{
		"metadata": map[string]map[string]*string{
			"annotations": payloadValue,
		},
	}

	payloadBytes, _ := json.Marshal(newPayload)
	if _, err := kubeClient.CoreV1().Pods(pod.Namespace).Patch(context.TODO(), pod.Name, types.MergePatchType,
		payloadBytes, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("unable to update NodePortLocal annotation for Pod %s/%s: %s", pod.Namespace,
			pod.Name, err.Error())
	}
	return nil
}
