//go:build !windows
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
	"reflect"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	NPLAnnotationKey          = "nodeportlocal.antrea.io"
	NPLEnabledAnnotationKey   = "nodeportlocal.antrea.io/enabled"
	NPLEnabledAnnotationIndex = "nplEnabledAnnotation"
)

// NPLAnnotation is the structure used for setting NodePortLocal annotation on the Pods.
type NPLAnnotation struct {
	PodPort   int      `json:"podPort"`
	NodeIP    string   `json:"nodeIP"`
	NodePort  int      `json:"nodePort"`
	Protocols []string `json:"protocols"`
}

func toJSON(serialize interface{}) string {
	jsonMarshalled, _ := json.Marshal(serialize)
	return string(jsonMarshalled)
}

func (c *NPLController) updatePodNPLAnnotation(pod *corev1.Pod, annotations []NPLAnnotation) error {
	if err := patchPod(annotations, pod, c.kubeClient); err != nil {
		klog.Warningf("Unable to patch NodePortLocal annotation for Pod %s/%s: %v", pod.Namespace, pod.Name, err)
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
		payloadBytes, metav1.PatchOptions{}, "status"); err != nil {
		return fmt.Errorf("unable to update NodePortLocal annotation for Pod %s/%s: %v", pod.Namespace,
			pod.Name, err)
	}
	return nil
}

// compareNPLAnnotationLists returns true if and only if the two lists contain the same set of
// annotations, irrespective of the order.
func compareNPLAnnotationLists(annotations1, annotations2 []NPLAnnotation) bool {
	if len(annotations1) != len(annotations2) {
		return false
	}
	nplAnnotationLess := func(a1, a2 *NPLAnnotation) bool {
		return a1.NodePort < a2.NodePort

	}
	sort.Slice(annotations1, func(i, j int) bool {
		return nplAnnotationLess(&annotations1[i], &annotations1[j])
	})
	sort.Slice(annotations2, func(i, j int) bool {
		return nplAnnotationLess(&annotations2[i], &annotations2[j])
	})
	return reflect.DeepEqual(annotations1, annotations2)
}
