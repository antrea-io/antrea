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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	npltypes "antrea.io/antrea/v2/pkg/agent/nodeportlocal/types"
)

const NPLEnabledAnnotationIndex = "nplEnabledAnnotation"

func toJSON(serialize interface{}) string {
	jsonMarshalled, _ := json.Marshal(serialize)
	return string(jsonMarshalled)
}

func (c *NPLController) updatePodNPLAnnotation(ctx context.Context, pod *corev1.Pod, annotations []npltypes.NPLAnnotation) error {
	if err := patchPod(ctx, annotations, pod, c.kubeClient); err != nil {
		return fmt.Errorf("failed to patch NodePortLocal annotation for Pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	klog.V(2).InfoS("Successfully updated NodePortLocal annotation", "pod", klog.KObj(pod))
	return nil
}

func patchPod(ctx context.Context, value []npltypes.NPLAnnotation, pod *corev1.Pod, kubeClient clientset.Interface) error {
	payloadValue := make(map[string]*string)
	if len(value) > 0 {
		valueStr := string(toJSON(value))
		payloadValue[npltypes.NPLAnnotationKey] = &valueStr
	} else {
		payloadValue[npltypes.NPLAnnotationKey] = nil
	}

	newPayload := map[string]interface{}{
		"metadata": map[string]map[string]*string{
			"annotations": payloadValue,
		},
	}

	payloadBytes, _ := json.Marshal(newPayload)
	if _, err := kubeClient.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType,
		payloadBytes, metav1.PatchOptions{}, "status"); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("unable to update NodePortLocal annotation for Pod %s/%s: %v", pod.Namespace,
			pod.Name, err)
	}
	return nil
}

// compareNPLAnnotationLists returns true if and only if the two lists contain the same set of
// annotations, irrespective of the order.
func compareNPLAnnotationLists(annotations1, annotations2 []npltypes.NPLAnnotation) bool {
	if len(annotations1) != len(annotations2) {
		return false
	}
	nplAnnotationLess := func(a1, a2 *npltypes.NPLAnnotation) bool {
		if a1.NodePort != a2.NodePort {
			return a1.NodePort < a2.NodePort
		}
		// Use IPFamily for tie-breaking to ensure consistent ordering
		return a1.IPFamily < a2.IPFamily
	}
	sort.Slice(annotations1, func(i, j int) bool {
		return nplAnnotationLess(&annotations1[i], &annotations1[j])
	})
	sort.Slice(annotations2, func(i, j int) bool {
		return nplAnnotationLess(&annotations2[i], &annotations2[j])
	})
	return reflect.DeepEqual(annotations1, annotations2)
}
