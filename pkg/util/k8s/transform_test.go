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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestTrimK8sObject(t *testing.T) {
	tests := []struct {
		name    string
		trimmer cache.TransformFunc
		obj     interface{}
		want    interface{}
	}{
		{
			name:    "pod",
			trimmer: NewTrimmer(TrimPod),
			obj: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					UID:       "test-uid",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       "DaemonSet",
							Name:       "test-daemonset",
							UID:        "5a39d3c8-0f5f-4aad-94bf-315c4fe11320",
						},
					},
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							APIVersion: "v1",
							FieldsType: "FieldsV1",
						},
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name: "container-0",
					}},
					Containers: []corev1.Container{{
						Name:    "container-1",
						Command: []string{"foo", "bar"},
						Args:    []string{"--a=b"},
						Env:     []corev1.EnvVar{{Name: "foo", Value: "bar"}},
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{
							Type:   corev1.PodReady,
							Status: corev1.ConditionTrue,
						},
					},
					PodIP: "1.2.3.4",
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
			want: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					UID:       "test-uid",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "container-1",
					}},
					NodeName: "nodeA",
				},
				Status: corev1.PodStatus{
					PodIP: "1.2.3.4",
					PodIPs: []corev1.PodIP{
						{IP: "1.2.3.4"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.trimmer(tt.obj)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
