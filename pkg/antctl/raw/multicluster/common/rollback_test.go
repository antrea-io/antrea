// Copyright 2026 Antrea Authors
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

package common

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha2"
	multiclusterscheme "antrea.io/antrea/v2/pkg/antctl/raw/multicluster/scheme"
)

func TestRollback(t *testing.T) {
	tests := []struct {
		name            string
		createdRes      []map[string]interface{}
		existingObjects []client.Object
		expectedOutput  string
		expectError     bool
	}{
		{
			name: "rollback multiple resources",
			createdRes: []map[string]interface{}{
				{
					"apiVersion": "v1",
					"kind":       "Secret",
					"metadata": map[string]interface{}{
						"name":      "test-secret",
						"namespace": "default",
					},
				},
				{
					"apiVersion": "multicluster.crd.antrea.io/v1alpha1",
					"kind":       "ClusterSet",
					"metadata": map[string]interface{}{
						"name":      "test-clusterset",
						"namespace": "default",
					},
				},
			},
			existingObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "default",
					},
				},
				&mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
				},
			},
			expectedOutput: "ClusterSet \"default/test-clusterset\" deleted\n",
			expectError:    false,
		},
		{
			name: "rollback fails with missing Kind",
			createdRes: []map[string]interface{}{
				{
					"apiVersion": "multicluster.crd.antrea.io/v1alpha1",
					"metadata": map[string]interface{}{
						"name":      "test-clusterset",
						"namespace": "default",
					},
				},
			},
			existingObjects: []client.Object{
				&mcv1alpha2.ClusterSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-clusterset",
						Namespace: "default",
					},
				},
			},
			expectedOutput: "Failed to delete",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(tt.existingObjects...).Build()
			err := Rollback(cmd, fakeClient, tt.createdRes)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Contains(t, buf.String(), tt.expectedOutput)
		})
	}
}
