// Copyright 2022 Antrea Authors
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

package delete

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestDeleteToken(t *testing.T) {
	secretContent := []byte(`apiVersion: v1
kind: Secret
metadata:
  name: default-member-token
data:
  ca.crt: YWJjZAo=
  namespace: ZGVmYXVsdAo=
  token: YWJjZAo=
type: Opaque`)
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
			Annotations: map[string]string{
				"multicluster.antrea.io/created-by-antctl": "true",
			},
		},
		Data: map[string][]byte{"token": secretContent},
	}

	existingRolebinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
			Annotations: map[string]string{
				"multicluster.antrea.io/created-by-antctl": "true",
			},
		},
	}

	existingServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
			Annotations: map[string]string{
				"multicluster.antrea.io/created-by-antctl": "true",
			},
		},
	}

	tests := []struct {
		name           string
		namespace      string
		expectedOutput string
		tokenName      string
	}{
		{
			name:           "delete successfully",
			tokenName:      "default-member-token",
			namespace:      "default",
			expectedOutput: "Secret default-member-token deleted",
		},
		{
			name:           "fail to delete without name",
			namespace:      "default",
			expectedOutput: "token name must be specified",
		},
		{
			name:           "fail to delete without namespace",
			namespace:      "",
			expectedOutput: "Namespace must be specified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewMemberTokenCmd()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			deleteTokenOpts.namespace = tt.namespace
			deleteTokenOpts.k8sClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(existingSecret, existingRolebinding, existingServiceAccount).Build()

			if tt.tokenName != "" {
				cmd.SetArgs([]string{tt.tokenName})
			}

			err := cmd.Execute()
			if err != nil {
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.Contains(t, buf.String(), tt.expectedOutput)
			}
		})
	}
}
