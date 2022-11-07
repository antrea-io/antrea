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

package create

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestCreateAccessToken(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
		},
		Data: map[string][]byte{"token": []byte("12345")},
	}

	secretContent := []byte(`# Manifest to create a Secret for an Antrea Multi-cluster member token.
---
apiVersion: v1
data:
  token: MTIzNDU=
kind: Secret
metadata:
  creationTimestamp: null
  name: default-member-token
type: Opaque
`)

	tests := []struct {
		name           string
		namespace      string
		expectedOutput string
		secretFile     string
		failureType    string
		tokenName      string
	}{
		{
			name:           "create successfully",
			tokenName:      "default-member-token",
			namespace:      "default",
			expectedOutput: "You can now run \"antctl mc join\" command with the token in a member cluster to join the ClusterSet\n",
		},
		{
			name:           "create successfully with file",
			tokenName:      "default-member-token",
			namespace:      "default",
			expectedOutput: "You can now run \"antctl mc join\" command with the token in a member cluster to join the ClusterSet\n",
			secretFile:     "test.yml",
		},
		{
			name:           "fail to create without name",
			namespace:      "default",
			expectedOutput: "token name must be specified",
		},
		{
			name:           "fail to create without Namespace",
			namespace:      "",
			expectedOutput: "Namespace must be specified",
		},
		{
			name:           "fail to create and rollback",
			namespace:      "default",
			failureType:    "create",
			tokenName:      "default-member-token",
			expectedOutput: "failed to create object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewMemberTokenCmd()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			memberTokenOpts.namespace = tt.namespace
			memberTokenOpts.k8sClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(existingSecret).Build()
			if tt.failureType == "create" {
				memberTokenOpts.k8sClient = common.FakeCtrlRuntimeClient{
					Client:      fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(existingSecret).Build(),
					ShouldError: true,
				}
			}
			if tt.secretFile != "" {
				memberTokenOpts.output = tt.secretFile
			}

			if tt.tokenName != "" {
				cmd.SetArgs([]string{tt.tokenName})
			}
			err := cmd.Execute()
			if tt.secretFile != "" {
				defer os.Remove(tt.secretFile)
				yamlFile, _ := os.ReadFile(tt.secretFile)

				assert.Equal(t, string(yamlFile), string(secretContent))
			}
			if err != nil {
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.Contains(t, buf.String(), tt.expectedOutput)
			}
		})
	}
}
