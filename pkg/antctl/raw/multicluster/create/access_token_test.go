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
	"log"
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

	secretContent := []byte(`apiVersion: v1
kind: Secret
metadata:
  name: default-member-token
data:
  ca.crt: YWJjZAo=
  namespace: ZGVmYXVsdAo=
  token: YWJjZAo=
type: Opaque`)

	tests := []struct {
		name           string
		namespace      string
		expectedOutput string
		secretFile     bool
		failureType    string
		tokeName       string
	}{
		{
			name:           "create successfully",
			tokeName:       "default-member-token",
			namespace:      "default",
			expectedOutput: "You can now run the \"antctl mc join\" command with the token to have the cluster join the ClusterSet\n",
		},
		{
			name:           "create successfully with file",
			tokeName:       "default-member-token",
			namespace:      "default",
			expectedOutput: "You can now run the \"antctl mc join\" command with the token to have the cluster join the ClusterSet\n",
			secretFile:     true,
		},
		{
			name:           "fail to create without name",
			namespace:      "default",
			expectedOutput: "exactly one NAME is required, got 0",
		},
		{
			name:           "fail to create without namespace",
			namespace:      "",
			expectedOutput: "the Namespace is required",
		},
		{
			name:           "fail to create and rollback",
			namespace:      "default",
			failureType:    "create",
			tokeName:       "default-member-token",
			expectedOutput: "failed to create object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewAccessTokenCmd()
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
			if tt.tokeName != "" {
				cmd.SetArgs([]string{tt.tokeName})
			}
			if tt.secretFile {
				secret, err := os.CreateTemp("", "secret")
				if err != nil {
					log.Fatal(err)
				}
				defer os.Remove(secret.Name())
				secret.Write([]byte(secretContent))
				memberTokenOpts.output = secret.Name()
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
