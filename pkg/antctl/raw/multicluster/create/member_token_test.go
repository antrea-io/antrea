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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	"antrea.io/antrea/v2/pkg/antctl/raw/multicluster/common"
	mcscheme "antrea.io/antrea/v2/pkg/antctl/raw/multicluster/scheme"
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
		clusterID      string
		existingSA     *corev1.ServiceAccount
	}{
		{
			name:           "create successfully",
			tokenName:      "default-member-token",
			namespace:      "default",
			clusterID:      "cluster-east",
			expectedOutput: "You can now run \"antctl mc join\" command with the token in a member cluster to join the ClusterSet\n",
		},
		{
			name:           "create successfully with file",
			tokenName:      "default-member-token",
			namespace:      "default",
			clusterID:      "cluster-east",
			expectedOutput: "You can now run \"antctl mc join\" command with the token in a member cluster to join the ClusterSet\n",
			secretFile:     "test.yml",
		},
		{
			name:           "fail to create without name",
			namespace:      "default",
			clusterID:      "cluster-east",
			expectedOutput: "token name must be specified",
		},
		{
			name:           "fail to create without Namespace",
			namespace:      "",
			clusterID:      "cluster-east",
			expectedOutput: "Namespace must be specified",
		},
		{
			name:           "fail to create without cluster-id",
			tokenName:      "default-member-token",
			namespace:      "default",
			clusterID:      "",
			expectedOutput: "--cluster-id must be specified",
		},
		{
			name:           "create successfully with cluster-id containing dots",
			tokenName:      "default-member-token",
			namespace:      "default",
			clusterID:      "cluster.east",
			expectedOutput: "You can now run \"antctl mc join\" command with the token in a member cluster to join the ClusterSet\n",
		},
		{
			name:           "fail to create with cluster-id too long",
			tokenName:      "default-member-token",
			namespace:      "default",
			clusterID:      strings.Repeat("a", 233),
			expectedOutput: "invalid cluster ID",
		},
		{
			name:           "fail to create and rollback",
			namespace:      "default",
			clusterID:      "cluster-east",
			failureType:    "create",
			tokenName:      "default-member-token",
			expectedOutput: "failed to create object",
		},
		{
			name:      "fail to create with prefix-conflicting cluster-id",
			tokenName: "default-member-token",
			namespace: "default",
			clusterID: "east",
			existingSA: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "east-1-token",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "east-1",
					},
				},
			},
			expectedOutput: "conflicts with the ClusterID",
		},
		{
			// The ServiceAccount being re-bound to the new ClusterID is not part of
			// the existing identity set, so correcting a mistyped ClusterID (or
			// renaming a member) to one that is a dash-delimited prefix of its old
			// value is not blocked by this check.
			name:      "create successfully when re-binding the prefix-conflicting ServiceAccount",
			tokenName: "default-member-token",
			namespace: "default",
			clusterID: "east",
			existingSA: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "default-member-token",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "east-1",
					},
				},
			},
			expectedOutput: "You can now run",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewMemberTokenCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			memberTokenOpts.namespace = tt.namespace
			memberTokenOpts.clusterID = tt.clusterID
			clientBuilder := fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(existingSecret)
			if tt.existingSA != nil {
				clientBuilder = clientBuilder.WithObjects(tt.existingSA)
			}
			memberTokenOpts.k8sClient = clientBuilder.Build()
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
