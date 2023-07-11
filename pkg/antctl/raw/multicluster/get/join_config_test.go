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

package get

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

var (
	clusterSet1 = &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-multi-cluster",
			Name:      "clusterset1",
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
				},
			},
		},
	}
	invalidClusterSet = &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-multi-cluster",
			Name:      "invalidClusterSet",
		},
		// No leader cluster in Spec.
		Spec:   mcv1alpha2.ClusterSetSpec{},
		Status: mcv1alpha2.ClusterSetStatus{},
	}

	tokenSecret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-multi-cluster",
			Name:      "default-member-token",
		},
		Data: map[string][]byte{"token": []byte("12345")},
	}

	jcOutput = `---
apiVersion: multicluster.antrea.io/v1alpha1
kind: ClusterSetJoinConfig
clusterSetID: clusterset1
leaderClusterID: leader1
leaderNamespace: antrea-multi-cluster
leaderAPIServer: https://localhost
#clusterID: ""
#namespace: ""
# Use the pre-created token Secret.
#tokenSecretName: ""
# Create a token Secret with the manifest file.
#tokenSecretFile: ""
`

	tkOutput = `# Manifest to create a Secret for an Antrea Multi-cluster member token.
---
apiVersion: v1
data:
  token: MTIzNDU=
kind: Secret
metadata:
  creationTimestamp: null
  name: default-member-token
type: Opaque
`
)

func TestJoinConfig(t *testing.T) {
	cmd := NewJoinConfigCommand()
	buf := new(bytes.Buffer)
	cmd.SetOutput(buf)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	joinConfigOpts.namespace = "antrea-multi-cluster"

	kcFile, err := createFakeKubeconfigFile()
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(kcFile)
	kcOption := ""
	cmd.Flags().StringVarP(&kcOption, "kubeconfig", "k", kcFile, "path of kubeconfig")

	tests := []struct {
		name           string
		clusterSets    []*mcv1alpha2.ClusterSet
		secret         *corev1.Secret
		tokenName      string
		expectedOutput string
	}{
		{
			name:           "successful get",
			clusterSets:    []*mcv1alpha2.ClusterSet{clusterSet1},
			expectedOutput: jcOutput,
		},
		{
			name:           "no ClusterSet",
			expectedOutput: "No ClusterSet found in Namespace",
		},
		{
			name:           "invalid ClusterSet",
			clusterSets:    []*mcv1alpha2.ClusterSet{invalidClusterSet},
			expectedOutput: "Invalid ClusterSet",
		},
		{
			name:           ">1 ClusterSets",
			clusterSets:    []*mcv1alpha2.ClusterSet{clusterSet1, invalidClusterSet},
			expectedOutput: "More than one ClusterSets in Namespace",
		},
		{
			name:           "get with token",
			clusterSets:    []*mcv1alpha2.ClusterSet{clusterSet1},
			secret:         tokenSecret,
			tokenName:      tokenSecret.Name,
			expectedOutput: jcOutput + tkOutput,
		},
		{
			name:           "non-existing token",
			tokenName:      "token0",
			clusterSets:    []*mcv1alpha2.ClusterSet{clusterSet1},
			expectedOutput: "secrets \"token0\" not found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{}
			for _, cs := range tt.clusterSets {
				objs = append(objs, cs)
			}
			if tt.secret != nil {
				objs = append(objs, tt.secret)
			}
			joinConfigOpts.k8sClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(objs...).Build()
			joinConfigOpts.memberToken = tt.tokenName
			err := cmd.Execute()
			if err != nil {
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.Contains(t, buf.String(), tt.expectedOutput)
			}
		})
	}
}

func TestOptValidate(t *testing.T) {
	tests := []struct {
		name string
		opts *joinConfigOptions
		err  error
	}{
		{
			name: "no Namespace",
			opts: &joinConfigOptions{
				k8sClient: fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build(),
			},
			err: fmt.Errorf("Namespace must be specified"),
		},
		{
			name: "Namespace specified",
			opts: &joinConfigOptions{
				namespace: "ns1",
				k8sClient: fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build(),
			},
			err: nil,
		},
		{
			name: "token specified",
			opts: &joinConfigOptions{
				namespace:   "ns1",
				memberToken: "token1",
				k8sClient:   fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build(),
			},
			err: nil,
		},
		{
			name: "K8s client error",
			opts: &joinConfigOptions{
				namespace: "ns1",
			},
			err: fmt.Errorf("flag accessed but not defined: kubeconfig"),
		},
	}

	cmd := &cobra.Command{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.validateAndComplete(cmd)
			assert.Equal(t, tt.err, err)
		})
	}
}

func createFakeKubeconfigFile() (string, error) {
	fakeKubeconfig := []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: data
    server: https://localhost
  name: fake-cluster
contexts:
- context:
    cluster:  fake-cluster
    user:  user-id
  name:  fake-cluster
current-context:  fake-cluster
kind: Config`)

	fileName := "fakeKubeconfig"
	kcFile, err := os.CreateTemp("", fileName)
	if err != nil {
		return "", err
	}
	if _, err = kcFile.Write(fakeKubeconfig); err != nil {
		return "", err
	}
	kcFile.Close()
	return kcFile.Name(), nil
}
