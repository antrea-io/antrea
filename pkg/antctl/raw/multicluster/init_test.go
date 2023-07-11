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

package multicluster

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestInit(t *testing.T) {
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
		},
		Data: map[string][]byte{"token": []byte("12345")},
	}

	cmd := NewInitCommand()
	buf := new(bytes.Buffer)
	cmd.SetOutput(buf)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.Flag("clusterset").Value.Set("test-clusterset")

	initOpts.namespace = "default"
	initOpts.clusterSet = "test-clusterset"
	initOpts.clusterID = "cluster-id"
	initOpts.createToken = true

	fakeConfigs := []byte(`apiVersion: v1
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

	var err error
	fakeKubeconfig, err := os.CreateTemp("", "fakeKubeconfig")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(fakeKubeconfig.Name())
	fakeKubeconfig.Write(fakeConfigs)
	kubeconfig := ""
	cmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", fakeKubeconfig.Name(), "path of kubeconfig")

	tests := []struct {
		name           string
		namespace      string
		expectedOutput string
		failureType    string
		outputToFile   bool
	}{
		{
			name:      "init successfully",
			namespace: "default",
			expectedOutput: `ClusterSet "test-clusterset" created in Namespace default
Successfully initialized ClusterSet test-clusterset
You can run command "antctl mc get joinconfig -n default" to print the parameters needed for a member cluster to join the ClusterSet.
ServiceAccount "default-member-token" created
RoleBinding "default-member-token" created
Secret "default-member-token" already exists
`,
		},
		{
			name:           "init fail due to empty Namespace",
			namespace:      "",
			expectedOutput: "Namespace must be specified",
		},
		{
			name:           "fail to create and rollback",
			namespace:      "default",
			failureType:    "create",
			expectedOutput: "failed to create object",
		},
		{
			name:           "init successfully with output",
			namespace:      "default",
			expectedOutput: "Saved ClusterSet join parameters to file:",
			outputToFile:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initOpts.k8sClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(existingSecret).Build()
			if tt.failureType == "create" {
				initOpts.k8sClient = common.FakeCtrlRuntimeClient{
					Client:      fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithObjects(existingSecret).Build(),
					ShouldError: true,
				}
			}
			cmd.Flag("namespace").Value.Set(tt.namespace)
			if tt.outputToFile {
				output, err := os.CreateTemp("", "output")
				if err != nil {
					log.Fatal(err)
				}
				defer os.Remove(output.Name())
				initOpts.output = output.Name()
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

func TestInitOptValidate(t *testing.T) {
	tests := []struct {
		name           string
		expectedOutput string
		opts           *initOptions
	}{
		{
			name:           "empty Namespace",
			expectedOutput: "Namespace must be specified",
			opts:           &initOptions{clusterID: "cluster-a"},
		},
		{
			name:           "empty ClusterSet",
			expectedOutput: "ClusterSet must be provided",
			opts: &initOptions{
				clusterID: "cluster-a",
				namespace: "default",
			},
		},
		{
			name:           "empty ClusterID",
			expectedOutput: "ClusterID must be provided",
			opts: &initOptions{
				clusterSet: "clusterset-a",
				namespace:  "default",
			},
		},
	}

	cmd := &cobra.Command{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.validate(cmd)
			if err != nil {
				assert.Equal(t, tt.expectedOutput, err.Error())
			} else {
				t.Error("Expected to get error but got nil")
			}
		})
	}
}
