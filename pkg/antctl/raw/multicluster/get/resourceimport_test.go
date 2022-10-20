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
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestGetResourceImport(t *testing.T) {
	resourceImportList := &mcsv1alpha1.ResourceImportList{
		Items: []mcsv1alpha1.ResourceImport{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "ri-cluster-id-1",
				},
				Spec: mcsv1alpha1.ResourceImportSpec{
					Kind: "ServiceImport",
				},
			},
		},
	}
	tests := []struct {
		name                    string
		existingResourceImports *mcsv1alpha1.ResourceImportList
		args                    []string
		output                  string
		allNamespaces           bool
		donotFake               bool
		expectedOutput          string
	}{
		{
			name:                    "get single ResourceImport",
			existingResourceImports: resourceImportList,
			args:                    []string{"ri-cluster-id-1"},
			expectedOutput:          "NAMESPACE NAME            KIND         \ndefault   ri-cluster-id-1 ServiceImport\n",
		},
		{
			name:                    "get single ResourceImport with json output",
			existingResourceImports: resourceImportList,
			args:                    []string{"ri-cluster-id-1"},
			output:                  "json",
			expectedOutput:          "{\n  \"kind\": \"ResourceImport\",\n  \"apiVersion\": \"multicluster.crd.antrea.io/v1alpha1\",\n  \"metadata\": {\n    \"name\": \"ri-cluster-id-1\",\n    \"namespace\": \"default\",\n    \"resourceVersion\": \"999\",\n    \"creationTimestamp\": null\n  },\n  \"spec\": {\n    \"kind\": \"ServiceImport\"\n  },\n  \"status\": {}\n}\n",
		},
		{
			name:                    "get single ResourceImport with yaml output",
			existingResourceImports: resourceImportList,
			args:                    []string{"ri-cluster-id-1"},
			output:                  "yaml",
			expectedOutput:          "apiVersion: multicluster.crd.antrea.io/v1alpha1\nkind: ResourceImport\nmetadata:\n  creationTimestamp: null\n  name: ri-cluster-id-1\n  namespace: default\n  resourceVersion: \"999\"\nspec:\n  kind: ServiceImport\nstatus: {}\n",
		},
		{
			name:           "get non-existing ResourceImport",
			args:           []string{"ri-cluster-id-2"},
			expectedOutput: "resourceimports.multicluster.crd.antrea.io \"ri-cluster-id-2\" not found",
		},
		{
			name:          "get all ResourceImports",
			allNamespaces: true,
			existingResourceImports: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "ri-cluster-id-1",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "kube-system",
							Name:      "ri-cluster-id-2",
						},
					},
				},
			},
			expectedOutput: "NAMESPACE   NAME            KIND  \ndefault     ri-cluster-id-1 <NONE>\nkube-system ri-cluster-id-2 <NONE>\n",
		},
		{
			name:           "get all ResourceImports but empty result",
			allNamespaces:  true,
			expectedOutput: "No ResourceImport found\n",
		},
		{
			name:           "error to get a ResourceImport in all Namespaces",
			args:           []string{"ri-cluster-id-1"},
			allNamespaces:  true,
			expectedOutput: "a resource cannot be retrieved by name across all Namespaces",
		},
		{
			name:           "get all ResourceImports in default Namespace but empty result",
			expectedOutput: "No ResourceImport found in Namespace default\n",
		},
		{
			name:           "error due to no kubeconfig",
			expectedOutput: "flag accessed but not defined: kubeconfig",
			donotFake:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewResourceImportCommand()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			fakeClient := fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build()
			if tt.existingResourceImports != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithLists(tt.existingResourceImports).Build()

			}
			if !tt.donotFake {
				options.k8sClient = fakeClient
			}
			if tt.allNamespaces {
				options.allNamespaces = true
			}
			options.outputFormat = tt.output
			err := cmd.Execute()
			if err != nil {
				assert.Equal(t, tt.expectedOutput, err.Error())
			} else {
				assert.Equal(t, tt.expectedOutput, buf.String())
			}
		})
	}
}
