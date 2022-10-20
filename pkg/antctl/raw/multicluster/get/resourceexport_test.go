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

func TestGetResourceExport(t *testing.T) {
	resourceExportList := &mcsv1alpha1.ResourceExportList{
		Items: []mcsv1alpha1.ResourceExport{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "re-cluster-id-1",
				},
			},
		},
	}
	tests := []struct {
		name                    string
		existingResourceExports *mcsv1alpha1.ResourceExportList
		args                    []string
		flags                   map[string]string
		allNamespaces           bool
		donotFake               bool
		expectedOutput          string
	}{
		{
			name:                    "get single ResourceExport",
			existingResourceExports: resourceExportList,
			args:                    []string{"re-cluster-id-1"},
			expectedOutput:          "CLUSTER-ID NAMESPACE NAME            KIND  \n<NONE>     default   re-cluster-id-1 <NONE>\n",
		},
		{
			name:                    "get single ResourceExport with json output",
			existingResourceExports: resourceExportList,
			args:                    []string{"re-cluster-id-1"},
			flags:                   map[string]string{"output": "json"},
			expectedOutput:          "{\n  \"kind\": \"ResourceExport\",\n  \"apiVersion\": \"multicluster.crd.antrea.io/v1alpha1\",\n  \"metadata\": {\n    \"name\": \"re-cluster-id-1\",\n    \"namespace\": \"default\",\n    \"resourceVersion\": \"999\",\n    \"creationTimestamp\": null\n  },\n  \"spec\": {},\n  \"status\": {}\n}\n",
		},
		{
			name:                    "get single ResourceExport with yaml output",
			existingResourceExports: resourceExportList,
			args:                    []string{"re-cluster-id-1"},
			flags:                   map[string]string{"output": "yaml"},
			expectedOutput:          "apiVersion: multicluster.crd.antrea.io/v1alpha1\nkind: ResourceExport\nmetadata:\n  creationTimestamp: null\n  name: re-cluster-id-1\n  namespace: default\n  resourceVersion: \"999\"\nspec: {}\nstatus: {}\n",
		},
		{
			name:           "get non-existing ResourceExport",
			args:           []string{"re-cluster-id-2"},
			expectedOutput: "resourceexports.multicluster.crd.antrea.io \"re-cluster-id-2\" not found",
		},
		{
			name:          "get all ResourceExports with given cluster ID",
			allNamespaces: true,
			flags:         map[string]string{"clusterID": "cluster-id-1"},
			existingResourceExports: &mcsv1alpha1.ResourceExportList{
				Items: []mcsv1alpha1.ResourceExport{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "re-cluster-id-1",
							Labels: map[string]string{
								"sourceClusterID": "cluster-id-1",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "kube-system",
							Name:      "re-cluster-id-2",
						},
					},
				},
			},
			expectedOutput: "CLUSTER-ID   NAMESPACE NAME            KIND  \ncluster-id-1 default   re-cluster-id-1 <NONE>\n",
		},
		{
			name:           "get all ResourceExports but empty result",
			allNamespaces:  true,
			expectedOutput: "No ResourceExport found\n",
		},
		{
			name:           "error to get a ResourceExport in all Namespaces",
			args:           []string{"re-cluster-id-1"},
			allNamespaces:  true,
			expectedOutput: "a resource cannot be retrieved by name across all Namespaces",
		},
		{
			name:           "get all ResourceExports in default Namespace but empty result",
			expectedOutput: "No ResourceExport found in Namespace default\n",
		},
		{
			name:           "error due to no kubeconfig",
			expectedOutput: "flag accessed but not defined: kubeconfig",
			donotFake:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewResourceExportCommand()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			fakeClient := fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build()
			if tt.existingResourceExports != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithLists(tt.existingResourceExports).Build()

			}
			if !tt.donotFake {
				optionsResourceExport.k8sClient = fakeClient
			}
			if tt.allNamespaces {
				optionsResourceExport.allNamespaces = true
			}
			if v, ok := tt.flags["output"]; ok {
				optionsResourceExport.outputFormat = v
			}
			if v, ok := tt.flags["clusterID"]; ok {
				optionsResourceExport.clusterID = v
			}
			err := cmd.Execute()
			if err != nil {
				assert.Equal(t, tt.expectedOutput, err.Error())
			} else {
				assert.Equal(t, tt.expectedOutput, buf.String())
			}
		})
	}
}
