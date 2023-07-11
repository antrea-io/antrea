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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestGetClusterSet(t *testing.T) {
	clusterSetList := &mcv1alpha2.ClusterSetList{
		Items: []mcv1alpha2.ClusterSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "clusterset-name",
				},
				Status: mcv1alpha2.ClusterSetStatus{},
			},
		},
	}
	tests := []struct {
		name                string
		existingClusterSets *mcv1alpha2.ClusterSetList
		args                []string
		output              string
		allNamespaces       bool
		donotFake           bool
		expectedOutput      string
	}{
		{
			name:                "get single ClusterSet",
			existingClusterSets: clusterSetList,
			args:                []string{"clusterset-name"},
			expectedOutput:      "CLUSTER-ID NAMESPACE CLUSTERSET-ID   TYPE   STATUS REASON\n<NONE>     default   clusterset-name <NONE> <NONE> <NONE>\n",
		},
		{
			name:                "get single ClusterSet with json output",
			existingClusterSets: clusterSetList,
			args:                []string{"clusterset-name"},
			output:              "json",
			expectedOutput:      "[\n  {\n    \"kind\": \"ClusterSet\",\n    \"apiVersion\": \"multicluster.crd.antrea.io/v1alpha2\",\n    \"metadata\": {\n      \"name\": \"clusterset-name\",\n      \"namespace\": \"default\",\n      \"resourceVersion\": \"999\",\n      \"creationTimestamp\": null\n    },\n    \"spec\": {\n      \"clusterID\": \"\",\n      \"leaders\": null\n    },\n    \"status\": {}\n  }\n]\n",
		},
		{
			name:                "get single ClusterSet with yaml output",
			existingClusterSets: clusterSetList,
			args:                []string{"clusterset-name"},
			output:              "yaml",
			expectedOutput:      "- apiVersion: multicluster.crd.antrea.io/v1alpha2\n  kind: ClusterSet\n  metadata:\n    creationTimestamp: null\n    name: clusterset-name\n    namespace: default\n    resourceVersion: \"999\"\n  spec:\n    clusterID: \"\"\n    leaders: null\n  status: {}\n",
		},
		{
			name:           "get non-existing ClusterSet",
			args:           []string{"clusterset1"},
			expectedOutput: "clustersets.multicluster.crd.antrea.io \"clusterset1\" not found",
		},
		{
			name:          "get all ClusterSets",
			allNamespaces: true,
			existingClusterSets: &mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "clusterset-name",
						},
						Status: mcv1alpha2.ClusterSetStatus{},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "kube-system",
							Name:      "clusterset-1",
						},
						Status: mcv1alpha2.ClusterSetStatus{
							ClusterStatuses: []mcv1alpha2.ClusterStatus{{
								ClusterID: "cluster-a",
								Conditions: []mcv1alpha2.ClusterCondition{
									{
										Message: "Member Connected",
										Reason:  "Connected",
										Status:  v1.ConditionTrue,
										Type:    mcv1alpha2.ClusterReady,
									},
								},
							},
							},
						},
					},
				},
			},
			expectedOutput: "CLUSTER-ID NAMESPACE   CLUSTERSET-ID   TYPE   STATUS REASON   \n<NONE>     default     clusterset-name <NONE> <NONE> <NONE>   \ncluster-a  kube-system clusterset-1    Ready  True   Connected\n",
		},
		{
			name:           "get all ClusterSets but empty result",
			allNamespaces:  true,
			expectedOutput: "No ClusterSet found\n",
		},
		{
			name:           "get all ClusterSets but empty result in default Namespace",
			expectedOutput: "No ClusterSet found in Namespace default\n",
		},
		{
			name:           "error due to no kubeconfig",
			expectedOutput: "flag accessed but not defined: kubeconfig",
			donotFake:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewClusterSetCommand()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			fakeClient := fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build()
			if tt.existingClusterSets != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithLists(tt.existingClusterSets).Build()
			}
			if !tt.donotFake {
				optionsClusterSet.k8sClient = fakeClient
			}

			if tt.allNamespaces {
				optionsClusterSet.allNamespaces = true
			}
			if tt.output != "" {
				optionsClusterSet.outputFormat = tt.output
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
