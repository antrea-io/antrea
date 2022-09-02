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

package resourceexport

import (
	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/transform/common"
)

type Response struct {
	ClusterID string `json:"clusterID" yaml:"clusterID"`
	Namespace string `json:"namespace" yaml:"namespace"`
	Name      string `json:"name" yaml:"name"`
	Kind      string `json:"kind" yaml:"kind"`
}

func Transform(r interface{}, single bool) (interface{}, error) {
	if single {
		return objectTransform(r)
	}
	return listTransform(r)
}

func listTransform(l interface{}) (interface{}, error) {
	resourceExports := l.([]multiclusterv1alpha1.ResourceExport)
	var result []interface{}

	for i := range resourceExports {
		item := resourceExports[i]
		o, _ := objectTransform(item)
		result = append(result, o.(Response))
	}

	return result, nil
}

func objectTransform(o interface{}) (interface{}, error) {
	resourceExport := o.(multiclusterv1alpha1.ResourceExport)

	return Response{
		ClusterID: resourceExport.Labels["sourceClusterID"],
		Namespace: resourceExport.Namespace,
		Name:      resourceExport.Name,
		Kind:      resourceExport.Spec.Kind,
	}, nil
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"CLUSTER-ID", "NAMESPACE", "NAME", "KIND"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.ClusterID, r.Namespace, r.Name, r.Kind}
}

func (r Response) SortRows() bool {
	return true
}
