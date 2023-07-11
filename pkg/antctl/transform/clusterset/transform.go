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

package clusterset

import (
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/antctl/transform/common"
)

type Response struct {
	ClusterID    string `json:"clusterID" yaml:"clusterID"`
	Namespace    string `json:"namespace" yaml:"namespace"`
	ClusterSetID string `json:"clusterSetID" yaml:"clusterSetID"`
	Type         string `json:"type" yaml:"type"`
	Status       string `json:"status" yaml:"status"`
	Reason       string `json:"reason" yaml:"reason"`
}

func Transform(r interface{}, single bool) (interface{}, error) {
	if single {
		return listTransform([]mcv1alpha2.ClusterSet{r.(mcv1alpha2.ClusterSet)})
	}
	return listTransform(r)
}

func listTransform(l interface{}) (interface{}, error) {
	clusterSets := l.([]mcv1alpha2.ClusterSet)
	var result []interface{}

	for _, clusterSet := range clusterSets {
		if len(clusterSet.Status.ClusterStatuses) > 0 {
			for i := range clusterSet.Status.ClusterStatuses {
				r := clusterSet.Status.ClusterStatuses[i]
				for j := range r.Conditions {
					condition := r.Conditions[j]
					o, _ := objectTransform(clusterSet, r, condition)
					result = append(result, o.(Response))
				}
			}
		} else {
			// When the ClusterSet has no status, we should print it with empty status.
			o, _ := objectTransform(clusterSet, mcv1alpha2.ClusterStatus{},
				mcv1alpha2.ClusterCondition{})
			result = append(result, o.(Response))
		}
	}

	return result, nil
}

func objectTransform(clusterSet mcv1alpha2.ClusterSet, status mcv1alpha2.ClusterStatus,
	condition mcv1alpha2.ClusterCondition) (interface{}, error) {

	return Response{
		ClusterID:    status.ClusterID,
		Namespace:    clusterSet.Namespace,
		ClusterSetID: clusterSet.Name,
		Type:         string(condition.Type),
		Status:       string(condition.Status),
		Reason:       condition.Reason,
	}, nil
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"CLUSTER-ID", "NAMESPACE", "CLUSTERSET-ID", "TYPE", "STATUS", "REASON"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.ClusterID, r.Namespace, r.ClusterSetID, r.Type, r.Status, r.Reason}
}

func (r Response) SortRows() bool {
	return true
}
