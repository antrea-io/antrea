// Copyright 2024 Antrea Authors.
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

package cluster

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

type checkControlPlaneAvailability struct{}

func init() {
	RegisterTest("check-control-plane-nodes-availability", &checkControlPlaneAvailability{})
}

func (t *checkControlPlaneAvailability) Run(ctx context.Context, testContext *testContext) error {
	controlPlaneNodes := sets.New[string]()
	controlPlaneLabels := []string{"node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master"}
	for _, label := range controlPlaneLabels {
		nodes, err := testContext.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: label})
		if err != nil {
			return fmt.Errorf("failed to list Nodes with label %s: %w", label, err)
		}
		for idx := range nodes.Items {
			controlPlaneNodes.Insert(nodes.Items[idx].Name)
		}
	}
	if controlPlaneNodes.Len() == 0 {
		return newUncertainError("no control-plane Nodes were found; if installing Antrea in encap mode, some K8s functionalities (API aggregation, apiserver proxy, admission controllers) may be impacted")
	} else {
		testContext.Log("control-plane Nodes were found in the cluster.")
	}
	return nil
}
