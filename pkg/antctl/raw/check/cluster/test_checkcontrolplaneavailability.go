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
)

type checkControlPlaneAvailability struct{}

func init() {
	RegisterTest("Check Control Plane Availability", &checkControlPlaneAvailability{})
}

func (t *checkControlPlaneAvailability) Run(ctx context.Context, testContext *testContext) error {
	controlPlaneLabel := "node-role.kubernetes.io/control-plane"
	masterNodeLabel := "node-role.kubernetes.io/master"
	controlPlaneNode, err := testContext.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: controlPlaneLabel})
	if err != nil {
		return fmt.Errorf("failed to list control plane Nodes: %w", err)
	}
	masterNode, err := testContext.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: masterNodeLabel})
	if err != nil {
		return fmt.Errorf("failed to list master Nodes: %w", err)
	}
	if len(controlPlaneNode.Items) == 0 && len(masterNode.Items) == 0 {
		testContext.Log("No control-plane Nodes were found; if installing Antrea in encap mode, some K8s functionalities (API aggregation, apiserver proxy, admission controllers) may be impacted.")
	} else {
		for _, node := range controlPlaneNode.Items {
			testContext.Log("Control plane Node %s found", node.Name)
		}
		for _, node := range masterNode.Items {
			testContext.Log("Master Node %s found", node.Name)
		}
	}
	return nil
}
