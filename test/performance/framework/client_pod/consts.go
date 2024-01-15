// Copyright 2023 Antrea Authors.
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

package client_pod

import (
	"fmt"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

func init() {
	suffix := uuid.New().String()
	ScaleTestNamespaceBase = fmt.Sprintf("%s-%s", ScaleTestNamespacePrefix, suffix[:6])
	klog.InfoS("Scale up namespace", "ScaleTestNamespaceBase", ScaleTestNamespaceBase)
}

var (
	ScaleTestNamespacePrefix = "antrea-scale-ns"
	ScaleTestNamespaceBase   = "antrea-scale-ns-xxxx"
	ClientPodsNamespace      = ScaleTestNamespacePrefix + "-scale-client"
)

const (
	AppLabelKey   = "app"
	AppLabelValue = "antrea-scale-test-workload"

	SimulatorNodeLabelKey   = "antrea/instance"
	SimulatorNodeLabelValue = "simulator"

	SimulatorTaintKey   = "simulator"
	SimulatorTaintValue = "true"

	ScaleTestClientDaemonSet          = "antrea-scale-test-client-daemonset"
	ScaleClientContainerName          = "antrea-scale-test-client"
	ScaleAgentProbeContainerName      = "antrea-scale-test-agent-probe"
	ScaleControllerProbeContainerName = "antrea-scale-test-controller-probe"
	ScaleClientPodTemplateName        = "antrea-scale-test-client"
	ScaleTestClientPodNamePrefix      = "antrea-scale-test-client-pod"
)

var (
	// RealNodeAffinity is used to make a Pod not to be scheduled to a simulated node.
	RealNodeAffinity = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      SimulatorNodeLabelKey,
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{SimulatorNodeLabelValue},
							},
						},
					},
				},
			},
		},
	}

	// SimulateAffinity is used to make a Pod to be scheduled to a simulated node.
	SimulateAffinity = corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      SimulatorNodeLabelKey,
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{SimulatorNodeLabelValue},
							},
						},
					},
				},
			},
		},
	}

	// SimulateToleration marks a Pod able to run on a simulate node.
	SimulateToleration = corev1.Toleration{
		Key:      SimulatorTaintKey,
		Operator: corev1.TolerationOpEqual,
		Value:    SimulatorTaintValue,
		Effect:   corev1.TaintEffectNoExecute,
	}

	// MasterToleration marks a Pod able to run on the master node.
	MasterToleration = corev1.Toleration{
		Key:      "node-role.kubernetes.io/master",
		Operator: corev1.TolerationOpExists,
		Effect:   corev1.TaintEffectNoSchedule,
	}

	// ClientPodTemplate is the PodTemplateSpec of a scale test client Pod.
	ClientPodTemplate = corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{ScaleClientPodTemplateName: ""}},
		Spec: corev1.PodSpec{
			Affinity:    &RealNodeAffinity,
			Tolerations: []corev1.Toleration{MasterToleration},
			Containers: []corev1.Container{
				{
					Name:            ScaleClientContainerName,
					Image:           "busybox",
					Command:         []string{"nc", "-lk", "-p", "80"},
					ImagePullPolicy: corev1.PullIfNotPresent,
				},
			},
		},
	}
)
