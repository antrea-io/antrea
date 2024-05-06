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
	"os"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/antctl/raw/check"
)

func Command() *cobra.Command {
	o := newOptions()
	command := &cobra.Command{
		Use:   "cluster",
		Short: "Runs pre installation checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(o)
		},
	}
	command.Flags().StringVarP(&o.antreaNamespace, "Namespace", "n", o.antreaNamespace, "Configure Namespace in which Antrea is running")
	return command
}

type options struct {
	antreaNamespace string
}

func newOptions() *options {
	return &options{
		antreaNamespace: "kube-system",
	}
}

const (
	antreaNamespace = "kube-system"
	testNamespace   = "antrea-test"
	deploymentName  = "check-cluster"
	podReadyTimeout = 1 * time.Minute
)

type Test interface {
	Run(ctx context.Context, testContext *testContext) error
}

var testsRegistry = make(map[string]Test)

func RegisterTest(name string, test Test) {
	testsRegistry[name] = test
}

type testContext struct {
	client          kubernetes.Interface
	config          *rest.Config
	clusterName     string
	antreaNamespace string
	namespace       string
}

func Run(o *options) error {
	client, config, clusterName, err := check.NewClient()
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client: %s", err)
	}
	ctx := context.Background()
	testContext := NewTestContext(client, config, clusterName, o)
	if err := testContext.setup(ctx); err != nil {
		return err
	}
	for name, test := range testsRegistry {
		testContext.Header("Running test: %s", name)
		if err := test.Run(ctx, testContext); err != nil {
			testContext.Header("Test %s failed: %s", name, err)
		} else {
			testContext.Header("Test %s passed", name)
		}
	}
	testContext.Log("Test finished")
	check.Teardown(ctx, testContext.client, testContext.namespace, testContext.clusterName)
	return nil
}

func (t *testContext) setup(ctx context.Context) error {
	t.Log("Creating Namespace %s for pre installation tests...", t.namespace)
	_, err := t.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: t.namespace}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Namespace %s: %s", t.namespace, err)
	}
	deployment := check.NewDeployment(check.DeploymentParameters{
		Name:        deploymentName,
		Image:       "antrea/antrea-agent-ubuntu:latest",
		Replicas:    1,
		Command:     []string{"sleep", "infinity"},
		Labels:      map[string]string{"app": "check-cluster"},
		HostNetwork: true,
		VolumeMounts: []corev1.VolumeMount{
			{Name: "cni-conf", MountPath: "/etc/cni/net.d"},
			{Name: "lib-modules", MountPath: "/lib/modules"},
		},
		Tolerations: []corev1.Toleration{
			{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: "Exists",
				Effect:   "NoSchedule",
			},
			{
				Key:      "node-role.kubernetes.io/master",
				Operator: "Exists",
				Effect:   "NoSchedule",
			},
			{
				Key:      "node.kubernetes.io/not-ready",
				Operator: "Exists",
				Effect:   "NoSchedule",
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "cni-conf",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/cni/net.d",
					},
				},
			},
			{
				Name: "lib-modules",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/lib/modules",
						Type: ptr.To(corev1.HostPathType("Directory")),
					},
				},
			},
		},
	})

	t.Log("Creating Deployment")
	_, err = t.client.AppsV1().Deployments(t.namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Deployment: %w", err)
	}

	t.Log("Waiting for Deployment to become ready")
	check.WaitForDeploymentsReady(ctx, time.Second, podReadyTimeout, t.client, t.namespace, t.clusterName, deploymentName)
	if err != nil {
		return fmt.Errorf("error while waiting for Deployment to become ready: %w", err)
	}
	return nil
}

func NewTestContext(client kubernetes.Interface, config *rest.Config, clusterName string, o *options) *testContext {
	return &testContext{
		client:          client,
		config:          config,
		clusterName:     clusterName,
		antreaNamespace: o.antreaNamespace,
		namespace:       check.GenerateRandomNamespace(testNamespace),
	}
}

func (t *testContext) Log(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, fmt.Sprintf("[%s] ", t.clusterName)+format+"\n", a...)
}

func (t *testContext) Header(format string, a ...interface{}) {
	t.Log("-------------------------------------------------------------------------------------------")
	t.Log(format, a...)
	t.Log("-------------------------------------------------------------------------------------------")
}
