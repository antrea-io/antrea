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
	"errors"
	"fmt"
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
	command.Flags().StringVar(&o.testImage, "test-image", o.testImage, "Container image override for the cluster checker")
	return command
}

const (
	testNamespacePrefix = "antrea-test"
	deploymentName      = "cluster-checker"
	podReadyTimeout     = 1 * time.Minute
)

type options struct {
	// Container image for the cluster checker.
	testImage string
}

func newOptions() *options {
	return &options{
		testImage: check.DefaultTestImage,
	}
}

type uncertainError struct {
	reason string
}

func (e uncertainError) Error() string {
	return e.reason
}

func newUncertainError(reason string, a ...interface{}) uncertainError {
	return uncertainError{reason: fmt.Sprintf(reason, a...)}
}

type Test interface {
	Run(ctx context.Context, testContext *testContext) error
}

var testsRegistry = make(map[string]Test)

func RegisterTest(name string, test Test) {
	testsRegistry[name] = test
}

type testContext struct {
	check.Logger
	client      kubernetes.Interface
	config      *rest.Config
	clusterName string
	namespace   string
	testPod     *corev1.Pod
	// Container image for the cluster checker.
	testImage string
}

func Run(o *options) error {
	client, config, clusterName, err := check.NewClient()
	if err != nil {
		return fmt.Errorf("unable to create Kubernetes client: %s", err)
	}
	ctx := context.Background()
	testContext := NewTestContext(client, config, clusterName, o.testImage)
	defer check.Teardown(ctx, testContext.Logger, testContext.client, testContext.namespace)
	if err := testContext.setup(ctx); err != nil {
		return err
	}
	var numSuccess, numFailure, numUncertain int
	for name, test := range testsRegistry {
		testContext.Header("Running test: %s", name)
		if err := test.Run(ctx, testContext); err != nil {
			if errors.As(err, new(uncertainError)) {
				testContext.Warning("Test %s was uncertain: %v", name, err)
				numUncertain++
			} else {
				testContext.Fail("Test %s failed: %v", name, err)
				numFailure++
			}
		} else {
			testContext.Success("Test %s passed", name)
			numSuccess++
		}
	}
	testContext.Log("Test finished: %v tests succeeded, %v tests failed, %v tests were uncertain", numSuccess, numFailure, numUncertain)
	if numFailure > 0 {
		return fmt.Errorf("%v/%v tests failed", numFailure, len(testsRegistry))
	}
	return nil
}

func (t *testContext) setup(ctx context.Context) error {
	t.Log("Creating Namespace %s for pre installation tests...", t.namespace)
	_, err := t.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: t.namespace, Labels: map[string]string{"app": "antrea", "component": "cluster-checker"}}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Namespace %s: %s", t.namespace, err)
	}
	deployment := check.NewDeployment(check.DeploymentParameters{
		Name:        deploymentName,
		Image:       t.testImage,
		Replicas:    1,
		Command:     []string{"bash", "-c"},
		Args:        []string{"trap 'exit 0' SIGTERM; sleep infinity & pid=$!; wait $pid"},
		Labels:      map[string]string{"app": "antrea", "component": "cluster-checker"},
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
		NodeSelector: map[string]string{
			"kubernetes.io/os": "linux",
		},
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"SYS_MODULE"},
			},
		},
	})

	t.Log("Creating Deployment")
	_, err = t.client.AppsV1().Deployments(t.namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Deployment: %w", err)
	}

	t.Log("Waiting for Deployment to become ready")
	err = check.WaitForDeploymentsReady(ctx, time.Second, podReadyTimeout, t.client, t.clusterName, t.namespace, deploymentName)
	if err != nil {
		return fmt.Errorf("error while waiting for Deployment to become ready: %w", err)
	}
	testPods, err := t.client.CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{LabelSelector: "component=cluster-checker"})
	if err != nil {
		return fmt.Errorf("no Pod found for Deployment %s", deploymentName)
	}
	t.testPod = &testPods.Items[0]
	return nil
}

func NewTestContext(client kubernetes.Interface, config *rest.Config, clusterName, testImage string) *testContext {
	return &testContext{
		Logger:      check.NewLogger(fmt.Sprintf("[%s] ", clusterName)),
		client:      client,
		config:      config,
		clusterName: clusterName,
		namespace:   check.GenerateRandomNamespace(testNamespacePrefix),
		testImage:   testImage,
	}
}

func (t *testContext) Header(format string, a ...interface{}) {
	t.Log("-------------------------------------------------------------------------------------------")
	t.Log(format, a...)
	t.Log("-------------------------------------------------------------------------------------------")
}
