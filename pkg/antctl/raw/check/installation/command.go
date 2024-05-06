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

package installation

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/antctl/raw/check"
)

func Command() *cobra.Command {
	o := newOptions()
	command := &cobra.Command{
		Use:   "installation",
		Short: "Runs post installation checks",
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
	testNamespacePrefix         = "antrea-test"
	clientDeploymentName        = "test-client"
	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
	agentDaemonSetName          = "antrea-agent"
	deploymentImage             = "registry.k8s.io/e2e-test-images/agnhost:2.29"
	podReadyTimeout             = 1 * time.Minute
)

type Test interface {
	Run(ctx context.Context, testContext *testContext) error
}

var testsRegistry = make(map[string]Test)

func RegisterTest(name string, test Test) {
	testsRegistry[name] = test
}

type testContext struct {
	client           kubernetes.Interface
	config           *rest.Config
	clusterName      string
	antreaNamespace  string
	clientPods       []corev1.Pod
	echoSameNodePod  *corev1.Pod
	echoOtherNodePod *corev1.Pod
	namespace        string
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

func agnhostConnectCommand(ip string, port string) []string {
	hostPort := net.JoinHostPort(ip, port)
	return []string{"/agnhost", "connect", hostPort, "--timeout=5s"}
}

func newService(name string, selector map[string]string, port int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Name: name, Port: int32(port)},
			},
			Selector: selector,
		},
	}
}

func NewTestContext(client kubernetes.Interface, config *rest.Config, clusterName string, o *options) *testContext {
	return &testContext{
		client:          client,
		config:          config,
		clusterName:     clusterName,
		antreaNamespace: o.antreaNamespace,
		namespace:       check.GenerateRandomNamespace(testNamespacePrefix),
	}
}

func (t *testContext) setup(ctx context.Context) error {
	t.Log("Test starting....")
	_, err := t.client.AppsV1().DaemonSets(t.antreaNamespace).Get(ctx, agentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to determine status of Antrea DaemonSet: %w", err)
	}
	t.Log("Creating Namespace %s for post installation tests...", t.namespace)
	_, err = t.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: t.namespace}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Namespace %s: %s", t.namespace, err)
	}
	t.Log("Deploying echo-same-node Service %s...", echoSameNodeDeploymentName)
	svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, 80)
	_, err = t.client.CoreV1().Services(t.namespace).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	commonToleration := []corev1.Toleration{
		{
			Key:      "node-role.kubernetes.io/control-plane",
			Operator: "Exists",
			Effect:   "NoSchedule",
		},
	}
	echoDeployment := check.NewDeployment(check.DeploymentParameters{
		Name:    echoSameNodeDeploymentName,
		Role:    kindEchoName,
		Port:    80,
		Image:   deploymentImage,
		Command: []string{"/agnhost", "netexec", "--http-port=80"},
		Affinity: &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "name",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{clientDeploymentName},
								},
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		},
		Tolerations: commonToleration,
		Labels:      map[string]string{"app": echoSameNodeDeploymentName},
	})
	_, err = t.client.AppsV1().Deployments(t.namespace).Create(ctx, echoDeployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Deployment %s: %s", echoSameNodeDeploymentName, err)
	}
	t.Log("Deploying client Deployment %s...", clientDeploymentName)
	clientDeployment := check.NewDeployment(check.DeploymentParameters{
		Name:        clientDeploymentName,
		Role:        kindClientName,
		Image:       deploymentImage,
		Command:     []string{"/agnhost", "pause"},
		Port:        80,
		Tolerations: commonToleration,
		Labels:      map[string]string{"app": clientDeploymentName},
	})
	_, err = t.client.AppsV1().Deployments(t.namespace).Create(ctx, clientDeployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create Deployment %s: %s", clientDeploymentName, err)
	}

	t.Log("Deploying echo-other-node Service %s...", echoOtherNodeDeploymentName)
	svc = newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, 80)
	_, err = t.client.CoreV1().Services(t.namespace).Create(ctx, svc, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	echoOtherNodeDeployment := check.NewDeployment(check.DeploymentParameters{
		Name:    echoOtherNodeDeploymentName,
		Role:    kindEchoName,
		Port:    80,
		Image:   deploymentImage,
		Command: []string{"/agnhost", "netexec", "--http-port=80"},
		Affinity: &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{clientDeploymentName}},
							},
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		},
		Tolerations: commonToleration,
		Labels:      map[string]string{"app": echoOtherNodeDeploymentName},
	})
	nodes, err := t.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list Nodes: %s", err)
	}
	if len(nodes.Items) >= 2 {
		_, err = t.client.AppsV1().Deployments(t.namespace).Create(ctx, echoOtherNodeDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", echoOtherNodeDeploymentName, err)
		}
		if err := check.WaitForDeploymentsReady(ctx, time.Second, podReadyTimeout, t.client, t.namespace, t.clusterName, clientDeploymentName, echoSameNodeDeploymentName, echoOtherNodeDeploymentName); err != nil {
			return err
		}
		podList, err := t.client.CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{LabelSelector: "name=" + echoOtherNodeDeploymentName})
		if err != nil {
			return fmt.Errorf("unable to list Echo Other Node Pod: %s", err)
		}
		if len(podList.Items) > 0 {
			t.echoOtherNodePod = &podList.Items[0]
		}
	} else {
		t.Log("skipping other Node Deployments as multiple Nodes are not available")
		if err := check.WaitForDeploymentsReady(ctx, time.Second, podReadyTimeout, t.client, t.namespace, t.clusterName, clientDeploymentName, echoSameNodeDeploymentName); err != nil {
			return err
		}
	}
	podList, err := t.client.CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client Pods: %s", err)
	}
	t.clientPods = podList.Items
	podList, err = t.client.CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{LabelSelector: "name=" + echoSameNodeDeploymentName})
	if err != nil {
		return fmt.Errorf("unable to list Echo Same Node Pod: %s", err)
	}
	if len(podList.Items) > 0 {
		t.echoSameNodePod = &podList.Items[0]
	}
	t.Log("Deployment is validated successfully")
	return nil
}

func (t *testContext) Log(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, fmt.Sprintf("[%s] ", t.clusterName)+format+"\n", a...)
}

func (t *testContext) Header(format string, a ...interface{}) {
	t.Log("-------------------------------------------------------------------------------------------")
	t.Log(format, a...)
	t.Log("-------------------------------------------------------------------------------------------")
}
