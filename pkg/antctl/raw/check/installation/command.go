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
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

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

func init() {
	RegisterTest("Pod-to-Pod Connectivity", &PodToPodConnectivityTest{})
	RegisterTest("Pod-to-Internet Connectivity", &PodToInternetConnectivityTest{})
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
	postInstallationTestsNamespace = "antrea-test"
	clientDeploymentName           = "test-client"
	echoSameNodeDeploymentName     = "echo-same-node"
	echoOtherNodeDeploymentName    = "echo-other-node"
	kindEchoName                   = "echo"
	kindClientName                 = "client"
	agentDaemonSetName             = "antrea-agent"
	deploymentImage                = "registry.k8s.io/e2e-test-images/agnhost:2.29"
)

type Test interface {
	Run(ctx context.Context, testContext *testContext) error
}

var testsRegistry = make(map[string]Test)

func RegisterTest(name string, test Test) {
	testsRegistry[name] = test
}

type testContext struct {
	client          k8sClientOperations
	antreaNamespace string
	clientPods      *corev1.PodList
	echoPods        map[string]string
	namespace       string
}

func Run(o *options) error {
	client, err := check.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create Kubernetes client: %s", err)
	}
	ctx := context.Background()
	testContext := NewTestContext(client, o)
	testContext.Log("Test starting")
	if err := testContext.setup(ctx); err != nil {
		return err
	}
	if err := testContext.validateDeployment(ctx); err != nil {
		return err
	}
	for name, test := range testsRegistry {
		testContext.Header("Running test: %s\n", name)
		if err := test.Run(ctx, testContext); err != nil {
			testContext.Header("Test %s failed: %s", name, err)
		} else {
			testContext.Header("Test %s passed", name)
		}
	}
	testContext.Log("Test finished")
	testContext.Log("Deleting deployments")
	if err := testContext.deleteDeployments(ctx, testContext.client); err != nil {
		testContext.Log("Deployments deletion failed")
	} else {
		testContext.Log("Deployments deletion successful")
	}
	return nil
}

func agnhostConnectCommand(target string) []string {
	return []string{"/agnhost", "connect", target, "--timeout=5s"}
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

type deploymentParameters struct {
	Name        string
	Kind        string
	Image       string
	Replicas    int
	Port        int
	Command     []string
	Affinity    *corev1.Affinity
	Tolerations []corev1.Toleration
	Labels      map[string]string
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	replicas32 := int32(p.Replicas)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
			Labels: map[string]string{
				"name": p.Name,
				"kind": p.Kind,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: p.Name,
					Labels: map[string]string{
						"name": p.Name,
						"kind": p.Kind,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: p.Name,
							Env: []corev1.EnvVar{
								{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
							},
							Ports: []corev1.ContainerPort{
								{ContainerPort: int32(p.Port)},
							},
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
						},
					},
					Affinity: p.Affinity,
				},
			},
			Replicas: &replicas32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": p.Name,
					"kind": p.Kind,
				},
			},
		},
	}
}

func NewTestContext(client k8sClientOperations, o *options) *testContext {
	return &testContext{
		client:          client,
		antreaNamespace: o.antreaNamespace,
		namespace:       generateRandomNamespace(postInstallationTestsNamespace),
	}
}

func generateRandomNamespace(baseName string) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	bytes := make([]byte, 5)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return fmt.Sprintf("%s-%s", baseName, string(bytes))
}

const podReadyTimeout = 5 * time.Minute

func (t *testContext) deleteDeployments(ctx context.Context, client k8sClientOperations) error {
	t.Log("[%s] Deleting Post installation tests Deployments...", client.ClusterName())
	client.GetClientSet().CoreV1().Namespaces().Delete(ctx, t.namespace, metav1.DeleteOptions{})
	t.Log("[%s] Waiting for Namespace %s to disappear", client.ClusterName(), t.namespace)
	err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := client.GetClientSet().CoreV1().Namespaces().Get(ctx, t.namespace, metav1.GetOptions{})
		if err != nil {
			return true, nil
		}
		return false, nil
	})
	return err
}

func (t *testContext) setup(ctx context.Context) error {
	_, err := t.client.GetClientSet().AppsV1().DaemonSets(t.antreaNamespace).Get(ctx, agentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to determine status of Antrea DaemonSet: %w", err)
	}
	var srcDeploymentNeeded, dstDeploymentNeeded bool
	_, err = t.client.GetClientSet().CoreV1().Namespaces().Get(ctx, t.namespace, metav1.GetOptions{})
	if err != nil {
		srcDeploymentNeeded = true
		dstDeploymentNeeded = true
		t.Log("[%s] Creating Namespace for Post installation tests...", t.client.ClusterName())
		_, err = t.client.GetClientSet().CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: t.namespace}}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("Unable to create Namespace %s: %s", t.namespace, err)
		}
	}

	if srcDeploymentNeeded {
		t.Log("[%s] Deploying echo-same-node service...", t.client.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, 80)
		_, err = t.client.GetClientSet().CoreV1().Services(t.namespace).Create(ctx, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		echoDeployment := newDeployment(deploymentParameters{
			Name:    echoSameNodeDeploymentName,
			Kind:    kindEchoName,
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
			Labels: map[string]string{"app": echoSameNodeDeploymentName},
		})
		_, err = t.client.GetClientSet().AppsV1().Deployments(t.namespace).Create(ctx, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", echoSameNodeDeploymentName, err)
		}
		t.Log("[%s] Deploying client Deployment...", t.client.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    clientDeploymentName,
			Kind:    kindClientName,
			Image:   deploymentImage,
			Command: []string{"/agnhost", "pause"},
			Port:    80,
			Labels:  map[string]string{"app": clientDeploymentName},
		})
		_, err = t.client.GetClientSet().AppsV1().Deployments(t.namespace).Create(ctx, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", clientDeploymentName, err)
		}
	}

	if dstDeploymentNeeded {
		t.Log("[%s] Deploying echo-other-node Service...", t.client.ClusterName())
		svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, 80)
		_, err = t.client.GetClientSet().CoreV1().Services(t.namespace).Create(ctx, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		echoOtherNodeDeployment := newDeployment(deploymentParameters{
			Name:    echoOtherNodeDeploymentName,
			Kind:    kindEchoName,
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
			Labels: map[string]string{"app": echoOtherNodeDeploymentName},
		})
		_, err = t.client.GetClientSet().AppsV1().Deployments(t.namespace).Create(ctx, echoOtherNodeDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", echoOtherNodeDeploymentName, err)
		}
	}
	return nil
}

func (t *testContext) waitForDeploymentsReady(ctx context.Context, client k8sClientOperations, deployments []string, interval, timeout time.Duration) error {
	for _, deployment := range deployments {
		t.Log("[%s] Waiting for Deployment %s to become ready...", client.ClusterName(), deployment)
		err := wait.PollUntilContextTimeout(ctx, interval, timeout, false, func(ctx context.Context) (bool, error) {
			ready, err := client.DeploymentIsReady(ctx, t.namespace, deployment)
			if err != nil {
				return false, fmt.Errorf("error checking readiness of deployment %s: %w", deployment, err)
			}
			return ready, nil
		})
		if err != nil {
			return fmt.Errorf("waiting for Deployment %s to become ready has been interrupted: %w", deployment, err)
		}
		t.Log("[%s] Deployment %s is ready.", client.ClusterName(), deployment)
	}
	return nil
}

func (t *testContext) validateDeployment(ctx context.Context) error {
	var err error
	srcDeployments := []string{clientDeploymentName, echoSameNodeDeploymentName}
	dstDeployments := []string{echoOtherNodeDeploymentName}
	if err := t.waitForDeploymentsReady(ctx, t.client, srcDeployments, time.Second, podReadyTimeout); err != nil {
		return err
	}
	if err := t.waitForDeploymentsReady(ctx, t.client, dstDeployments, time.Second, podReadyTimeout); err != nil {
		return err
	}
	t.clientPods, err = t.client.GetClientSet().CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("Unable to list Client Pods: %s", err)
	}
	t.echoPods = map[string]string{}
	echoPods, err := t.client.GetClientSet().CoreV1().Pods(t.namespace).List(ctx, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
	if err != nil {
		return fmt.Errorf("Unable to list Echo Pods: %s", err)
	}
	for _, echoPod := range echoPods.Items {
		t.echoPods[echoPod.Name] = echoPod.Status.PodIP
	}
	t.Log("Deployment is validated successfully")
	return nil
}

func (t *testContext) Log(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func (t *testContext) Header(format string, a ...interface{}) {
	t.Log("-------------------------------------------------------------------------------------------")
	t.Log(format, a...)
	t.Log("-------------------------------------------------------------------------------------------")
}

type k8sClientOperations interface {
	DeploymentIsReady(ctx context.Context, namespace, deploymentName string) (bool, error)
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (string, string, error)
	ClusterName() (name string)
	GetClientSet() kubernetes.Interface
}
