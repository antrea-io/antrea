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
	"bytes"
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

	client "antrea.io/antrea/pkg/antctl/raw/check"
)

func Command() *cobra.Command {
	client, err := client.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create Kubernetes client: %s", err)
	}
	check := NewConnectivityCheck(client)
	command := &cobra.Command{
		Use:   "installation",
		Short: "Runs post installation checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			return check.Run(context.Background())
		},
	}
	command.Flags().StringVarP(&check.antreaNamespace, "Namespace", "n", check.antreaNamespace, "Configure Namespace in which Antrea is running")
	return command
}

func init() {
	RegisterTest("Pod-to-Pod Connectivity", &PodtoPodConnectivityTest{})
	RegisterTest("Pod-to-Internet Connectivity", &PodtoInternetConnectivityTest{})
}

const (
	connectivityCheckNamespace  = "antrea-test"
	clientDeploymentName        = "test-client"
	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
	agentDaemonSetName          = "antrea-agent"
	deploymentImage             = "registry.k8s.io/e2e-test-images/agnhost:2.29"
)

type Test interface {
	Run(ctx context.Context, testContext *TestContext) error
}

var testsRegistry = make(map[string]Test)

func RegisterTest(name string, test Test) {
	testsRegistry[name] = test
}

type TestContext struct {
	client connectivityCheck
}

func (k *connectivityCheck) Run(ctx context.Context) error {
	k.Log("Test starting")
	err := k.initClients(ctx)
	if err != nil {
		return err
	}
	err = k.deploy(ctx)
	if err != nil {
		return err
	}
	if err := k.validateDeployment(ctx); err != nil {
		return err
	}
	testContext := &TestContext{
		client: *k,
	}
	runAllTests(ctx, testContext)
	k.Log("Test finished")
	k.Log("Deleting deployments")
	if err := k.deleteDeployments(ctx, k.client); err != nil {
		k.Log("Deployments deletion failed")
	} else {
		k.Log("Deployments deletion successful")
	}
	return nil
}

func runAllTests(ctx context.Context, testContext *TestContext) {
	for name, test := range testsRegistry {
		testContext.client.Log("-------------------------------------------------------------------------------------------")
		testContext.client.Log("Running test: %s\n", name)
		if err := test.Run(ctx, testContext); err != nil {
			testContext.client.Log("Test %s failed: %s", name, err)
		} else {
			testContext.client.Log("Test %s passed", name)
		}
	}
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

type connectivityCheck struct {
	client          k8sClientOperations
	antreaNamespace string
	clientPods      *corev1.PodList
	echoPods        map[string]string
	namespace       string
}

func NewConnectivityCheck(client k8sClientOperations) *connectivityCheck {
	return &connectivityCheck{
		client:          client,
		antreaNamespace: "kube-system",
		namespace:       generateRandomNamespace(connectivityCheckNamespace),
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

func (k *connectivityCheck) deleteDeployments(ctx context.Context, client k8sClientOperations) error {
	k.Log("[%s] Deleting connectivity check Deployments...", client.ClusterName())
	client.GetClientSet().CoreV1().Namespaces().Delete(ctx, k.namespace, metav1.DeleteOptions{})
	k.Log("[%s] Waiting for Namespace %s to disappear", client.ClusterName(), k.namespace)
	err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := client.GetClientSet().CoreV1().Namespaces().Get(ctx, k.namespace, metav1.GetOptions{})
		if err != nil {
			return true, nil
		}
		return false, nil
	})
	return err
}

func (k *connectivityCheck) initClients(ctx context.Context) error {
	_, err := k.client.GetClientSet().AppsV1().DaemonSets(k.antreaNamespace).Get(ctx, agentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to determine status of Antrea DaemonSet: %w", err)
	}
	return nil
}

func (k *connectivityCheck) deploy(ctx context.Context) error {
	var srcDeploymentNeeded, dstDeploymentNeeded bool
	_, err := k.client.GetClientSet().CoreV1().Namespaces().Get(ctx, k.namespace, metav1.GetOptions{})
	if err != nil {
		srcDeploymentNeeded = true
		dstDeploymentNeeded = true
		k.Log("[%s] Creating Namespace for connectivity check...", k.client.ClusterName())
		_, err = k.client.GetClientSet().CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: k.namespace}}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("Unable to create Namespace %s: %s", k.namespace, err)
		}
	}

	if srcDeploymentNeeded {
		k.Log("[%s] Deploying echo-same-node service...", k.client.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, 80)
		_, err = k.client.GetClientSet().CoreV1().Services(k.namespace).Create(ctx, svc, metav1.CreateOptions{})
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
			Tolerations: []corev1.Toleration{
				{
					Key:      "node-role.kubernetes.io/control-plane",
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			},
			Labels: map[string]string{"app": echoSameNodeDeploymentName},
		})
		_, err = k.client.GetClientSet().AppsV1().Deployments(k.namespace).Create(ctx, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", echoSameNodeDeploymentName, err)
		}
		k.Log("[%s] Deploying client Deployment...", k.client.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    clientDeploymentName,
			Kind:    kindClientName,
			Image:   deploymentImage,
			Command: []string{"/agnhost", "pause"},
			Port:    80,
			Labels:  map[string]string{"app": clientDeploymentName},
		})
		_, err = k.client.GetClientSet().AppsV1().Deployments(k.namespace).Create(ctx, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", clientDeploymentName, err)
		}
	}

	if dstDeploymentNeeded {
		k.Log("[%s] Deploying echo-other-node Service...", k.client.ClusterName())
		svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, 80)
		_, err = k.client.GetClientSet().CoreV1().Services(k.namespace).Create(ctx, svc, metav1.CreateOptions{})
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
		_, err = k.client.GetClientSet().AppsV1().Deployments(k.namespace).Create(ctx, echoOtherNodeDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create Deployment %s: %s", echoOtherNodeDeploymentName, err)
		}
	}
	return nil
}

func (k *connectivityCheck) waitForDeploymentsReady(ctx context.Context, client k8sClientOperations, deployments []string, interval, timeout time.Duration) error {
	for _, deployment := range deployments {
		k.Log("[%s] Waiting for Deployment %s to become ready...", client.ClusterName(), deployment)
		err := wait.PollUntilContextTimeout(ctx, interval, timeout, false, func(ctx context.Context) (bool, error) {
			ready, err := client.DeploymentIsReady(ctx, k.namespace, deployment)
			if err != nil {
				return false, fmt.Errorf("error checking readiness of deployment %s: %w", deployment, err)
			}
			return ready, nil
		})
		if err != nil {
			return fmt.Errorf("waiting for Deployment %s to become ready has been interrupted: %w", deployment, err)
		}
		k.Log("[%s] Deployment %s is ready.", client.ClusterName(), deployment)
	}
	return nil
}

func (k *connectivityCheck) validateDeployment(ctx context.Context) error {
	var err error
	srcDeployments := []string{clientDeploymentName, echoSameNodeDeploymentName}
	dstDeployments := []string{echoOtherNodeDeploymentName}
	if err := k.waitForDeploymentsReady(ctx, k.client, srcDeployments, time.Second, podReadyTimeout); err != nil {
		return err
	}
	if err := k.waitForDeploymentsReady(ctx, k.client, dstDeployments, time.Second, podReadyTimeout); err != nil {
		return err
	}
	k.clientPods, err = k.client.GetClientSet().CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("Unable to list Client Pods: %s", err)
	}
	k.echoPods = map[string]string{}
	echoPods, err := k.client.GetClientSet().CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
	if err != nil {
		return fmt.Errorf("Unable to list Echo Pods: %s", err)
	}
	for _, echoPod := range echoPods.Items {
		k.echoPods[echoPod.Name] = echoPod.Status.PodIP
	}
	k.Log("Deployment is validated successfully")
	return nil
}

func (k *connectivityCheck) Log(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func (k *connectivityCheck) Header(format string, a ...interface{}) {
	k.Log("-------------------------------------------------------------------------------------------")
	k.Log(format, a...)
	k.Log("-------------------------------------------------------------------------------------------")
}

type k8sClientOperations interface {
	DeploymentIsReady(ctx context.Context, namespace, deploymentName string) (bool, error)
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	ClusterName() (name string)
	GetClientSet() kubernetes.Interface
}
