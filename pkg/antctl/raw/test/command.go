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

package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func Command() *cobra.Command {
	client, err := NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create kubernetes client: %s", err)
	}
	k8sClient := client
	check := NewAntreaConnectivityCheck(k8sClient)
	command := &cobra.Command{
		Use:   "installation",
		Short: "Runs post installation checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(check.Writer, "Test starting \n")
			return check.Run(context.Background())
		},
	}
	command.Flags().StringVarP(&check.antreaNamespace, "namespace", "n", check.antreaNamespace, "Configure namespace in which antrea is running")
	return command
}

const (
	connectivityCheckNamespace  = "antrea-test"
	clientDeploymentName        = "test-client"
	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
	agentDaemonSetName          = "antrea-agent"
)

func (k *k8sConnectivityParams) Run(ctx context.Context) error {
	c, err := k.initClients(ctx)
	if err != nil {
		return err
	}
	k.clients = c

	err = k.deploy(ctx)
	if err != nil {
		return err
	}

	if err := k.validateDeployment(ctx); err != nil {
		return err
	}
	k.validatePodToPod(ctx)
	k.validatePodInternetConnectivity(ctx)
	k.Log("Test finished")
	k.Log("Deleting deployments")
	if err := k.deleteDeployments(ctx, k.client); err != nil {
		k.Log("Deployments deletion failed")
	} else {
		k.Log("Deployments deletion successful")
	}
	return nil
}

func agnhostConnectCommand(target string) []string {
	return []string{"/agnhost", "connect", target, "--timeout=5s"}
}

func newService(name string, selector map[string]string, portName string, port int) *corev1.Service {
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

type k8sConnectivityParams struct {
	clients         *deploymentClients
	client          k8sClientOperations
	Writer          io.Writer
	antreaNamespace string
	clientPods      *corev1.PodList
	echoPods        map[string]string
	namespace       string
}

func NewAntreaConnectivityCheck(client k8sClientOperations) *k8sConnectivityParams {
	return &k8sConnectivityParams{
		client:          client,
		antreaNamespace: "kube-system",
		Writer:          os.Stdout,
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

func (k *k8sConnectivityParams) validatePodToPod(ctx context.Context) {
	//conducts Pod to Pod connectivity tests within same node and different node
	for _, clientPod := range k.clientPods.Items {
		for echoName, echoIP := range k.echoPods {
			var (
				srcPod  = k.namespace + "/" + clientPod.Name
				dstPod  = k.namespace + "/" + echoName
				success = true
			)
			k.Header("Validating from pod %s to pod %s...", srcPod, dstPod)
			_, err := k.client.ExecInPod(ctx, k.namespace, clientPod.Name, "", agnhostConnectCommand(echoIP+":80"))
			if err != nil {
				k.Log("curl connectivity check command failed: %s", err)
				success = false
			}

			if success {
				k.Log("client pod %s was able to communicate with echo pod %s (%s)", clientPod.Name, echoName, echoIP)
			} else {
				k.Log("client pod %s was not able to communicate with echo pod %s (%s)", clientPod.Name, echoName, echoIP)
			}

			k.Relax()
		}
	}
}

func (k *k8sConnectivityParams) validatePodInternetConnectivity(ctx context.Context) error {
	for _, clientPod := range k.clientPods.Items {
		var (
			srcPod  = k.namespace + "/" + clientPod.Name
			success = true
		)

		k.Header("Validating connectivity from pod %s to the world (google.com)...", srcPod)
		_, err := k.client.ExecInPod(ctx, k.namespace, clientPod.Name, clientDeploymentName, agnhostConnectCommand("google.com:80"))
		if err != nil {
			k.Log("Connectivity test from pod %s to google.com failed: %s", srcPod, err)
			success = false
		}

		if success {
			k.Log("Pod %s was able to connect to google.com", srcPod)
		}

		k.Relax()
	}
	return nil
}

func (k *k8sConnectivityParams) Relax() {
	time.Sleep(2 * time.Second)
}

const podReadyTimeout = 5 * time.Minute

func (k *k8sConnectivityParams) deleteDeployments(ctx context.Context, client k8sClientOperations) error {
	k.Log("[%s] Deleting connectivity check deployments...", client.ClusterName())
	client.DeleteNamespace(ctx, k.namespace, metav1.DeleteOptions{})

	_, err := client.GetNamespace(ctx, k.namespace, metav1.GetOptions{})
	if err == nil {
		k.Log("[%s] Waiting for namespace %s to disappear", client.ClusterName(), k.namespace)
		for err == nil {
			time.Sleep(time.Second)
			_, err = client.GetNamespace(ctx, k.namespace, metav1.GetOptions{})
		}
	}

	return nil
}

func (k *k8sConnectivityParams) deploymentList() (srcList []string, dstList []string) {
	srcList = []string{clientDeploymentName, echoSameNodeDeploymentName}
	dstList = append(dstList, echoOtherNodeDeploymentName)

	return srcList, dstList
}

type deploymentClients struct {
	source      k8sClientOperations
	destination k8sClientOperations
}

func (d *deploymentClients) clients() []k8sClientOperations {
	return []k8sClientOperations{d.source}
}

func (k *k8sConnectivityParams) initClients(ctx context.Context) (*deploymentClients, error) {
	c := &deploymentClients{
		source:      k.client,
		destination: k.client,
	}

	_, err := k.client.GetDaemonSet(ctx, k.antreaNamespace, agentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		k.Log("Unable to determine status of Antrea DaemonSet.")
		return nil, fmt.Errorf("Unable to determine status of antrea DaemonSet: %w", err)
	}

	return c, nil
}

func (k *k8sConnectivityParams) deploy(ctx context.Context) error {
	var srcDeploymentNeeded, dstDeploymentNeeded bool

	_, err := k.clients.source.GetNamespace(ctx, k.namespace, metav1.GetOptions{})
	if err != nil {
		srcDeploymentNeeded = true
		dstDeploymentNeeded = true

		k.Log("[%s] Creating namespace for connectivity check...", k.clients.source.ClusterName())
		_, err = k.clients.source.CreateNamespace(ctx, k.namespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create namespace %s: %s", k.namespace, err)
		}
	}

	if srcDeploymentNeeded {
		k.Log("[%s] Deploying echo-same-node service...", k.clients.source.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, "http", 80)
		_, err = k.clients.source.CreateService(ctx, k.namespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		echoDeployment := newDeployment(deploymentParameters{
			Name:    echoSameNodeDeploymentName,
			Kind:    kindEchoName,
			Port:    80,
			Image:   "registry.k8s.io/e2e-test-images/agnhost:2.29",
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

		_, err = k.clients.source.CreateDeployment(ctx, k.namespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoSameNodeDeploymentName, err)
		}

		k.Log("[%s] Deploying client deployment...", k.clients.source.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    clientDeploymentName,
			Kind:    kindClientName,
			Image:   "registry.k8s.io/e2e-test-images/agnhost:2.29",
			Command: []string{"/agnhost", "pause"},
			Port:    80,
			Labels:  map[string]string{"app": clientDeploymentName},
		})
		_, err = k.clients.source.CreateDeployment(ctx, k.namespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", clientDeploymentName, err)
		}
	}

	if dstDeploymentNeeded {
		k.Log("[%s] Deploying echo-other-node service...", k.clients.destination.ClusterName())
		svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, "http", 80)
		_, err = k.clients.destination.CreateService(ctx, k.namespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		echoOtherNodeDeployment := newDeployment(deploymentParameters{
			Name:    echoOtherNodeDeploymentName,
			Kind:    kindEchoName,
			Port:    80,
			Image:   "k8s.gcr.io/e2e-test-images/agnhost:2.31",
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

		_, err = k.clients.destination.CreateDeployment(ctx, k.namespace, echoOtherNodeDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoOtherNodeDeploymentName, err)
		}
	}

	return nil
}

func (k *k8sConnectivityParams) waitForDeploymentsReady(ctx context.Context, client k8sClientOperations, deployments []string, interval, timeout time.Duration) error {
	for _, deployment := range deployments {
		k.Log("[%s] Waiting for deployment %s to become ready...", client.ClusterName(), deployment)
		err := wait.PollUntilContextTimeout(ctx, interval, timeout, false, func(ctx context.Context) (bool, error) {
			ready, err := client.DeploymentIsReady(ctx, k.namespace, deployment)
			if err != nil {
				return false, fmt.Errorf("error checking readiness of deployment %s: %w", deployment, err)
			}
			return ready, nil
		})
		if err != nil {
			return fmt.Errorf("waiting for deployment %s to become ready has been interrupted: %w", deployment, err)
		}
		k.Log("[%s] Deployment %s is ready.", client.ClusterName(), deployment)
	}
	return nil
}

func (k *k8sConnectivityParams) validateDeployment(ctx context.Context) error {
	var err error

	srcDeployments, dstDeployments := k.deploymentList()
	if err := k.waitForDeploymentsReady(ctx, k.clients.source, srcDeployments, time.Second, podReadyTimeout); err != nil {
		return err
	}
	if err := k.waitForDeploymentsReady(ctx, k.clients.destination, dstDeployments, time.Second, podReadyTimeout); err != nil {
		return err
	}

	k.clientPods, err = k.client.ListPods(ctx, k.namespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	k.echoPods = map[string]string{}
	for _, client := range k.clients.clients() {
		echoPods, err := client.ListPods(ctx, k.namespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %s", err)
		}
		for _, echoPod := range echoPods.Items {
			k.echoPods[echoPod.Name] = echoPod.Status.PodIP
		}
	}
	fmt.Fprintf(k.Writer, "Deployment is validated\n")
	return nil
}

func (k *k8sConnectivityParams) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.Writer, format+"\n", a...)
}

func (k *k8sConnectivityParams) Header(format string, a ...interface{}) {
	k.Log("-------------------------------------------------------------------------------------------")
	k.Log(format, a...)
	k.Log("-------------------------------------------------------------------------------------------")
}

type k8sClientOperations interface {
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	DeploymentIsReady(ctx context.Context, namespace, deploymentName string) (bool, error)
	DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error
	CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	ClusterName() (name string)
}
