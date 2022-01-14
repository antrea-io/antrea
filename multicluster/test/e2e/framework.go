// Copyright 2021 Antrea Authors
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

package e2e

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"antrea.io/antrea/test/e2e/providers"
)

var (
	homedir, _ = os.UserHomeDir()
)

const (
	defaultTimeout     = 90 * time.Second
	defaultInterval    = 1 * time.Second
	importServiceDelay = 10 * time.Second

	multiClusterTestNamespace string = "antrea-multicluster-test"
	eastClusterTestService    string = "east-nginx"
	westClusterTestService    string = "west-nginx"
	eastCluster               string = "east-cluster"
	westCluster               string = "west-cluster"
	leaderCluster             string = "leader-cluster"
	serviceExportYML          string = "serviceexport.yml"

	nameSuffixLength int = 8

	nginxImage = "nginx:latest"
)

var provider providers.ProviderInterface

type TestOptions struct {
	leaderClusterKubeConfigPath string
	westClusterKubeConfigPath   string
	eastClusterKubeConfigPath   string
	logsExportDir               string
}

var testOptions TestOptions

type TestData struct {
	kubeconfigs map[string]*restclient.Config
	clients     map[string]kubernetes.Interface
	clusters    []string

	logsDirForTestCase string
}

var testData *TestData

func (data *TestData) createClients() error {
	data.clients = make(map[string]kubernetes.Interface)
	data.kubeconfigs = make(map[string]*restclient.Config)
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}

	kubeConfigPaths := []string{
		testOptions.leaderClusterKubeConfigPath,
		testOptions.eastClusterKubeConfigPath,
		testOptions.westClusterKubeConfigPath,
	}
	data.clusters = []string{
		leaderCluster, eastCluster, westCluster,
	}
	for i, cluster := range data.clusters {
		loadingRules.ExplicitPath = kubeConfigPaths[i]
		kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
		if err != nil {
			return fmt.Errorf("error when building kube config of cluster %s: %v", cluster, err)
		}
		clusterClient, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return fmt.Errorf("error when creating kubernetes client of cluster %s: %v", cluster, err)
		}
		data.kubeconfigs[cluster] = kubeConfig
		data.clients[cluster] = clusterClient
	}

	return nil
}

func (data *TestData) createTestNamespace() error {
	for _, client := range data.clients {
		if err := createNamespace(client, multiClusterTestNamespace, nil); err != nil {
			return err
		}
	}
	return nil
}

func (data *TestData) deletePod(clusterName string, namespace string, name string) error {
	client := data.getClientOfCluster(clusterName)
	return deletePod(client, namespace, name)
}

func (data *TestData) deleteService(clusterName string, namespace string, name string) error {
	client := data.getClientOfCluster(clusterName)
	return deleteService(client, namespace, name)
}

func (data *TestData) deleteTestNamespace(timeout time.Duration) error {
	return data.deleteNamespaceInAllClusters(multiClusterTestNamespace, timeout)
}

func (data *TestData) deleteNamespace(clusterName string, namespace string, timeout time.Duration) error {
	client := data.getClientOfCluster(clusterName)
	return deleteNamespace(client, namespace, timeout)
}

func (data *TestData) deleteNamespaceInAllClusters(namespace string, timeout time.Duration) error {
	for _, client := range data.clients {
		if err := deleteNamespace(client, namespace, timeout); err != nil {
			return err
		}
	}
	return nil
}

func (data *TestData) createPod(clusterName string, name string, namespace string, ctrName string, image string, command []string,
	args []string, env []corev1.EnvVar, ports []corev1.ContainerPort, hostNetwork bool, mutateFunc func(pod *corev1.Pod)) error {
	client := data.getClientOfCluster(clusterName)
	return createPod(client, name, namespace, ctrName, image, command, args, env, ports, hostNetwork, mutateFunc)
}

func (data *TestData) getService(clusterName string, namespace string, serviceName string) (*corev1.Service, error) {
	client := data.getClientOfCluster(clusterName)
	return getService(client, namespace, serviceName)
}

func (data *TestData) createService(cluster string, serviceName string, namespace string, port int32, targetPort int32,
	protocol corev1.Protocol, selector map[string]string, affinity bool, nodeLocalExternal bool, serviceType corev1.ServiceType,
	ipFamily *corev1.IPFamily, annotation map[string]string) (*corev1.Service, error) {
	client := data.getClientOfCluster(cluster)
	return createService(client, serviceName, namespace, port, targetPort, protocol, selector, affinity, nodeLocalExternal, serviceType, ipFamily, annotation)
}

func (data *TestData) getClientOfCluster(clusterName string) kubernetes.Interface {
	return data.clients[clusterName]
}

type PodCondition func(*corev1.Pod) (bool, error)

// podWaitFor polls the K8s apiserver until the specified Pod is found (in the test Namespace) and
// the condition predicate is met (or until the provided timeout expires).
func (data *TestData) podWaitFor(timeout time.Duration, clusterName string, name string, namespace string, condition PodCondition) (*corev1.Pod, error) {
	client := data.getClientOfCluster(clusterName)
	return podWaitFor(client, timeout, name, namespace, condition)
}

func initProvider() error {
	newProvider, err := providers.NewRemoteProvider("multicluster")
	if err != nil {
		return err
	}
	provider = newProvider
	return nil
}

// A DNS-1123 subdomain must consist of lower case alphanumeric characters
var lettersAndDigits = []rune("abcdefghijklmnopqrstuvwxyz0123456789")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		// #nosec G404: random number generator not used for security purposes
		randIdx := rand.Intn(len(lettersAndDigits))
		b[i] = lettersAndDigits[randIdx]
	}
	return string(b)
}

func randName(prefix string) string {
	return prefix + randSeq(nameSuffixLength)
}

func createNamespace(client kubernetes.Interface, namespace string, mutateFunc func(namespace2 *corev1.Namespace)) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if mutateFunc != nil {
		mutateFunc(ns)
	}

	if ns, err := client.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{}); err != nil {
		// Ignore error if the namespace already exists
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("error when creating '%s' Namespace: %v", namespace, err)
		}
		// When namespace already exists, check phase
		if ns.Status.Phase == corev1.NamespaceTerminating {
			return fmt.Errorf("error when creating '%s' Namespace: namespace exists but is in 'Terminating' phase", namespace)
		}
	}
	return nil
}

func deletePod(client kubernetes.Interface, namespace string, name string) error {
	var gracePeriodSeconds int64 = 5
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}

	if err := client.CoreV1().Pods(namespace).Delete(context.TODO(), name, deleteOptions); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func deleteService(client kubernetes.Interface, namespace string, name string) error {
	var gracePeriodSeconds int64 = 5
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}

	return client.CoreV1().Services(namespace).Delete(context.TODO(), name, deleteOptions)
}

func deleteNamespace(client kubernetes.Interface, namespace string, timeout time.Duration) error {
	var gracePeriodSeconds int64
	var propagationPolicy = metav1.DeletePropagationForeground
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
		PropagationPolicy:  &propagationPolicy,
	}

	if err := client.CoreV1().Namespaces().Delete(context.TODO(), namespace, deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			// namespace does not exist, we return right away
			return nil
		}
		return fmt.Errorf("error when deleting '%s' Namespace: %v", namespace, err)
	}
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if ns, err := client.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				// Success
				return true, nil
			}
			return false, fmt.Errorf("error when getting Namespace '%s' after delete: %v", namespace, err)
		} else if ns.Status.Phase != corev1.NamespaceTerminating {
			return false, fmt.Errorf("deleted Namespace '%s' should be in 'Terminating' phase", namespace)
		}

		// Keep trying
		return false, nil
	})

	return err
}

func createPod(client kubernetes.Interface, name string, namespace string, ctrName string, image string, command []string,
	args []string, env []corev1.EnvVar, ports []corev1.ContainerPort, hostNetwork bool, mutateFunc func(pod *corev1.Pod)) error {
	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:            ctrName,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         command,
				Args:            args,
				Env:             env,
				Ports:           ports,
			},
		},
		RestartPolicy: corev1.RestartPolicyNever,
		HostNetwork:   hostNetwork,
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-multicluster-e2e": name,
				"app":                     ctrName,
			},
		},
		Spec: podSpec,
	}

	if mutateFunc != nil {
		mutateFunc(pod)
	}

	_, err := client.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	return err
}

func createService(client kubernetes.Interface, serviceName string, namespace string, port int32, targetPort int32,
	protocol corev1.Protocol, selector map[string]string, affinity bool, nodeLocalExternal bool, serviceType corev1.ServiceType,
	ipFamily *corev1.IPFamily, annotation map[string]string) (*corev1.Service, error) {
	affinityType := corev1.ServiceAffinityNone
	var ipFamilies []corev1.IPFamily
	if ipFamily != nil {
		ipFamilies = append(ipFamilies, *ipFamily)
	}
	if affinity {
		affinityType = corev1.ServiceAffinityClientIP
	}
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
			Labels: map[string]string{
				"antrea-multicluster-e2e": serviceName,
				"app":                     serviceName,
			},
			Annotations: annotation,
		},
		Spec: corev1.ServiceSpec{
			SessionAffinity: affinityType,
			Ports: []corev1.ServicePort{{
				Port:       port,
				TargetPort: intstr.FromInt(int(targetPort)),
				Protocol:   protocol,
			}},
			Type:       serviceType,
			Selector:   selector,
			IPFamilies: ipFamilies,
		},
	}
	if (serviceType == corev1.ServiceTypeNodePort || serviceType == corev1.ServiceTypeLoadBalancer) && nodeLocalExternal {
		service.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}

	return client.CoreV1().Services(namespace).Create(context.TODO(), &service, metav1.CreateOptions{})
}

func getService(client kubernetes.Interface, namespace string, serviceName string) (*corev1.Service, error) {
	svc, err := client.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Error when Getting service %s/%s", namespace, serviceName)
	}
	return svc, err
}

func podWaitFor(client kubernetes.Interface, timeout time.Duration, name string, namespace string, condition PodCondition) (*corev1.Pod, error) {
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("error when getting Pod '%s' in west clsuter: %v", name, err)
		}
		return condition(pod)
	})
	if err != nil {
		return nil, err
	}
	return client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}
