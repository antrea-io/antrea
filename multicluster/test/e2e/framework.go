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
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	antreae2e "antrea.io/antrea/test/e2e"
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

	nginxImage   = "projects.registry.vmware.com/antrea/nginx:1.21.6-alpine"
	agnhostImage = "agnhost:2.26"
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
	crdClients  map[string]crdclientset.Interface
	clusters    []string

	logsDirForTestCase string
}

var testData *TestData

func (data *TestData) createClients() error {
	data.clients = make(map[string]kubernetes.Interface)
	data.kubeconfigs = make(map[string]*restclient.Config)
	data.crdClients = make(map[string]crdclientset.Interface)
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
			return fmt.Errorf("error when creating Kubernetes client of cluster %s: %v", cluster, err)
		}
		crdClient, err := crdclientset.NewForConfig(kubeConfig)
		if err != nil {
			return fmt.Errorf("error when creating crd client of cluster %s: %v", cluster, err)
		}
		data.kubeconfigs[cluster] = kubeConfig
		data.clients[cluster] = clusterClient
		data.crdClients[cluster] = crdClient
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

func (data *TestData) getCRDClientOfCluster(clusterName string) crdclientset.Interface {
	return data.crdClients[clusterName]
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

func (data *TestData) probe(
	cluster string,
	podNamespace string,
	podName string,
	containerName string,
	dstAddr string,
	dstName string,
	port int32,
	protocol corev1.Protocol,
) antreae2e.PodConnectivityMark {
	protocolStr := map[corev1.Protocol]string{
		corev1.ProtocolTCP:  "tcp",
		corev1.ProtocolUDP:  "udp",
		corev1.ProtocolSCTP: "sctp",
	}
	// There seems to be an issue when running Antrea in Kind where tunnel traffic is dropped at
	// first. This leads to the first test being run consistently failing. To avoid this issue
	// until it is resolved, we try to connect 3 times.
	// See https://github.com/antrea-io/antrea/issues/467.
	cmd := []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf("for i in $(seq 1 3); do /agnhost connect %s:%d --timeout=1s --protocol=%s; done;", dstAddr, port, protocolStr[protocol]),
	}
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", podName, containerName, podNamespace, strings.Join(cmd, " "))
	stdout, stderr, err := data.runCommandFromPod(cluster, podNamespace, podName, containerName, cmd)
	// It needs to check both err and stderr because:
	// 1. The probe tried 3 times. If it checks err only, failure+failure+success would be considered connected.
	// 2. There might be an issue in Pod exec API that it sometimes doesn't return error when the probe fails. See #2394.
	if err != nil || stderr != "" {
		// log this error as trace since may be an expected failure
		log.Tracef("%s -> %s: error when running command: err - %v /// stdout - %s /// stderr - %s", podName, dstName, err, stdout, stderr)
		// If err != nil and stderr == "", then it means this probe failed because of
		// the command instead of connectivity. For example, container name doesn't exist.
		if stderr == "" {
			return antreae2e.Error
		}
		return decideProbeResult(stderr, 3)
	}
	return antreae2e.Connected
}

// decideProbeResult uses the probe stderr to decide the connectivity.
func decideProbeResult(stderr string, probeNum int) antreae2e.PodConnectivityMark {
	countConnected := probeNum - strings.Count(stderr, "\n")
	countDropped := strings.Count(stderr, "TIMEOUT")
	// For our UDP rejection cases, agnhost will return:
	//   For IPv4: 'UNKNOWN: read udp [src]->[dst]: read: no route to host'
	//   For IPv6: 'UNKNOWN: read udp [src]->[dst]: read: permission denied'
	// To avoid incorrect identification, we use 'no route to host' and
	// `permission denied`, instead of 'UNKNOWN' as key string.
	// For our other protocols rejection cases, agnhost will return 'REFUSED'.
	countRejected := strings.Count(stderr, "REFUSED") + strings.Count(stderr, "no route to host") + strings.Count(stderr, "permission denied")

	if countRejected == 0 && countConnected > 0 {
		return antreae2e.Connected
	}
	if countConnected == 0 && countRejected > 0 {
		return antreae2e.Rejected
	}
	if countDropped == probeNum {
		return antreae2e.Dropped
	}
	return antreae2e.Error
}

// Run the provided command in the specified Container for the given Pod and returns the contents of
// stdout and stderr as strings. An error either indicates that the command couldn't be run or that
// the command returned a non-zero error code.
func (data *TestData) runCommandFromPod(cluster, podNamespace, podName, containerName string, cmd []string) (stdout string, stderr string, err error) {
	request := data.clients[cluster].CoreV1().RESTClient().Post().
		Namespace(podNamespace).
		Resource("pods").
		Name(podName).
		SubResource("exec").
		Param("container", containerName).
		VersionedParams(&corev1.PodExecOptions{
			Command: cmd,
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(data.kubeconfigs[cluster], "POST", request.URL())
	if err != nil {
		return "", "", err
	}
	var stdoutB, stderrB bytes.Buffer
	if err := exec.Stream(remotecommand.StreamOptions{
		Stdout: &stdoutB,
		Stderr: &stderrB,
	}); err != nil {
		return stdoutB.String(), stderrB.String(), err
	}
	return stdoutB.String(), stderrB.String(), nil
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

// createOrUpdateANP is a convenience function for updating/creating Antrea NetworkPolicies.
func createOrUpdateANP(crdClient crdclientset.Interface, anp *crdv1alpha1.NetworkPolicy) (*crdv1alpha1.NetworkPolicy, error) {
	log.Infof("Creating/updating Antrea NetworkPolicy %s/%s", anp.Namespace, anp.Name)
	cnpReturned, err := crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Get(context.TODO(), anp.Name, metav1.GetOptions{})
	if err != nil {
		log.Debugf("Creating Antrea NetworkPolicy %s", anp.Name)
		anp, err = crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Create(context.TODO(), anp, metav1.CreateOptions{})
		if err != nil {
			log.Debugf("Unable to create Antrea NetworkPolicy: %s", err)
		}
		return anp, err
	} else if cnpReturned.Name != "" {
		log.Debugf("Antrea NetworkPolicy with name %s already exists, updating", anp.Name)
		anp, err = crdClient.CrdV1alpha1().NetworkPolicies(anp.Namespace).Update(context.TODO(), anp, metav1.UpdateOptions{})
		return anp, err
	}
	return nil, fmt.Errorf("error occurred in creating/updating Antrea NetworkPolicy %s", anp.Name)
}

// deleteANP is a convenience function for deleting ANP by name and Namespace.
func deleteANP(crdClient crdclientset.Interface, ns, name string) error {
	log.Infof("Deleting Antrea NetworkPolicy '%s/%s'", ns, name)
	err := crdClient.CrdV1alpha1().NetworkPolicies(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to delete Antrea NetworkPolicy %s: %v", name, err)
	}
	return nil
}
