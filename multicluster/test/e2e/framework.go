// Copyright 2022 Antrea Authors
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
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreae2e "antrea.io/antrea/test/e2e"
	"antrea.io/antrea/test/e2e/providers"
)

var (
	homedir, _ = os.UserHomeDir()
)

const (
	defaultTimeout     = 90 * time.Second
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

type MCTestData struct {
	clusters           []string
	clusterTestDataMap map[string]antreae2e.TestData
	logsDirForTestCase string
}

var testData *MCTestData

func (data *MCTestData) createClients() error {
	kubeConfigPaths := []string{
		testOptions.leaderClusterKubeConfigPath,
		testOptions.eastClusterKubeConfigPath,
		testOptions.westClusterKubeConfigPath,
	}
	data.clusters = []string{
		leaderCluster, eastCluster, westCluster,
	}
	data.clusterTestDataMap = map[string]antreae2e.TestData{}
	for i, cluster := range data.clusters {
		testData := antreae2e.TestData{}
		if err := testData.CreateClient(kubeConfigPaths[i]); err != nil {
			return fmt.Errorf("error initializing clients for cluster %s: %v", cluster, err)
		}
		data.clusterTestDataMap[cluster] = testData
	}
	return nil
}

func (data *MCTestData) initProviders() error {
	for cluster, d := range data.clusterTestDataMap {
		if err := d.InitProvider("remote", "multicluster"); err != nil {
			log.Errorf("Failed to initialize provider for cluster %s", cluster)
			return err
		}
	}
	provider, _ = providers.NewRemoteProvider("multicluster")
	return nil
}

func (data *MCTestData) createTestNamespaces() error {
	for cluster, d := range data.clusterTestDataMap {
		if err := d.CreateNamespace(multiClusterTestNamespace, nil); err != nil {
			log.Errorf("Failed to create Namespace %s in cluster %s", multiClusterTestNamespace, cluster)
			return err
		}
	}
	return nil
}

func (data *MCTestData) deletePod(clusterName, namespace, name string) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.DeletePod(namespace, name); err != nil {
			return err
		}
	}
	return nil
}

func (data *MCTestData) deleteService(clusterName, namespace, name string) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.DeleteService(namespace, name); err != nil {
			return err
		}
	}
	return nil
}

func (data *MCTestData) getService(clusterName, namespace, name string) (*corev1.Service, error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.GetService(namespace, name)
	}
	return nil, fmt.Errorf("clusterName %s not found", clusterName)
}

func (data *MCTestData) deleteTestNamespaces(timeout time.Duration) error {
	var failedClusters []string
	for cluster, d := range data.clusterTestDataMap {
		if err := d.DeleteNamespace(multiClusterTestNamespace, timeout); err != nil {
			failedClusters = append(failedClusters, cluster)
		}
	}
	if len(failedClusters) > 0 {
		return fmt.Errorf("failed to delete Namespace %s in clusters %v", multiClusterTestNamespace, failedClusters)
	}
	return nil
}

func (data *MCTestData) deleteNamespace(clusterName, namespace string, timeout time.Duration) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.DeleteNamespace(namespace, timeout); err != nil {
			return err
		}
	}
	return nil
}

func (data *MCTestData) createPod(clusterName, name, namespace, ctrName, image string, command []string,
	args []string, env []corev1.EnvVar, ports []corev1.ContainerPort, hostNetwork bool, mutateFunc func(pod *corev1.Pod)) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.CreatePodOnNodeInNamespace(name, namespace, "", ctrName, image, command, args, env, ports, hostNetwork, mutateFunc)
	}
	return fmt.Errorf("clusterName %s not found", clusterName)
}

func (data *MCTestData) createService(clusterName, serviceName, namespace string, port int32, targetPort int32,
	protocol corev1.Protocol, selector map[string]string, affinity bool, nodeLocalExternal bool, serviceType corev1.ServiceType,
	ipFamily *corev1.IPFamily, annotation map[string]string) (*corev1.Service, error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		svc, err := d.CreateServiceWithAnnotations(serviceName, namespace, port, targetPort, protocol, selector, affinity, nodeLocalExternal, serviceType, ipFamily, annotation)
		if err != nil {
			return nil, err
		}
		return svc, nil
	}
	return nil, fmt.Errorf("clusterName %s not found", clusterName)
}

func (data *MCTestData) createOrUpdateANP(clusterName string, anp *crdv1alpha1.NetworkPolicy) (*crdv1alpha1.NetworkPolicy, error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.CreateOrUpdateANP(anp)
	}
	return nil, fmt.Errorf("clusterName %s not found", clusterName)
}

// deleteANP is a convenience function for deleting ANP by name and Namespace.
func (data *MCTestData) deleteANP(clusterName, namespace, name string) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.DeleteANP(namespace, name)
	}
	return fmt.Errorf("clusterName %s not found", clusterName)
}

// podWaitFor polls the K8s apiserver until the specified Pod is found (in the test Namespace) and
// the condition predicate is met (or until the provided timeout expires).
func (data *MCTestData) podWaitFor(timeout time.Duration, clusterName, name, namespace string, condition antreae2e.PodCondition) (*corev1.Pod, error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.PodWaitFor(timeout, name, namespace, condition)
	}
	return nil, fmt.Errorf("clusterName %s not found", clusterName)
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

func (data *MCTestData) probeServiceFromPodInCluster(
	cluster string,
	podName string,
	containerName string,
	podNamespace string,
	serviceIP string,
) error {
	cmd := []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf("curl --connect-timeout 5 -s %s", serviceIP),
	}
	log.Tracef("Running: kubectl exec %s -c %s -n %s -- %s", podName, containerName, podNamespace, strings.Join(cmd, " "))
	stdout, stderr, err := data.runCommandFromPod(cluster, podNamespace, podName, containerName, cmd)
	if err != nil || stderr != "" {
		return fmt.Errorf("%s -> %s: error when running command: err - %v /// stdout - %s /// stderr - %s", podName, serviceIP, err, stdout, stderr)
	}
	return nil
}

func (data *MCTestData) probeFromPodInCluster(
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
		return antreae2e.DecideProbeResult(stderr, 3)
	}
	return antreae2e.Connected
}

// Run the provided command in the specified Container for the given Pod and returns the contents of
// stdout and stderr as strings. An error either indicates that the command couldn't be run or that
// the command returned a non-zero error code.
func (data *MCTestData) runCommandFromPod(clusterName, podNamespace, podName, containerName string, cmd []string) (stdout string, stderr string, err error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.RunCommandFromPod(podNamespace, podName, containerName, cmd)
	}
	return "", "", fmt.Errorf("clusterName %s not found", clusterName)
}
