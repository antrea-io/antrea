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
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreae2e "antrea.io/antrea/test/e2e"
	"antrea.io/antrea/test/e2e/providers"
)

var (
	homedir, _ = os.UserHomeDir()
)

const (
	defaultTimeout     = 90 * time.Second
	importServiceDelay = 2 * time.Second

	multiClusterTestNamespace string = "antrea-multicluster-test"
	eastClusterTestService    string = "east-nginx"
	westClusterTestService    string = "west-nginx"
	mcEastClusterTestService  string = "antrea-mc-east-nginx"
	mcWestClusterTestService  string = "antrea-mc-west-nginx"
	eastCluster               string = "east-cluster"
	westCluster               string = "west-cluster"
	leaderCluster             string = "leader-cluster"
	serviceExportYML          string = "serviceexport.yml"

	testServerPod           string = "test-nginx-pod"
	gatewayNodeClientSuffix string = "gateway-client"
	regularNodeClientSuffix string = "regular-client"

	nginxImage   = "projects.registry.vmware.com/antrea/nginx:1.21.6-alpine"
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.29"
)

var provider providers.ProviderInterface

type TestOptions struct {
	leaderClusterKubeConfigPath string
	westClusterKubeConfigPath   string
	eastClusterKubeConfigPath   string
	enableGateway               bool
	providerName                string
	logsExportDir               string
}

var testOptions TestOptions

type MCTestData struct {
	clusters            []string
	clusterTestDataMap  map[string]antreae2e.TestData
	controlPlaneNames   map[string]string
	logsDirForTestCase  string
	clusterGateways     map[string]string
	clusterRegularNodes map[string]string
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
		testData := antreae2e.TestData{ClusterName: cluster}
		if err := testData.CreateClient(kubeConfigPaths[i]); err != nil {
			return fmt.Errorf("error initializing clients for cluster %s: %v", cluster, err)
		}
		data.clusterTestDataMap[cluster] = testData
	}
	data.controlPlaneNames = map[string]string{
		"east-cluster":   "east-control-plane",
		"west-cluster":   "west-control-plane",
		"leader-cluster": "leader-control-plane",
	}
	return nil
}

func (data *MCTestData) initProviders() error {
	providerName := "remote"
	if testOptions.providerName == "kind" {
		providerName = testOptions.providerName
	}
	for cluster, d := range data.clusterTestDataMap {
		if err := d.InitProvider(providerName, "multicluster"); err != nil {
			log.Errorf("Failed to initialize provider for cluster %s", cluster)
			return err
		}
	}
	if testOptions.providerName == "kind" {
		provider, _ = providers.NewKindProvider("multicluster")
	} else {
		provider, _ = providers.NewRemoteProvider("multicluster")
	}
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

func (data *MCTestData) deleteTestNamespaces() error {
	for cluster, d := range data.clusterTestDataMap {
		if err := d.DeleteNamespace(multiClusterTestNamespace, defaultTimeout); err != nil {
			log.Errorf("Failed to delete Namespace %s in cluster %s", multiClusterTestNamespace, cluster)
			return err
		}
	}
	return nil
}

func (data *MCTestData) patchPod(clusterName, namespace, name string, patch []byte) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.PatchPod(namespace, name, patch); err != nil {
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

func (data *MCTestData) deletePodAndWait(clusterName, namespace, name string) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.DeletePodAndWait(defaultTimeout, namespace, name); err != nil {
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

func (data *MCTestData) createPod(clusterName, name, nodeName, namespace, ctrName, image string, command []string,
	args []string, env []corev1.EnvVar, ports []corev1.ContainerPort, hostNetwork bool, mutateFunc func(pod *corev1.Pod)) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return antreae2e.NewPodBuilder(name, namespace, image).
			OnNode(nodeName).WithContainerName(ctrName).
			WithCommand(command).WithArgs(args).
			WithEnv(env).WithPorts(ports).WithHostNetwork(hostNetwork).
			WithMutateFunc(mutateFunc).
			Create(&d)
	}
	return fmt.Errorf("clusterName %s not found", clusterName)
}

func (data *MCTestData) updatePod(clusterName string, namespace, name string, mutateFunc func(*corev1.Pod)) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.UpdatePod(namespace, name, mutateFunc); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("clusterName %s not found", clusterName)
}

func (data *MCTestData) updateNamespace(clusterName string, namespace string, mutateFunc func(*corev1.Namespace)) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		if err := d.UpdateNamespace(namespace, mutateFunc); err != nil {
			return err
		}
		return nil
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

func (data *MCTestData) createOrUpdateANNP(clusterName string, annp *crdv1beta1.NetworkPolicy) (*crdv1beta1.NetworkPolicy, error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.CreateOrUpdateANNP(annp)
	}
	return nil, fmt.Errorf("clusterName %s not found", clusterName)
}

// deleteANNP is a convenience function for deleting ANNP by name and Namespace.
func (data *MCTestData) deleteANNP(clusterName, namespace, name string) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.DeleteANNP(namespace, name)
	}
	return fmt.Errorf("clusterName %s not found", clusterName)
}

func (data *MCTestData) createOrUpdateACNP(clusterName string, acnp *crdv1beta1.ClusterNetworkPolicy) (*crdv1beta1.ClusterNetworkPolicy, error) {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.CreateOrUpdateACNP(acnp)
	}
	return nil, fmt.Errorf("clusterName %s not found", clusterName)
}

// deleteACNP is a convenience function for deleting ACNP by name.
func (data *MCTestData) deleteACNP(clusterName, name string) error {
	if d, ok := data.clusterTestDataMap[clusterName]; ok {
		return d.DeleteACNP(name)
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
	cmd := antreae2e.ProbeCommand(fmt.Sprintf("%s:%d", dstAddr, port), protocolStr[protocol], "")
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
