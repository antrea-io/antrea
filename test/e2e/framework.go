// Copyright 2019 Antrea Authors
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
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/component-base/featuregate"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/typed/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/test/e2e/providers"
)

const (
	defaultTimeout  = 90 * time.Second
	defaultInterval = 1 * time.Second

	// antreaNamespace is the K8s Namespace in which all Antrea resources are running.
	antreaNamespace            string = "kube-system"
	flowAggregatorNamespace    string = "flow-aggregator"
	antreaConfigVolume         string = "antrea-config"
	flowAggregatorConfigVolume string = "flow-aggregator-config"
	antreaDaemonSet            string = "antrea-agent"
	antreaDeployment           string = "antrea-controller"
	flowAggregatorDeployment   string = "flow-aggregator"
	antreaDefaultGW            string = "antrea-gw0"
	testNamespace              string = "antrea-test"
	busyboxContainerName       string = "busybox"
	controllerContainerName    string = "antrea-controller"
	ovsContainerName           string = "antrea-ovs"
	agentContainerName         string = "antrea-agent"
	antreaYML                  string = "antrea.yml"
	antreaIPSecYML             string = "antrea-ipsec.yml"
	antreaCovYML               string = "antrea-coverage.yml"
	antreaIPSecCovYML          string = "antrea-ipsec-coverage.yml"
	flowaggregatorYML          string = "flow-aggregator.yml"
	defaultBridgeName          string = "br-int"
	monitoringNamespace        string = "monitoring"

	antreaControllerCovBinary string = "antrea-controller-coverage"
	antreaAgentCovBinary      string = "antrea-agent-coverage"
	antreaControllerCovFile   string = "antrea-controller.cov.out"
	antreaAgentCovFile        string = "antrea-agent.cov.out"

	antreaAgentConfName      string = "antrea-agent.conf"
	antreaControllerConfName string = "antrea-controller.conf"
	flowAggregatorConfName   string = "flow-aggregator.conf"

	nameSuffixLength int = 8

	agnhostImage        = "gcr.io/kubernetes-e2e-test-images/agnhost:2.8"
	busyboxImage        = "projects.registry.vmware.com/library/busybox"
	nginxImage          = "projects.registry.vmware.com/antrea/nginx"
	perftoolImage       = "projects.registry.vmware.com/antrea/perftool"
	ipfixCollectorImage = "projects.registry.vmware.com/antrea/ipfix-collector:v0.4.2"
	ipfixCollectorPort  = "4739"

	nginxLBService = "nginx-loadbalancer"
)

type ClusterNode struct {
	idx  int // 0 for control-plane Node
	name string
}

type ClusterInfo struct {
	numWorkerNodes       int
	numNodes             int
	podV4NetworkCIDR     string
	podV6NetworkCIDR     string
	svcV4NetworkCIDR     string
	svcV6NetworkCIDR     string
	controlPlaneNodeName string
	nodes                map[int]ClusterNode
	k8sServerVersion     string
}

var clusterInfo ClusterInfo

type TestOptions struct {
	providerName        string
	providerConfigPath  string
	logsExportDir       string
	logsExportOnSuccess bool
	withBench           bool
	enableCoverage      bool
	coverageDir         string
}

var testOptions TestOptions

var provider providers.ProviderInterface

// TestData stores the state required for each test case.
type TestData struct {
	kubeConfig         *restclient.Config
	clientset          kubernetes.Interface
	aggregatorClient   aggregatorclientset.Interface
	securityClient     secv1alpha1.SecurityV1alpha1Interface
	crdClient          crdclientset.Interface
	logsDirForTestCase string
}

var testData *TestData

type PodIPs struct {
	ipv4      *net.IP
	ipv6      *net.IP
	ipStrings []string
}

func (p PodIPs) String() string {
	res := ""
	if p.ipv4 != nil {
		res += fmt.Sprintf("IPv4: %s, ", p.ipv4.String())
	}
	if p.ipv6 != nil {
		res += fmt.Sprintf("IPv6: %s, ", p.ipv6.String())
	}
	return fmt.Sprintf("%sIP strings: %s", res, strings.Join(p.ipStrings, ", "))
}

func (p *PodIPs) hasSameIP(p1 *PodIPs) bool {
	if len(p.ipStrings) == 0 && len(p1.ipStrings) == 0 {
		return true
	}
	if p.ipv4 != nil && p1.ipv4 != nil && p.ipv4.Equal(*(p1.ipv4)) {
		return true
	}
	if p.ipv6 != nil && p1.ipv6 != nil && p.ipv6.Equal(*(p1.ipv6)) {
		return true
	}
	return false
}

// workerNodeName returns an empty string if there is no worker Node with the provided idx
// (including if idx is 0, which is reserved for the control-plane Node)
func workerNodeName(idx int) string {
	if idx == 0 { // control-plane Node
		return ""
	}
	if node, ok := clusterInfo.nodes[idx]; !ok {
		return ""
	} else {
		return node.name
	}
}

func controlPlaneNodeName() string {
	return clusterInfo.controlPlaneNodeName
}

// nodeName returns an empty string if there is no Node with the provided idx. If idx is 0, the name
// of the control-plane Node will be returned.
func nodeName(idx int) string {
	if node, ok := clusterInfo.nodes[idx]; !ok {
		return ""
	} else {
		return node.name
	}
}

func labelNodeRoleControlPlane() string {
	// TODO: return labelNodeRoleControlPlane unconditionally when the min K8s version
	// requirement to run Antrea becomes K8s v1.20
	const labelNodeRoleControlPlane = "node-role.kubernetes.io/control-plane"
	const labelNodeRoleOldControlPlane = "node-role.kubernetes.io/master"
	// If clusterInfo.k8sServerVersion < "v1.20.0"
	if semver.Compare(clusterInfo.k8sServerVersion, "v1.20.0") < 0 {
		return labelNodeRoleOldControlPlane
	}
	return labelNodeRoleControlPlane
}

func initProvider() error {
	providerFactory := map[string]func(string) (providers.ProviderInterface, error){
		"vagrant": providers.NewVagrantProvider,
		"kind":    providers.NewKindProvider,
		"remote":  providers.NewRemoteProvider,
	}
	if fn, ok := providerFactory[testOptions.providerName]; ok {
		if newProvider, err := fn(testOptions.providerConfigPath); err != nil {
			return err
		} else {
			provider = newProvider
		}
	} else {
		return fmt.Errorf("unknown provider '%s'", testOptions.providerName)
	}
	return nil
}

// RunCommandOnNode is a convenience wrapper around the Provider interface RunCommandOnNode method.
func RunCommandOnNode(nodeName string, cmd string) (code int, stdout string, stderr string, err error) {
	return provider.RunCommandOnNode(nodeName, cmd)
}

func collectClusterInfo() error {
	// retrieve Node information
	nodes, err := testData.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error when listing cluster Nodes: %v", err)
	}
	workerIdx := 1
	clusterInfo.nodes = make(map[int]ClusterNode)
	for _, node := range nodes.Items {
		isControlPlaneNode := func() bool {
			_, ok := node.Labels[labelNodeRoleControlPlane()]
			return ok
		}()

		var nodeIdx int
		// If multiple control-plane Nodes (HA), we will select the last one in the list
		if isControlPlaneNode {
			nodeIdx = 0
			clusterInfo.controlPlaneNodeName = node.Name
		} else {
			nodeIdx = workerIdx
			workerIdx++
		}

		clusterInfo.nodes[nodeIdx] = ClusterNode{
			idx:  nodeIdx,
			name: node.Name,
		}
	}
	if clusterInfo.controlPlaneNodeName == "" {
		return fmt.Errorf("error when listing cluster Nodes: control-plane Node not found")
	}
	clusterInfo.numNodes = workerIdx
	clusterInfo.numWorkerNodes = clusterInfo.numNodes - 1

	retrieveCIDRs := func(cmd string, reg string) ([]string, error) {
		res := make([]string, 2)
		rc, stdout, _, err := RunCommandOnNode(clusterInfo.controlPlaneNodeName, cmd)
		if err != nil || rc != 0 {
			return res, fmt.Errorf("error when running the following command `%s` on control-plane Node: %v, %s", cmd, err, stdout)
		}
		re := regexp.MustCompile(reg)
		if matches := re.FindStringSubmatch(stdout); len(matches) == 0 {
			return res, fmt.Errorf("cannot retrieve CIDR, unexpected kubectl output: %s", stdout)
		} else {
			cidrs := strings.Split(matches[1], ",")
			if len(cidrs) == 1 {
				_, cidr, err := net.ParseCIDR(cidrs[0])
				if err != nil {
					return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
				}
				if cidr.IP.To4() != nil {
					res[0] = cidrs[0]
				} else {
					res[1] = cidrs[0]
				}
			} else if len(cidrs) == 2 {
				_, cidr, err := net.ParseCIDR(cidrs[0])
				if err != nil {
					return res, fmt.Errorf("CIDR cannot be parsed: %s", cidrs[0])
				}
				if cidr.IP.To4() != nil {
					res[0] = cidrs[0]
					res[1] = cidrs[1]
				} else {
					res[0] = cidrs[1]
					res[1] = cidrs[0]
				}
			} else {
				return res, fmt.Errorf("unexpected cluster CIDR: %s", matches[1])
			}
		}
		return res, nil
	}

	// retrieve cluster CIDRs
	podCIDRs, err := retrieveCIDRs("kubectl cluster-info dump | grep cluster-cidr", `cluster-cidr=([^"]+)`)
	if err != nil {
		return err
	}
	clusterInfo.podV4NetworkCIDR = podCIDRs[0]
	clusterInfo.podV6NetworkCIDR = podCIDRs[1]

	// retrieve service CIDRs
	svcCIDRs, err := retrieveCIDRs("kubectl cluster-info dump | grep service-cluster-ip-range", `service-cluster-ip-range=([^"]+)`)
	if err != nil {
		return err
	}
	clusterInfo.svcV4NetworkCIDR = svcCIDRs[0]
	clusterInfo.svcV6NetworkCIDR = svcCIDRs[1]

	// retrieve K8s server version

	serverVersion, err := testData.clientset.Discovery().ServerVersion()
	if err != nil {
		return err
	}
	clusterInfo.k8sServerVersion = serverVersion.String()

	return nil
}

// createNamespace creates the provided namespace.
func (data *TestData) createNamespace(namespace string) error {
	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if ns, err := data.clientset.CoreV1().Namespaces().Create(context.TODO(), &ns, metav1.CreateOptions{}); err != nil {
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

// createTestNamespace creates the namespace used for tests.
func (data *TestData) createTestNamespace() error {
	return data.createNamespace(testNamespace)
}

// deleteNamespace deletes the provided namespace and waits for deletion to actually complete.
func (data *TestData) deleteNamespace(namespace string, timeout time.Duration) error {
	var gracePeriodSeconds int64 = 0
	var propagationPolicy = metav1.DeletePropagationForeground
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
		PropagationPolicy:  &propagationPolicy,
	}
	if err := data.clientset.CoreV1().Namespaces().Delete(context.TODO(), namespace, deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			// namespace does not exist, we return right away
			return nil
		}
		return fmt.Errorf("error when deleting '%s' Namespace: %v", namespace, err)
	}
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if ns, err := data.clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{}); err != nil {
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

// deleteTestNamespace deletes test namespace and waits for deletion to actually complete.
func (data *TestData) deleteTestNamespace(timeout time.Duration) error {
	return data.deleteNamespace(testNamespace, timeout)
}

// deployAntreaCommon deploys Antrea using kubectl on the control-plane Node.
func (data *TestData) deployAntreaCommon(yamlFile string, extraOptions string) error {
	// TODO: use the K8s apiserver when server side apply is available?
	// See https://kubernetes.io/docs/reference/using-api/api-concepts/#server-side-apply
	rc, _, _, err := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply %s -f %s", extraOptions, yamlFile))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying Antrea; is %s available on the control-plane Node?", yamlFile)
	}
	rc, _, _, err = provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status deploy/%s --timeout=%v", antreaNamespace, antreaDeployment, defaultTimeout))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when waiting for antrea-controller rollout to complete")
	}
	rc, _, _, err = provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status ds/%s --timeout=%v", antreaNamespace, antreaDaemonSet, defaultTimeout))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when waiting for antrea-agent rollout to complete")
	}

	return nil
}

// deployAntrea deploys Antrea with the standard manifest.
func (data *TestData) deployAntrea() error {
	if testOptions.enableCoverage {
		return data.deployAntreaCommon(antreaCovYML, "")
	}
	return data.deployAntreaCommon(antreaYML, "")
}

// deployAntreaIPSec deploys Antrea with IPSec tunnel enabled.
func (data *TestData) deployAntreaIPSec() error {
	if testOptions.enableCoverage {
		return data.deployAntreaCommon(antreaIPSecCovYML, "")
	}
	return data.deployAntreaCommon(antreaIPSecYML, "")
}

// deployAntreaFlowExporter deploys Antrea with flow exporter config params enabled.
func (data *TestData) deployAntreaFlowExporter(ipfixCollector string) error {
	// Enable flow exporter feature and add related config params to antrea agent configmap.
	return data.mutateAntreaConfigMap(func(data map[string]string) {
		antreaAgentConf, _ := data["antrea-agent.conf"]
		antreaAgentConf = strings.Replace(antreaAgentConf, "#  FlowExporter: false", "  FlowExporter: true", 1)
		if ipfixCollector != "" {
			antreaAgentConf = strings.Replace(antreaAgentConf, "#flowCollectorAddr: \"flow-aggregator.flow-aggregator.svc:4739:tcp\"", fmt.Sprintf("flowCollectorAddr: \"%s\"", ipfixCollector), 1)
		}
		antreaAgentConf = strings.Replace(antreaAgentConf, "#flowPollInterval: \"5s\"", "flowPollInterval: \"1s\"", 1)
		antreaAgentConf = strings.Replace(antreaAgentConf, "#flowExportFrequency: 12", "flowExportFrequency: 2", 1)
		data["antrea-agent.conf"] = antreaAgentConf
	}, false, true)
}

// deployFlowAggregator deploys flow aggregator with ipfix collector address.
func (data *TestData) deployFlowAggregator(ipfixCollector string) (string, error) {
	rc, _, _, err := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s", flowaggregatorYML))
	if err != nil || rc != 0 {
		return "", fmt.Errorf("error when deploying flow aggregator; %s not available on the control-plane Node", flowaggregatorYML)
	}
	if err = data.mutateFlowAggregatorConfigMap(ipfixCollector); err != nil {
		return "", err
	}
	if rc, _, _, err = provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status deployment/%s --timeout=%v", flowAggregatorNamespace, flowAggregatorDeployment, 2*defaultTimeout)); err != nil || rc != 0 {
		_, stdout, _, _ := provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s describe pod", flowAggregatorNamespace))
		return stdout, fmt.Errorf("error when waiting for flow aggregator rollout to complete. kubectl describe output: %v", stdout)
	}
	svc, err := data.clientset.CoreV1().Services(flowAggregatorNamespace).Get(context.TODO(), flowAggregatorDeployment, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to get service %v: %v", flowAggregatorDeployment, err)
	}
	return svc.Spec.ClusterIP, nil
}

func (data *TestData) mutateFlowAggregatorConfigMap(ipfixCollector string) error {
	configMap, err := data.GetFlowAggregatorConfigMap()
	if err != nil {
		return err
	}
	flowAggregatorConf, _ := configMap.Data[flowAggregatorConfName]
	flowAggregatorConf = strings.Replace(flowAggregatorConf, "#externalFlowCollectorAddr: \"\"", fmt.Sprintf("externalFlowCollectorAddr: \"%s\"", ipfixCollector), 1)
	flowAggregatorConf = strings.Replace(flowAggregatorConf, "#flowExportInterval: 60s", "flowExportInterval: 5s", 1)
	configMap.Data[flowAggregatorConfName] = flowAggregatorConf
	if _, err := data.clientset.CoreV1().ConfigMaps(flowAggregatorNamespace).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update ConfigMap %s: %v", configMap.Name, err)
	}
	return nil
}

func (data *TestData) GetFlowAggregatorConfigMap() (*corev1.ConfigMap, error) {
	deployment, err := data.clientset.AppsV1().Deployments(flowAggregatorNamespace).Get(context.TODO(), flowAggregatorDeployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Flow aggregator deployment: %v", err)
	}
	var configMapName string
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil && volume.Name == flowAggregatorConfigVolume {
			configMapName = volume.ConfigMap.Name
			break
		}
	}
	if len(configMapName) == 0 {
		return nil, fmt.Errorf("failed to locate %s ConfigMap volume", flowAggregatorConfigVolume)
	}
	configMap, err := data.clientset.CoreV1().ConfigMaps(flowAggregatorNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s: %v", configMapName, err)
	}
	return configMap, nil
}

// getAgentContainersRestartCount reads the restart count for every container across all Antrea
// Agent Pods and returns the sum of all the read values.
func (data *TestData) getAgentContainersRestartCount() (int, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-agent",
	}
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
	if err != nil {
		return 0, fmt.Errorf("failed to list antrea-agent Pods: %v", err)
	}
	containerRestarts := 0
	for _, pod := range pods.Items {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			containerRestarts += int(containerStatus.RestartCount)
		}
	}
	return containerRestarts, nil
}

// waitForAntreaDaemonSetPods waits for the K8s apiserver to report that all the Antrea Pods are
// available, i.e. all the Nodes have one or more of the Antrea daemon Pod running and available.
func (data *TestData) waitForAntreaDaemonSetPods(timeout time.Duration) error {
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		daemonSet, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), antreaDaemonSet, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error when getting Antrea daemonset: %v", err)
		}

		// Make sure that all Daemon Pods are available.
		// We use clusterInfo.numNodes instead of DesiredNumberScheduled because
		// DesiredNumberScheduled may not be updated right away. If it is still set to 0 the
		// first time we get the DaemonSet's Status, we would return immediately instead of
		// waiting.
		desiredNumber := int32(clusterInfo.numNodes)
		if daemonSet.Status.NumberAvailable != desiredNumber ||
			daemonSet.Status.UpdatedNumberScheduled != desiredNumber {
			return false, nil
		}

		// Make sure that all antrea-agent Pods are not terminating. This is required because NumberAvailable of
		// DaemonSet counts Pods even if they are terminating. Deleting antrea-agent Pods directly does not cause the
		// number to decrease if the process doesn't quit immediately, e.g. when the signal is caught by bincover
		// program and triggers coverage calculation.
		pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=antrea,component=antrea-agent",
		})
		if err != nil {
			return false, fmt.Errorf("failed to list antrea-agent Pods: %v", err)
		}
		if len(pods.Items) != clusterInfo.numNodes {
			return false, nil
		}
		for _, pod := range pods.Items {
			if pod.DeletionTimestamp != nil {
				return false, nil
			}
		}
		return true, nil
	})
	if err == wait.ErrWaitTimeout {
		return fmt.Errorf("antrea-agent DaemonSet not ready within %v", defaultTimeout)
	} else if err != nil {
		return err
	}

	return nil
}

// waitForCoreDNSPods waits for the K8s apiserver to report that all the CoreDNS Pods are available.
func (data *TestData) waitForCoreDNSPods(timeout time.Duration) error {
	err := wait.PollImmediate(defaultInterval, timeout, func() (bool, error) {
		deployment, err := data.clientset.AppsV1().Deployments("kube-system").Get(context.TODO(), "coredns", metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error when retrieving CoreDNS deployment: %v", err)
		}
		if deployment.Status.UnavailableReplicas == 0 {
			return true, nil
		}
		// Keep trying
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return fmt.Errorf("some CoreDNS replicas are still unavailable after %v", defaultTimeout)
	} else if err != nil {
		return err
	}
	return nil
}

// restartCoreDNSPods deletes all the CoreDNS Pods to force them to be re-scheduled. It then waits
// for all the Pods to become available, by calling waitForCoreDNSPods.
func (data *TestData) restartCoreDNSPods(timeout time.Duration) error {
	var gracePeriodSeconds int64 = 1
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	listOptions := metav1.ListOptions{
		LabelSelector: "k8s-app=kube-dns",
	}
	if err := data.clientset.CoreV1().Pods(antreaNamespace).DeleteCollection(context.TODO(), deleteOptions, listOptions); err != nil {
		return fmt.Errorf("error when deleting all CoreDNS Pods: %v", err)
	}
	return data.waitForCoreDNSPods(timeout)
}

// checkCoreDNSPods checks that all the Pods for the CoreDNS deployment are ready. If not, it
// deletes all the Pods to force them to restart and waits up to timeout for the Pods to become
// ready.
func (data *TestData) checkCoreDNSPods(timeout time.Duration) error {
	if deployment, err := data.clientset.AppsV1().Deployments(antreaNamespace).Get(context.TODO(), "coredns", metav1.GetOptions{}); err != nil {
		return fmt.Errorf("error when retrieving CoreDNS deployment: %v", err)
	} else if deployment.Status.UnavailableReplicas == 0 {
		// deployment ready, nothing to do
		return nil
	}
	return data.restartCoreDNSPods(timeout)
}

// createClient initializes the K8s clientset in the TestData structure.
func (data *TestData) createClient() error {
	kubeconfigPath, err := provider.GetKubeconfigPath()
	if err != nil {
		return fmt.Errorf("error when getting Kubeconfig path: %v", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath
	configOverrides := &clientcmd.ConfigOverrides{}

	kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		return fmt.Errorf("error when building kube config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("error when creating kubernetes client: %v", err)
	}
	aggregatorClient, err := aggregatorclientset.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("error when creating kubernetes aggregatorClient: %v", err)
	}
	securityClient, err := secv1alpha1.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("error when creating Antrea securityClient: %v", err)
	}
	crdClient, err := crdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("error when creating CRD client: %v", err)
	}
	data.kubeConfig = kubeConfig
	data.clientset = clientset
	data.aggregatorClient = aggregatorClient
	data.securityClient = securityClient
	data.crdClient = crdClient
	return nil
}

// deleteAntrea deletes the Antrea DaemonSet; we use cascading deletion, which means all the Pods created
// by Antrea will be deleted. After issuing the deletion request, we poll the K8s apiserver to ensure
// that the DaemonSet does not exist any more. This function is a no-op if the Antrea DaemonSet does
// not exist at the time the function is called.
func (data *TestData) deleteAntrea(timeout time.Duration) error {
	if testOptions.enableCoverage {
		data.gracefulExitAntreaAgent(testOptions.coverageDir, "all")
	}
	var gracePeriodSeconds int64 = 5
	// Foreground deletion policy ensures that by the time the DaemonSet is deleted, there are
	// no Antrea Pods left.
	var propagationPolicy = metav1.DeletePropagationForeground
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
		PropagationPolicy:  &propagationPolicy,
	}
	if err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Delete(context.TODO(), antreaDaemonSet, deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			// no Antrea DaemonSet running, we return right away
			return nil
		}
		return fmt.Errorf("error when trying to delete Antrea DaemonSet: %v", err)
	}
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if _, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), antreaDaemonSet, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				// Antrea DaemonSet does not exist any more, success
				return true, nil
			}
			return false, fmt.Errorf("error when trying to get Antrea DaemonSet after deletion: %v", err)
		}

		// Keep trying
		return false, nil
	})
	return err
}

// getImageName gets the image name from the fully qualified URI.
// For example: "gcr.io/kubernetes-e2e-test-images/agnhost:2.8" gets "agnhost".
func getImageName(uri string) string {
	registryAndImage := strings.Split(uri, ":")[0]
	paths := strings.Split(registryAndImage, "/")
	return paths[len(paths)-1]
}

// createPodOnNode creates a pod in the test namespace with a container whose type is decided by imageName.
// Pod will be scheduled on the specified Node (if nodeName is not empty).
// mutateFunc can be used to customize the Pod if the other parameters don't meet the requirements.
func (data *TestData) createPodOnNode(name string, nodeName string, image string, command []string, args []string, env []corev1.EnvVar, ports []corev1.ContainerPort, hostNetwork bool, mutateFunc func(*corev1.Pod)) error {
	// image could be a fully qualified URI which can't be used as container name and label value,
	// extract the image name from it.
	imageName := getImageName(image)
	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:            imageName,
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
	if nodeName != "" {
		podSpec.NodeSelector = map[string]string{
			"kubernetes.io/hostname": nodeName,
		}
	}
	if nodeName == controlPlaneNodeName() {
		// tolerate NoSchedule taint if we want Pod to run on control-plane Node
		noScheduleToleration := corev1.Toleration{
			Key:      labelNodeRoleControlPlane(),
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		}
		podSpec.Tolerations = []corev1.Toleration{noScheduleToleration}
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-e2e": name,
				"app":        imageName,
			},
		},
		Spec: podSpec,
	}
	if mutateFunc != nil {
		mutateFunc(pod)
	}
	if _, err := data.clientset.CoreV1().Pods(testNamespace).Create(context.TODO(), pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

// createBusyboxPodOnNode creates a Pod in the test namespace with a single busybox container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createBusyboxPodOnNode(name string, nodeName string) error {
	sleepDuration := 3600 // seconds
	return data.createPodOnNode(name, nodeName, busyboxImage, []string{"sleep", strconv.Itoa(sleepDuration)}, nil, nil, nil, false, nil)
}

// createBusyboxPod creates a Pod in the test namespace with a single busybox container.
func (data *TestData) createBusyboxPod(name string) error {
	return data.createBusyboxPodOnNode(name, "")
}

// createNginxPodOnNode creates a Pod in the test namespace with a single nginx container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createNginxPodOnNode(name string, nodeName string) error {
	return data.createPodOnNode(name, nodeName, nginxImage, []string{}, nil, nil, []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
	}, false, nil)
}

// createNginxPod creates a Pod in the test namespace with a single nginx container.
func (data *TestData) createNginxPod(name, nodeName string) error {
	return data.createNginxPodOnNode(name, nodeName)
}

// createServerPod creates a Pod that can listen to specified port and have named port set.
func (data *TestData) createServerPod(name string, portName string, portNum int, setHostPort bool) error {
	// See https://github.com/kubernetes/kubernetes/blob/master/test/images/agnhost/porter/porter.go#L17 for the image's detail.
	cmd := "porter"
	env := corev1.EnvVar{Name: fmt.Sprintf("SERVE_PORT_%d", portNum), Value: "foo"}
	port := corev1.ContainerPort{Name: portName, ContainerPort: int32(portNum)}
	if setHostPort {
		// If hostPort is to be set, it must match the container port number.
		port.HostPort = int32(portNum)
	}
	return data.createPodOnNode(name, "", agnhostImage, nil, []string{cmd}, []corev1.EnvVar{env}, []corev1.ContainerPort{port}, false, nil)
}

// deletePod deletes a Pod in the test namespace.
func (data *TestData) deletePod(name string) error {
	var gracePeriodSeconds int64 = 5
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	if err := data.clientset.CoreV1().Pods(testNamespace).Delete(context.TODO(), name, deleteOptions); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// Deletes a Pod in the test namespace then waits us to timeout for the Pod not to be visible to the
// client any more.
func (data *TestData) deletePodAndWait(timeout time.Duration, name string) error {
	if err := data.deletePod(name); err != nil {
		return err
	}

	if err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if _, err := data.clientset.CoreV1().Pods(testNamespace).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, fmt.Errorf("error when getting Pod: %v", err)
		}
		// Keep trying
		return false, nil
	}); err == wait.ErrWaitTimeout {
		return fmt.Errorf("Pod '%s' still visible to client after %v", name, timeout)
	} else {
		return err
	}
}

type PodCondition func(*corev1.Pod) (bool, error)

// podWaitFor polls the K8s apiserver until the specified Pod is found (in the test Namespace) and
// the condition predicate is met (or until the provided timeout expires).
func (data *TestData) podWaitFor(timeout time.Duration, name, namespace string, condition PodCondition) (*corev1.Pod, error) {
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if pod, err := data.clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("error when getting Pod '%s': %v", name, err)
		} else {
			return condition(pod)
		}
	})
	if err != nil {
		return nil, err
	}
	return data.clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

// podWaitForRunning polls the k8s apiserver until the specified Pod is in the "running" state (or
// until the provided timeout expires).
func (data *TestData) podWaitForRunning(timeout time.Duration, name, namespace string) error {
	_, err := data.podWaitFor(timeout, name, namespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	return err
}

// podWaitForIPs polls the K8s apiserver until the specified Pod is in the "running" state (or until
// the provided timeout expires). The function then returns the IP addresses assigned to the Pod. If the
// Pod is not using "hostNetwork", the function also checks that an IP address exists in each required
// Address Family in the cluster.
func (data *TestData) podWaitForIPs(timeout time.Duration, name, namespace string) (*PodIPs, error) {
	pod, err := data.podWaitFor(timeout, name, namespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		return nil, err
	}
	// According to the K8s API documentation (https://godoc.org/k8s.io/api/core/v1#PodStatus),
	// the PodIP field should only be empty if the Pod has not yet been scheduled, and "running"
	// implies scheduled.
	if pod.Status.PodIP == "" {
		return nil, fmt.Errorf("Pod is running but has no assigned IP, which should never happen")
	}
	podIPStrings := sets.NewString(pod.Status.PodIP)
	for _, podIP := range pod.Status.PodIPs {
		ipStr := strings.TrimSpace(podIP.IP)
		if ipStr != "" {
			podIPStrings.Insert(ipStr)
		}
	}
	ips, err := parsePodIPs(podIPStrings)
	if err != nil {
		return nil, err
	}

	if !pod.Spec.HostNetwork {
		if clusterInfo.podV4NetworkCIDR != "" && ips.ipv4 == nil {
			return nil, fmt.Errorf("no IPv4 address is assigned while cluster was configured with IPv4 Pod CIDR %s", clusterInfo.podV4NetworkCIDR)
		}
		if clusterInfo.podV6NetworkCIDR != "" && ips.ipv6 == nil {
			return nil, fmt.Errorf("no IPv6 address is assigned while cluster was configured with IPv6 Pod CIDR %s", clusterInfo.podV6NetworkCIDR)
		}
	}
	return ips, nil
}

func parsePodIPs(podIPStrings sets.String) (*PodIPs, error) {
	ips := new(PodIPs)
	for idx := range podIPStrings.List() {
		ipStr := podIPStrings.List()[idx]
		ip := net.ParseIP(ipStr)
		if ip.To4() != nil {
			if ips.ipv4 != nil && ipStr != ips.ipv4.String() {
				return nil, fmt.Errorf("Pod is assigned multiple IPv4 addresses: %s and %s", ips.ipv4.String(), ipStr)
			}
			if ips.ipv4 == nil {
				ips.ipv4 = &ip
				ips.ipStrings = append(ips.ipStrings, ipStr)
			}
		} else {
			if ips.ipv6 != nil && ipStr != ips.ipv6.String() {
				return nil, fmt.Errorf("Pod is assigned multiple IPv6 addresses: %s and %s", ips.ipv6.String(), ipStr)
			}
			if ips.ipv6 == nil {
				ips.ipv6 = &ip
				ips.ipStrings = append(ips.ipStrings, ipStr)
			}
		}
	}
	if len(ips.ipStrings) == 0 {
		return nil, fmt.Errorf("pod is running but has no assigned IP, which should never happen")
	}
	return ips, nil
}

// deleteAntreaAgentOnNode deletes the antrea-agent Pod on a specific Node and measure how long it
// takes for the Pod not to be visible to the client any more. It also waits for a new antrea-agent
// Pod to be running on the Node.
func (data *TestData) deleteAntreaAgentOnNode(nodeName string, gracePeriodSeconds int64, timeout time.Duration) (time.Duration, error) {
	if testOptions.enableCoverage {
		data.gracefulExitAntreaAgent(testOptions.coverageDir, nodeName)
	}
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-agent",
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	}
	// we do not use DeleteCollection directly because we want to ensure the resources no longer
	// exist by the time we return
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
	if err != nil {
		return 0, fmt.Errorf("failed to list antrea-agent Pods on Node '%s': %v", nodeName, err)
	}
	// in the normal case, there should be a single Pod in the list
	if len(pods.Items) == 0 {
		return 0, fmt.Errorf("no available antrea-agent Pods on Node '%s'", nodeName)
	}
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}

	start := time.Now()
	if err := data.clientset.CoreV1().Pods(antreaNamespace).DeleteCollection(context.TODO(), deleteOptions, listOptions); err != nil {
		return 0, fmt.Errorf("error when deleting antrea-agent Pods on Node '%s': %v", nodeName, err)
	}

	if err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		for _, pod := range pods.Items {
			if _, err := data.clientset.CoreV1().Pods(antreaNamespace).Get(context.TODO(), pod.Name, metav1.GetOptions{}); err != nil {
				if errors.IsNotFound(err) {
					continue
				}
				return false, fmt.Errorf("error when getting Pod: %v", err)
			}
			// Keep trying, at least one Pod left
			return false, nil
		}
		return true, nil
	}); err != nil {
		return 0, err
	}

	delay := time.Since(start)

	// wait for new antrea-agent Pod
	if err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
		if err != nil {
			return false, fmt.Errorf("failed to list antrea-agent Pods on Node '%s': %v", nodeName, err)
		}
		if len(pods.Items) == 0 {
			// keep trying
			return false, nil
		}
		for _, pod := range pods.Items {
			if pod.Status.Phase != corev1.PodRunning {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		return 0, err
	}

	return delay, nil
}

// getAntreaPodOnNode retrieves the name of the Antrea Pod (antrea-agent-*) running on a specific Node.
func (data *TestData) getAntreaPodOnNode(nodeName string) (podName string, err error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-agent",
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	}
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
	if err != nil {
		return "", fmt.Errorf("failed to list Antrea Pods: %v", err)
	}
	if len(pods.Items) != 1 {
		return "", fmt.Errorf("expected *exactly* one Pod")
	}
	return pods.Items[0].Name, nil
}

// getAntreaController retrieves the name of the Antrea Controller (antrea-controller-*) running in the k8s cluster.
func (data *TestData) getAntreaController() (*corev1.Pod, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-controller",
	}
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list Antrea Controller: %v", err)
	}
	if len(pods.Items) != 1 {
		return nil, fmt.Errorf("expected *exactly* one Pod")
	}
	return &pods.Items[0], nil
}

// restartAntreaControllerPod deletes the antrea-controller Pod to force it to be re-scheduled. It then waits
// for the new Pod to become available, and returns it.
func (data *TestData) restartAntreaControllerPod(timeout time.Duration) (*corev1.Pod, error) {
	if testOptions.enableCoverage {
		data.gracefulExitAntreaController(testOptions.coverageDir)
	}
	var gracePeriodSeconds int64 = 1
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-controller",
	}
	if err := data.clientset.CoreV1().Pods(antreaNamespace).DeleteCollection(context.TODO(), deleteOptions, listOptions); err != nil {
		return nil, fmt.Errorf("error when deleting antrea-controller Pod: %v", err)
	}

	var newPod *corev1.Pod
	// wait for new antrea-controller Pod
	if err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
		if err != nil {
			return false, fmt.Errorf("failed to list antrea-controller Pods: %v", err)
		}
		// Even though the strategy is "Recreate", the old Pod might still be in terminating state when the new Pod is
		// running as this is deleting a Pod manually, not upgrade.
		// See https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#recreate-deployment.
		// So we should ensure there's only 1 Pod and it's running.
		if len(pods.Items) != 1 || pods.Items[0].DeletionTimestamp != nil {
			return false, nil
		}
		pod := pods.Items[0]
		ready := false
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady {
				ready = condition.Status == corev1.ConditionTrue
				break
			}
		}
		if !ready {
			return false, nil
		}
		newPod = &pod
		return true, nil
	}); err != nil {
		return nil, err
	}
	return newPod, nil
}

// restartAntreaAgentPods deletes all the antrea-agent Pods to force them to be re-scheduled. It
// then waits for the new Pods to become available.
func (data *TestData) restartAntreaAgentPods(timeout time.Duration) error {
	if testOptions.enableCoverage {
		data.gracefulExitAntreaAgent(testOptions.coverageDir, "all")
	}
	var gracePeriodSeconds int64 = 1
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-agent",
	}
	if err := data.clientset.CoreV1().Pods(antreaNamespace).DeleteCollection(context.TODO(), deleteOptions, listOptions); err != nil {
		return fmt.Errorf("error when deleting antrea-agent Pods: %v", err)
	}

	return data.waitForAntreaDaemonSetPods(timeout)
}

// validatePodIP checks that the provided IP address is in the Pod Network CIDR for the cluster.
func validatePodIP(podNetworkCIDR string, ip net.IP) (bool, error) {
	_, cidr, err := net.ParseCIDR(podNetworkCIDR)
	if err != nil {
		return false, fmt.Errorf("podNetworkCIDR '%s' is not a valid CIDR", podNetworkCIDR)
	}
	return cidr.Contains(ip), nil
}

// createService creates a service with port and targetPort.
func (data *TestData) createService(serviceName string, port, targetPort int, selector map[string]string, affinity bool,
	serviceType corev1.ServiceType, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	affinityType := corev1.ServiceAffinityNone
	if affinity {
		affinityType = corev1.ServiceAffinityClientIP
	}
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: testNamespace,
			Labels: map[string]string{
				"antrea-e2e": serviceName,
				"app":        serviceName,
			},
		},
		Spec: corev1.ServiceSpec{
			SessionAffinity: affinityType,
			Ports: []corev1.ServicePort{{
				Port:       int32(port),
				TargetPort: intstr.FromInt(targetPort),
			}},
			Type:     serviceType,
			Selector: selector,
			IPFamily: ipFamily,
		},
	}
	return data.clientset.CoreV1().Services(testNamespace).Create(context.TODO(), &service, metav1.CreateOptions{})
}

// createNginxClusterIPService create a nginx service with the given name.
func (data *TestData) createNginxClusterIPService(affinity bool, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	return data.createService("nginx", 80, 80, map[string]string{"app": "nginx"}, affinity, corev1.ServiceTypeClusterIP, ipFamily)
}

func (data *TestData) createNginxLoadBalancerService(affinity bool, ingressIPs []string, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	svc, err := data.createService(nginxLBService, 80, 80, map[string]string{"app": "nginx"}, affinity, corev1.ServiceTypeLoadBalancer, ipFamily)
	if err != nil {
		return svc, err
	}
	ingress := make([]corev1.LoadBalancerIngress, len(ingressIPs))
	for idx, ingressIP := range ingressIPs {
		ingress[idx].IP = ingressIP
	}
	updatedSvc := svc.DeepCopy()
	updatedSvc.Status.LoadBalancer.Ingress = ingress
	patchData, err := json.Marshal(updatedSvc)
	if err != nil {
		return svc, err
	}
	return data.clientset.CoreV1().Services(svc.Namespace).Patch(context.TODO(), svc.Name, types.MergePatchType, patchData, metav1.PatchOptions{}, "status")
}

// deleteService deletes the service.
func (data *TestData) deleteService(name string) error {
	if err := data.clientset.CoreV1().Services(testNamespace).Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("unable to cleanup service %v: %v", name, err)
	}
	return nil
}

// Deletes a Service in the test namespace then waits us to timeout for the Service not to be visible to the
// client any more.
func (data *TestData) deleteServiceAndWait(timeout time.Duration, name string) error {
	if err := data.deleteService(name); err != nil {
		return err
	}

	if err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if _, err := data.clientset.CoreV1().Services(testNamespace).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, fmt.Errorf("error when getting Service: %v", err)
		}
		// Keep trying
		return false, nil
	}); err == wait.ErrWaitTimeout {
		return fmt.Errorf("Service '%s' still visible to client after %v", name, timeout)
	} else {
		return err
	}
}

// createNetworkPolicy creates a network policy with spec.
func (data *TestData) createNetworkPolicy(name string, spec *networkingv1.NetworkPolicySpec) (*networkingv1.NetworkPolicy, error) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-e2e": name,
			},
		},
		Spec: *spec,
	}
	return data.clientset.NetworkingV1().NetworkPolicies(testNamespace).Create(context.TODO(), policy, metav1.CreateOptions{})
}

// deleteNetworkpolicy deletes the network policy.
func (data *TestData) deleteNetworkpolicy(policy *networkingv1.NetworkPolicy) error {
	if err := data.clientset.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("unable to cleanup policy %v: %v", policy.Name, err)
	}
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

// Run the provided command in the specified Container for the give Pod and returns the contents of
// stdout and stderr as strings. An error either indicates that the command couldn't be run or that
// the command returned a non-zero error code.
func (data *TestData) runCommandFromPod(podNamespace string, podName string, containerName string, cmd []string) (stdout string, stderr string, err error) {
	request := data.clientset.CoreV1().RESTClient().Post().
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
	exec, err := remotecommand.NewSPDYExecutor(data.kubeConfig, "POST", request.URL())
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

func forAllNodes(fn func(nodeName string) error) error {
	for idx := 0; idx < clusterInfo.numNodes; idx++ {
		name := nodeName(idx)
		if name == "" {
			return fmt.Errorf("unexpected empty name for Node %d", idx)
		}
		if err := fn(name); err != nil {
			return err
		}
	}
	return nil
}

// forAllMatchingPodsInNamespace invokes the provided function for every Pod currently running on every Node in a given
// namespace and which matches labelSelector criteria.
func (data *TestData) forAllMatchingPodsInNamespace(
	labelSelector, nsName string, fn func(nodeName string, podName string, nsName string) error) error {
	for _, node := range clusterInfo.nodes {
		listOptions := metav1.ListOptions{
			LabelSelector: labelSelector,
			FieldSelector: fmt.Sprintf("spec.nodeName=%s", node.name),
		}
		pods, err := data.clientset.CoreV1().Pods(nsName).List(context.TODO(), listOptions)
		if err != nil {
			return fmt.Errorf("failed to list Antrea Pods on Node '%s': %v", node.name, err)
		}
		for _, pod := range pods.Items {
			if err := fn(node.name, pod.Name, nsName); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseArpingStdout(out string) (sent uint32, received uint32, loss float32, err error) {
	re := regexp.MustCompile(`Sent\s+(\d+)\s+probe.*\nReceived\s+(\d+)\s+response`)
	matches := re.FindStringSubmatch(out)
	if len(matches) == 0 {
		return 0, 0, 0.0, fmt.Errorf("Unexpected arping output")
	}
	if v, err := strconv.ParseUint(matches[1], 10, 32); err != nil {
		return 0, 0, 0.0, fmt.Errorf("Error when retrieving 'sent probes' from arpping output: %v", err)
	} else {
		sent = uint32(v)
	}
	if v, err := strconv.ParseUint(matches[2], 10, 32); err != nil {
		return 0, 0, 0.0, fmt.Errorf("Error when retrieving 'received responses' from arpping output: %v", err)
	} else {
		received = uint32(v)
	}
	loss = 100. * float32(sent-received) / float32(sent)
	return sent, received, loss, nil
}

func (data *TestData) runPingCommandFromTestPod(podName string, targetPodIPs *PodIPs, count int) error {
	var cmd []string
	if targetPodIPs.ipv4 != nil {
		cmd = []string{"ping", "-c", strconv.Itoa(count), targetPodIPs.ipv4.String()}
		if _, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, cmd); err != nil {
			return err
		}
	}
	if targetPodIPs.ipv6 != nil {
		cmd = []string{"ping", "-6", "-c", strconv.Itoa(count), targetPodIPs.ipv6.String()}
		if _, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, cmd); err != nil {
			return err
		}
	}
	return nil
}

func (data *TestData) runNetcatCommandFromTestPod(podName string, server string, port int) error {
	// Retrying several times to avoid flakes as the test may involve DNS (coredns) and Service/Endpoints (kube-proxy).
	cmd := []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf("for i in $(seq 1 5); do nc -vz -w 4 %s %d && exit 0 || sleep 1; done; exit 1",
			server, port),
	}
	stdout, stderr, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, cmd)
	if err == nil {
		return nil
	}
	return fmt.Errorf("nc stdout: <%v>, stderr: <%v>, err: <%v>", stdout, stderr, err)
}

func (data *TestData) doesOVSPortExist(antreaPodName string, portName string) (bool, error) {
	cmd := []string{"ovs-vsctl", "port-to-br", portName}
	_, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
	if err == nil {
		return true, nil
	} else if strings.Contains(stderr, "no port named") {
		return false, nil
	}
	return false, fmt.Errorf("error when running ovs-vsctl command on Pod '%s': %v", antreaPodName, err)
}

func (data *TestData) GetEncapMode() (config.TrafficEncapModeType, error) {
	mapList, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return config.TrafficEncapModeInvalid, err
	}
	for _, m := range mapList.Items {
		if strings.HasPrefix(m.Name, "antrea-config") {
			configMap, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).Get(context.TODO(), m.Name, metav1.GetOptions{})
			if err != nil {
				return config.TrafficEncapModeInvalid, err
			}
			for _, antreaConfig := range configMap.Data {
				for _, mode := range config.GetTrafficEncapModes() {
					searchStr := fmt.Sprintf("trafficEncapMode: %s", mode)
					if strings.Index(strings.ToLower(antreaConfig), strings.ToLower(searchStr)) != -1 {
						return mode, nil
					}
				}
			}
			return config.TrafficEncapModeEncap, nil
		}
	}
	return config.TrafficEncapModeInvalid, fmt.Errorf("antrea-conf config map is not found")
}

func (data *TestData) getFeatures(confName string, antreaNamespace string) (featuregate.FeatureGate, error) {
	featureGate := features.DefaultMutableFeatureGate.DeepCopy()
	cfgMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		return nil, err
	}
	var cfg interface{}
	if err := yaml.Unmarshal([]byte(cfgMap.Data[confName]), &cfg); err != nil {
		return nil, err
	}
	rawFeatureGateMap, ok := cfg.(map[interface{}]interface{})["featureGates"]
	if !ok || rawFeatureGateMap == nil {
		return featureGate, nil
	}
	featureGateMap := make(map[string]bool)
	for k, v := range rawFeatureGateMap.(map[interface{}]interface{}) {
		featureGateMap[k.(string)] = v.(bool)
	}
	if err := featureGate.SetFromMap(featureGateMap); err != nil {
		return nil, err
	}
	return featureGate, nil
}

func (data *TestData) GetAgentFeatures(antreaNamespace string) (featuregate.FeatureGate, error) {
	return data.getFeatures(antreaAgentConfName, antreaNamespace)
}

func (data *TestData) GetControllerFeatures(antreaNamespace string) (featuregate.FeatureGate, error) {
	return data.getFeatures(antreaControllerConfName, antreaNamespace)
}

func (data *TestData) GetAntreaConfigMap(antreaNamespace string) (*corev1.ConfigMap, error) {
	deployment, err := data.clientset.AppsV1().Deployments(antreaNamespace).Get(context.TODO(), antreaDeployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Antrea Controller deployment: %v", err)
	}
	var configMapName string
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil && volume.Name == antreaConfigVolume {
			configMapName = volume.ConfigMap.Name
			break
		}
	}
	if len(configMapName) == 0 {
		return nil, fmt.Errorf("failed to locate %s ConfigMap volume", antreaConfigVolume)
	}
	configMap, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s: %v", configMapName, err)
	}
	return configMap, nil
}

func (data *TestData) GetGatewayInterfaceName(antreaNamespace string) (string, error) {
	configMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		return "", err
	}
	agentConfData := configMap.Data["antrea-agent.conf"]
	for _, line := range strings.Split(agentConfData, "\n") {
		if strings.HasPrefix(line, "hostGateway") {
			return strings.Fields(line)[1], nil
		}
	}
	return antreaDefaultGW, nil
}

func (data *TestData) mutateAntreaConfigMap(mutatingFunc func(data map[string]string), restartController, restartAgent bool) error {
	configMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		return err
	}
	mutatingFunc(configMap.Data)
	if _, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update ConfigMap %s: %v", configMap.Name, err)
	}
	if restartAgent {
		err = data.restartAntreaAgentPods(defaultTimeout)
		if err != nil {
			return fmt.Errorf("error when restarting antrea-agent Pod: %v", err)
		}
	}
	// controller should be restarted after agents in case of dataplane disruption caused by agent restart on Kind cluster.
	if restartController {
		_, err = data.restartAntreaControllerPod(defaultTimeout)
		if err != nil {
			return fmt.Errorf("error when restarting antrea-controller Pod: %v", err)
		}
	}
	return nil
}

// gracefulExitAntreaController copies the Antrea controller binary coverage data file out before terminating the Pod
func (data *TestData) gracefulExitAntreaController(covDir string) error {
	antreaController, err := data.getAntreaController()
	if err != nil {
		return fmt.Errorf("error when getting antrea-controller Pod: %v", err)
	}
	podName := antreaController.Name

	err = data.collectAntctlCovFiles(podName, "antrea-controller", antreaNamespace, covDir)

	if err != nil {
		return fmt.Errorf("error when graceful exit Antrea controller - copy antctl coverage files out: %v", err)
	}

	cmds := []string{"pgrep", "-f", antreaControllerCovBinary, "-P", "1"}
	stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, "antrea-controller", cmds)
	if err != nil {
		return fmt.Errorf("error when getting pid of '%s', stderr: <%v>, err: <%v>", antreaControllerCovBinary, stderr, err)
	}
	cmds = []string{"kill", "-SIGINT", strings.TrimSpace(stdout)}

	_, stderr, err = data.runCommandFromPod(antreaNamespace, podName, "antrea-controller", cmds)
	if err != nil {
		return fmt.Errorf("error when sending SIGINT signal to '%s', stderr: <%v>, err: <%v>", antreaControllerCovBinary, stderr, err)
	}
	err = data.copyPodFiles(podName, "antrea-controller", antreaNamespace, antreaControllerCovFile, covDir)

	if err != nil {
		return fmt.Errorf("error when graceful exit Antrea controller - copy antrea-controller coverage files out: %v", err)
	}

	return nil
}

// gracefulExitAntreaAgent copies the Antrea agent binary coverage data file out before terminating the Pod
func (data *TestData) gracefulExitAntreaAgent(covDir string, nodeName string) error {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-agent",
	}
	if nodeName != "all" {
		listOptions.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
	}

	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), listOptions)
	if err != nil {
		return fmt.Errorf("failed to list antrea-agent pods: %v", err)
	}
	for _, pod := range pods.Items {
		podName := pod.Name
		err := data.collectAntctlCovFiles(podName, "antrea-agent", antreaNamespace, covDir)

		if err != nil {
			return fmt.Errorf("error when graceful exit Antrea agent - copy antctl coverage files out: %v", err)
		}

		cmds := []string{"pgrep", "-f", antreaAgentCovBinary, "-P", "1"}
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, podName, "antrea-agent", cmds)
		if err != nil {
			return fmt.Errorf("error when getting pid of '%s', stderr: <%v>, err: <%v>", antreaAgentCovBinary, stderr, err)
		}
		cmds = []string{"kill", "-SIGINT", strings.TrimSpace(stdout)}
		_, stderr, err = data.runCommandFromPod(antreaNamespace, podName, "antrea-agent", cmds)
		if err != nil {
			return fmt.Errorf("error when sending SIGINT signal to '%s', stderr: <%v>, err: <%v>", antreaAgentCovBinary, stderr, err)
		}
		err = data.copyPodFiles(podName, "antrea-agent", antreaNamespace, antreaAgentCovFile, covDir)

		if err != nil {
			return fmt.Errorf("error when graceful exit Antrea agent - copy antrea-agent coverage files out: %v", err)
		}
	}
	return nil
}

// collectAntctlCovFiles collects coverage files for the antctl binary from the Pod and saves them to the coverage directory
func (data *TestData) collectAntctlCovFiles(podName string, containerName string, nsName string, covDir string) error {
	// copy antctl coverage files from Pod to the coverage directory
	cmds := []string{"bash", "-c", "find . -maxdepth 1 -name 'antctl*.out' -exec basename {} ';'"}
	stdout, stderr, err := data.runCommandFromPod(nsName, podName, containerName, cmds)
	if err != nil {
		return fmt.Errorf("error when running this find command '%s' on Pod '%s', stderr: <%v>, err: <%v>", cmds, podName, stderr, err)
	}
	stdout = strings.TrimSpace(stdout)
	files := strings.Split(stdout, "\n")
	for _, file := range files {
		if len(file) == 0 {
			continue
		}
		err := data.copyPodFiles(podName, containerName, nsName, file, covDir)
		if err != nil {
			return fmt.Errorf("error when copying coverage files for antctl from Pod '%s' to coverage directory '%s': %v", podName, covDir, err)
		}
	}
	return nil
}

// collectAntctlCovFilesFromControlPlaneNode collects coverage files for the antctl binary from the control-plane Node and saves them to the coverage directory
func (data *TestData) collectAntctlCovFilesFromControlPlaneNode(covDir string) error {
	// copy antctl coverage files from node to the coverage directory
	var cmd string
	if testOptions.providerName == "kind" {
		cmd = "/bin/sh -c find . -maxdepth 1 -name 'antctl*.out' -exec basename {} ';'"
	} else {
		cmd = "find . -maxdepth 1 -name 'antctl*.out' -exec basename {} ';'"
	}
	rc, stdout, stderr, err := RunCommandOnNode(controlPlaneNodeName(), cmd)
	if err != nil || rc != 0 {
		return fmt.Errorf("error when running this find command '%s' on control-plane Node '%s', stderr: <%v>, err: <%v>", cmd, controlPlaneNodeName(), stderr, err)

	}
	stdout = strings.TrimSpace(stdout)
	files := strings.Split(stdout, "\n")
	for _, file := range files {
		if len(file) == 0 {
			continue
		}
		err := data.copyNodeFiles(controlPlaneNodeName(), file, covDir)
		if err != nil {
			return fmt.Errorf("error when copying coverage files for antctl from Node '%s' to coverage directory '%s': %v", controlPlaneNodeName(), covDir, err)
		}
	}
	return nil

}

// copyPodFiles copies file from a Pod and save it to specified directory
func (data *TestData) copyPodFiles(podName string, containerName string, nsName string, fileName string, covDir string) error {
	// getPodWriter creates the file with name podName-fileName-suffix. It returns nil if the
	// file cannot be created. File must be closed by the caller.
	getPodWriter := func(podName, fileName, suffix string) *os.File {
		covFile := filepath.Join(covDir, fmt.Sprintf("%s-%s-%s", podName, fileName, suffix))
		f, err := os.Create(covFile)
		if err != nil {
			_ = fmt.Errorf("error when creating coverage file '%s': %v", covFile, err)
			return nil
		}
		return f
	}

	// dump the file from Antrea Pods to disk.
	// a filepath-friendly timestamp format.
	const timeFormat = "Jan02-15-04-05"
	timeStamp := time.Now().Format(timeFormat)
	w := getPodWriter(podName, fileName, timeStamp)
	if w == nil {
		return nil
	}
	defer w.Close()
	cmd := []string{"cat", fileName}
	stdout, stderr, err := data.runCommandFromPod(nsName, podName, containerName, cmd)
	if err != nil {
		return fmt.Errorf("cannot retrieve content of file '%s' from Pod '%s', stderr: <%v>, err: <%v>", fileName, podName, stderr, err)
	}
	if stdout == "" {
		return nil
	}
	w.WriteString(stdout)
	return nil
}

// copyNodeFiles copies a file from a Node and save it to specified directory
func (data *TestData) copyNodeFiles(nodeName string, fileName string, covDir string) error {
	// getNodeWriter creates the file with name nodeName-suffix. It returns nil if the file
	// cannot be created. File must be closed by the caller.
	getNodeWriter := func(nodeName, fileName, suffix string) *os.File {
		covFile := filepath.Join(covDir, fmt.Sprintf("%s-%s-%s", nodeName, fileName, suffix))
		f, err := os.Create(covFile)
		if err != nil {
			_ = fmt.Errorf("error when creating coverage file '%s': %v", covFile, err)
			return nil
		}
		return f
	}

	// dump the file from Antrea Pods to disk.
	// a filepath-friendly timestamp format.
	const timeFormat = "Jan02-15-04-05"
	timeStamp := time.Now().Format(timeFormat)
	w := getNodeWriter(nodeName, fileName, timeStamp)
	if w == nil {
		return nil
	}
	defer w.Close()
	cmd := fmt.Sprintf("cat %s", fileName)
	rc, stdout, stderr, err := RunCommandOnNode(controlPlaneNodeName(), cmd)
	if err != nil || rc != 0 {
		return fmt.Errorf("cannot retrieve content of file '%s' from Node '%s', stderr: <%v>, err: <%v>", fileName, controlPlaneNodeName(), stderr, err)
	}
	if stdout == "" {
		return nil
	}
	w.WriteString(stdout)
	return nil
}
