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
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
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
	"k8s.io/client-go/util/retry"
	"k8s.io/component-base/featuregate"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	"k8s.io/kubectl/pkg/util/podutils"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/pointer"

	"antrea.io/antrea/pkg/agent/config"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/test/e2e/providers"
)

var AntreaConfigMap *corev1.ConfigMap

var (
	connectionLostError = fmt.Errorf("http2: client connection lost")
)

const (
	defaultTimeout  = 90 * time.Second
	defaultInterval = 1 * time.Second

	// antreaNamespace is the K8s Namespace in which all Antrea resources are running.
	antreaNamespace             = "kube-system"
	kubeNamespace               = "kube-system"
	flowAggregatorNamespace     = "flow-aggregator"
	antreaConfigVolume          = "antrea-config"
	antreaWindowsConfigVolume   = "antrea-windows-config"
	flowAggregatorConfigVolume  = "flow-aggregator-config"
	antreaDaemonSet             = "antrea-agent"
	antreaWindowsDaemonSet      = "antrea-agent-windows"
	antreaDeployment            = "antrea-controller"
	flowAggregatorDeployment    = "flow-aggregator"
	flowAggregatorCHSecret      = "clickhouse-ca"
	antreaDefaultGW             = "antrea-gw0"
	testAntreaIPAMNamespace     = "antrea-ipam-test"
	testAntreaIPAMNamespace11   = "antrea-ipam-test-11"
	testAntreaIPAMNamespace12   = "antrea-ipam-test-12"
	busyboxContainerName        = "busybox"
	mcjoinContainerName         = "mcjoin"
	agnhostContainerName        = "agnhost"
	toolboxContainerName        = "toolbox"
	nginxContainerName          = "nginx"
	controllerContainerName     = "antrea-controller"
	ovsContainerName            = "antrea-ovs"
	agentContainerName          = "antrea-agent"
	flowAggregatorContainerName = "flow-aggregator"

	antreaYML               = "antrea.yml"
	antreaIPSecYML          = "antrea-ipsec.yml"
	antreaCovYML            = "antrea-coverage.yml"
	antreaIPSecCovYML       = "antrea-ipsec-coverage.yml"
	flowAggregatorYML       = "flow-aggregator.yml"
	flowAggregatorCovYML    = "flow-aggregator-coverage.yml"
	flowVisibilityYML       = "flow-visibility.yml"
	flowVisibilityTLSYML    = "flow-visibility-tls.yml"
	chOperatorYML           = "clickhouse-operator-install-bundle.yml"
	flowVisibilityCHPodName = "chi-clickhouse-clickhouse-0-0-0"
	flowVisibilityNamespace = "flow-visibility"
	defaultBridgeName       = "br-int"
	monitoringNamespace     = "monitoring"

	antreaControllerCovBinary = "antrea-controller-coverage"
	antreaAgentCovBinary      = "antrea-agent-coverage"
	flowAggregatorCovBinary   = "flow-aggregator-coverage"
	antreaControllerCovFile   = "antrea-controller.cov.out"
	antreaAgentCovFile        = "antrea-agent.cov.out"
	flowAggregatorCovFile     = "flow-aggregator.cov.out"
	cpNodeCoverageDir         = "/tmp/antrea-e2e-coverage"

	antreaAgentConfName      = "antrea-agent.conf"
	antreaControllerConfName = "antrea-controller.conf"
	flowAggregatorConfName   = "flow-aggregator.conf"

	agnhostImage        = "registry.k8s.io/e2e-test-images/agnhost:2.29"
	busyboxImage        = "projects.registry.vmware.com/antrea/busybox"
	ToolboxImage        = "projects.registry.vmware.com/antrea/toolbox:1.3-0"
	mcjoinImage         = "projects.registry.vmware.com/antrea/mcjoin:v2.9"
	nginxImage          = "projects.registry.vmware.com/antrea/nginx:1.21.6-alpine"
	iisImage            = "mcr.microsoft.com/windows/servercore/iis"
	ipfixCollectorImage = "projects.registry.vmware.com/antrea/ipfix-collector:v0.8.2"

	nginxLBService = "nginx-loadbalancer"

	ipfixCollectorPort                  = "4739"
	exporterFlowPollInterval            = 1 * time.Second
	exporterActiveFlowExportTimeout     = 2 * time.Second
	exporterIdleFlowExportTimeout       = 1 * time.Second
	aggregatorActiveFlowRecordTimeout   = 3500 * time.Millisecond
	aggregatorInactiveFlowRecordTimeout = 6 * time.Second
	aggregatorClickHouseCommitInterval  = 1 * time.Second
	clickHouseHTTPPort                  = "8123"
	defaultCHDatabaseURL                = "tcp://clickhouse-clickhouse.flow-visibility.svc:9000"

	statefulSetRestartAnnotationKey = "antrea-e2e/restartedAt"

	iperfPort    = 5201
	iperfSvcPort = 9999
)

type ClusterNode struct {
	idx              int // 0 for control-plane Node
	name             string
	ipv4Addr         string
	ipv6Addr         string
	podV4NetworkCIDR string
	podV6NetworkCIDR string
	gwV4Addr         string
	gwV6Addr         string
	os               string
}

func (n ClusterNode) ip() string {
	if n.ipv4Addr != "" {
		return n.ipv4Addr
	}
	return n.ipv6Addr
}

type ClusterInfo struct {
	numNodes             int
	podV4NetworkCIDR     string
	podV6NetworkCIDR     string
	svcV4NetworkCIDR     string
	svcV6NetworkCIDR     string
	controlPlaneNodeName string
	controlPlaneNodeIPv4 string
	controlPlaneNodeIPv6 string
	nodes                map[int]*ClusterNode
	nodesOS              map[string]string
	windowsNodes         []int
	k8sServerVersion     string
	k8sServiceHost       string
	k8sServicePort       int32
}

type ExternalInfo struct {
	externalServerIPv4 string
	externalServerIPv6 string

	vlanSubnetIPv4  string
	vlanGatewayIPv4 string
	vlanSubnetIPv6  string
	vlanGatewayIPv6 string
	vlanID          int
}

var clusterInfo ClusterInfo
var externalInfo ExternalInfo

type TestOptions struct {
	providerName        string
	providerConfigPath  string
	logsExportDir       string
	logsExportOnSuccess bool
	withBench           bool
	enableCoverage      bool
	enableAntreaIPAM    bool
	flowVisibility      bool
	coverageDir         string
	skipCases           string
	linuxVMs            string
	windowsVMs          string
	// deployAntrea determines whether to deploy Antrea before running tests. It requires antrea.yml to be present in
	// the home directory of the control-plane Node. Note it doesn't affect the tests that redeploy Antrea themselves.
	deployAntrea bool

	externalServerIPs string
	vlanSubnets       string
	vlanID            int
}

type flowVisibilityTestOptions struct {
	databaseURL      string
	secureConnection bool
}

var testOptions TestOptions

// PodInfo combines OS info with a Pod name. It is useful when choosing commands and options on Pods of different OS (Windows, Linux).
type PodInfo struct {
	Name      string
	OS        string
	NodeName  string
	Namespace string
}

// TestData stores the state required for each test case.
type TestData struct {
	ClusterName        string
	provider           providers.ProviderInterface
	kubeConfig         *restclient.Config
	clientset          kubernetes.Interface
	aggregatorClient   aggregatorclientset.Interface
	crdClient          crdclientset.Interface
	logsDirForTestCase string
	testNamespace      string
}

var testData *TestData

type PodIPs struct {
	IPv4      *net.IP
	IPv6      *net.IP
	IPStrings []string
}

type deployAntreaOptions int

const (
	deployAntreaDefault deployAntreaOptions = iota
	deployAntreaIPsec
	deployAntreaCoverageOffset
)

func (o deployAntreaOptions) WithCoverage() deployAntreaOptions {
	return o + deployAntreaCoverageOffset
}

func (o deployAntreaOptions) DeployYML() string {
	return deployAntreaOptionsYML[o]
}

func (o deployAntreaOptions) String() string {
	return deployAntreaOptionsString[o]
}

var (
	deployAntreaOptionsString = [...]string{
		"AntreaDefault",
		"AntreaWithIPSec",
	}
	deployAntreaOptionsYML = [...]string{
		antreaYML,
		antreaIPSecYML,
		antreaCovYML,
		antreaIPSecCovYML,
	}
)

func (p PodIPs) String() string {
	res := ""
	if p.IPv4 != nil {
		res += fmt.Sprintf("IPv4(%s),", p.IPv4.String())
	}
	if p.IPv6 != nil {
		res += fmt.Sprintf("IPv6(%s),", p.IPv6.String())
	}
	return fmt.Sprintf("%sIPstrings(%s)", res, strings.Join(p.IPStrings, ","))
}

func (p *PodIPs) hasSameIP(p1 *PodIPs) bool {
	if len(p.IPStrings) == 0 && len(p1.IPStrings) == 0 {
		return true
	}
	if p.IPv4 != nil && p1.IPv4 != nil && p.IPv4.Equal(*(p1.IPv4)) {
		return true
	}
	if p.IPv6 != nil && p1.IPv6 != nil && p.IPv6.Equal(*(p1.IPv6)) {
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
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.name
}

func workerNodeIPv4(idx int) string {
	if idx == 0 { // control-plane Node
		return ""
	}
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.ipv4Addr
}

func workerNodeIPv6(idx int) string {
	if idx == 0 { // control-plane Node
		return ""
	}
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.ipv6Addr
}

// workerNodeIP returns an empty string if there is no worker Node with the provided idx
// (including if idx is 0, which is reserved for the control-plane Node)
func workerNodeIP(idx int) string {
	if idx == 0 { // control-plane Node
		return ""
	}
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.ip()
}

// nodeGatewayIPs returns the Antrea gateway's IPv4 address and IPv6 address for the provided Node
// (if applicable), in that order.
func nodeGatewayIPs(idx int) (string, string) {
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return "", ""
	}
	return node.gwV4Addr, node.gwV6Addr
}

func controlPlaneNodeName() string {
	return clusterInfo.controlPlaneNodeName
}

func controlPlaneNodeIPv4() string {
	return clusterInfo.controlPlaneNodeIPv4
}

func controlPlaneNodeIPv6() string {
	return clusterInfo.controlPlaneNodeIPv6
}

// nodeName returns an empty string if there is no Node with the provided idx. If idx is 0, the name
// of the control-plane Node will be returned.
func nodeName(idx int) string {
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.name
}

// nodeIPv4 returns an empty string if there is no Node with the provided idx. If idx is 0, the IPv4
// Address of the control-plane Node will be returned.
func nodeIPv4(idx int) string {
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.ipv4Addr
}

// nodeIPv6 returns an empty string if there is no Node with the provided idx. If idx is 0, the IPv6
// Address of the control-plane Node will be returned.
func nodeIPv6(idx int) string {
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.ipv6Addr
}

// nodeIP returns an empty string if there is no Node with the provided idx. If idx is 0, the IP
// of the control-plane Node will be returned.
func nodeIP(idx int) string {
	node, ok := clusterInfo.nodes[idx]
	if !ok {
		return ""
	}
	return node.ip()
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

func controlPlaneNoScheduleTolerations() []corev1.Toleration {
	// the Node taint still uses "master" in K8s v1.20
	return []corev1.Toleration{
		{
			Key:      "node-role.kubernetes.io/master",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
		{
			Key:      "node-role.kubernetes.io/control-plane",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		},
	}
}

func (data *TestData) InitProvider(providerName, providerConfigPath string) error {
	providerFactory := map[string]func(string) (providers.ProviderInterface, error){
		"vagrant": providers.NewVagrantProvider,
		"kind":    providers.NewKindProvider,
		"remote":  providers.NewRemoteProvider,
	}
	if fn, ok := providerFactory[providerName]; ok {
		newProvider, err := fn(providerConfigPath)
		if err != nil {
			return err
		}
		data.provider = newProvider
	} else {
		return fmt.Errorf("unknown provider '%s'", providerName)
	}
	return nil
}

// RunCommandOnNode is a convenience wrapper around the Provider interface RunCommandOnNode method.
func (data *TestData) RunCommandOnNode(nodeName string, cmd string) (code int, stdout string, stderr string, err error) {
	return data.provider.RunCommandOnNode(nodeName, cmd)
}

func (data *TestData) RunCommandOnNodeExt(nodeName, cmd string, envs map[string]string, stdin string, sudo bool) (
	code int, stdout, stderr string, err error) {
	return data.provider.RunCommandOnNodeExt(nodeName, cmd, envs, stdin, sudo)
}

func (data *TestData) collectExternalInfo() error {
	ips := strings.Split(testOptions.externalServerIPs, ",")
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return fmt.Errorf("invalid external server IP %s", ip)
		}
		if parsedIP.To4() != nil {
			externalInfo.externalServerIPv4 = ip
		} else {
			externalInfo.externalServerIPv6 = ip
		}
	}

	subnets := strings.Split(testOptions.vlanSubnets, ",")
	for _, subnet := range subnets {
		if subnet == "" {
			continue
		}
		gatewayIP, _, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("invalid vlan subnet %s: %w", subnet, err)
		}
		if gatewayIP.To4() != nil {
			externalInfo.vlanSubnetIPv4 = subnet
			externalInfo.vlanGatewayIPv4 = gatewayIP.String()
		} else {
			externalInfo.vlanSubnetIPv6 = subnet
			externalInfo.vlanGatewayIPv6 = gatewayIP.String()
		}
	}
	externalInfo.vlanID = testOptions.vlanID
	return nil
}

func (data *TestData) collectClusterInfo() error {
	// retrieve K8s server version
	// this needs to be done first, as there may be dependencies on the
	// version later in this function (e.g., for labelNodeRoleControlPlane()).
	serverVersion, err := testData.clientset.Discovery().ServerVersion()
	if err != nil {
		return err
	}
	clusterInfo.k8sServerVersion = serverVersion.String()

	// retrieve Node information
	nodes, err := testData.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error when listing cluster Nodes: %v", err)
	}
	workerIdx := 1
	clusterInfo.nodes = make(map[int]*ClusterNode)
	clusterInfo.nodesOS = make(map[string]string)
	for _, node := range nodes.Items {
		isControlPlaneNode := func() bool {
			_, ok := node.Labels[labelNodeRoleControlPlane()]
			return ok
		}()

		var nodeIPv4 string
		var nodeIPv6 string
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				if utilnet.IsIPv6String(address.Address) {
					nodeIPv6 = address.Address
				} else if utilnet.IsIPv4String(address.Address) {
					nodeIPv4 = address.Address
				}
			}
		}

		var nodeIdx int
		// If multiple control-plane Nodes (HA), we will select the last one in the list
		if isControlPlaneNode {
			nodeIdx = 0
			clusterInfo.controlPlaneNodeName = node.Name
			clusterInfo.controlPlaneNodeIPv4 = nodeIPv4
			clusterInfo.controlPlaneNodeIPv6 = nodeIPv6
		} else {
			nodeIdx = workerIdx
			workerIdx++
		}

		clusterInfo.nodes[nodeIdx] = &ClusterNode{
			idx:      nodeIdx,
			name:     node.Name,
			ipv4Addr: nodeIPv4,
			ipv6Addr: nodeIPv6,
			os:       node.Status.NodeInfo.OperatingSystem,
		}
		if node.Status.NodeInfo.OperatingSystem == "windows" {
			clusterInfo.windowsNodes = append(clusterInfo.windowsNodes, nodeIdx)
		}
		clusterInfo.nodesOS[node.Name] = node.Status.NodeInfo.OperatingSystem
	}
	if clusterInfo.controlPlaneNodeName == "" {
		return fmt.Errorf("error when listing cluster Nodes: control-plane Node not found")
	}
	clusterInfo.numNodes = workerIdx

	retrieveCIDRs := func(cmd string, reg string) ([]string, error) {
		res := make([]string, 2)
		rc, stdout, _, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
		if err != nil || rc != 0 {
			return res, fmt.Errorf("error when running the following command `%s` on control-plane Node: %v, %s", cmd, err, stdout)
		}
		re := regexp.MustCompile(reg)
		matches := re.FindStringSubmatch(stdout)
		if len(matches) == 0 {
			return res, fmt.Errorf("cannot retrieve CIDR, unexpected kubectl output: %s", stdout)
		}
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
		return res, nil
	}

	// Retrieve cluster CIDRs
	podCIDRs, err := retrieveCIDRs("kubectl cluster-info dump | grep cluster-cidr", `cluster-cidr=([^"]+)`)
	if err != nil {
		// Retrieve cluster CIDRs for Rancher clusters.
		podCIDRs, err = retrieveCIDRs("ps aux | grep kube-controller | grep cluster-cidr", `cluster-cidr=([^\s]+)`)
		if err != nil {
			return err
		}
	}
	clusterInfo.podV4NetworkCIDR = podCIDRs[0]
	clusterInfo.podV6NetworkCIDR = podCIDRs[1]

	// Retrieve service CIDRs
	svcCIDRs, err := retrieveCIDRs("kubectl cluster-info dump | grep service-cluster-ip-range", `service-cluster-ip-range=([^"]+)`)
	if err != nil {
		// Retrieve service CIDRs for Rancher clusters.
		svcCIDRs, err = retrieveCIDRs("ps aux | grep kube-controller | grep service-cluster-ip-range", `service-cluster-ip-range=([^\s]+)`)
		if err != nil {
			return err
		}
	}
	clusterInfo.svcV4NetworkCIDR = svcCIDRs[0]
	clusterInfo.svcV6NetworkCIDR = svcCIDRs[1]

	// Retrieve kubernetes Service host and Port
	svc, err := testData.clientset.CoreV1().Services("default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get Service kubernetes: %v", err)
	}
	clusterInfo.k8sServiceHost = svc.Spec.ClusterIP
	clusterInfo.k8sServicePort = svc.Spec.Ports[0].Port

	return nil
}

func getNodeByName(name string) *ClusterNode {
	for _, node := range clusterInfo.nodes {
		if node.name == name {
			return node
		}
	}
	return nil
}

func (data *TestData) collectPodCIDRs() error {
	nodes, err := testData.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error when listing cluster Nodes: %v", err)
	}
	for _, node := range nodes.Items {
		var podV4NetworkCIDR, podV6NetworkCIDR string
		var gwV4Addr, gwV6Addr string
		processPodCIDR := func(podCIDR string) error {
			_, cidr, err := net.ParseCIDR(podCIDR)
			if err != nil {
				return err
			}
			if cidr.IP.To4() != nil {
				podV4NetworkCIDR = podCIDR
				gwV4Addr = ip.NextIP(cidr.IP).String()
			} else {
				podV6NetworkCIDR = podCIDR
				gwV6Addr = ip.NextIP(cidr.IP).String()
			}
			return nil
		}
		if len(node.Spec.PodCIDRs) == 0 {
			if err := processPodCIDR(node.Spec.PodCIDR); err != nil {
				return fmt.Errorf("error when processing PodCIDR field for Node %s: %v", node.Name, err)
			}
		} else {
			for _, podCIDR := range node.Spec.PodCIDRs {
				if err := processPodCIDR(podCIDR); err != nil {
					return fmt.Errorf("error when processing PodCIDRs field for Node %s: %v", node.Name, err)
				}
			}
		}
		clusterNode := getNodeByName(node.Name)
		if clusterNode == nil {
			return fmt.Errorf("Node %s not found in ClusterInfo", node.Name)
		}
		clusterNode.podV4NetworkCIDR = podV4NetworkCIDR
		clusterNode.podV6NetworkCIDR = podV6NetworkCIDR
		clusterNode.gwV4Addr = gwV4Addr
		clusterNode.gwV6Addr = gwV6Addr
	}
	return nil
}

// CreateNamespace creates the provided namespace.
func (data *TestData) CreateNamespace(namespace string, mutateFunc func(*corev1.Namespace)) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	if mutateFunc != nil {
		mutateFunc(ns)
	}
	if ns, err := data.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{}); err != nil {
		// Ignore error if the Namespace already exists
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("error when creating '%s' Namespace: %v", namespace, err)
		}
		// When Namespace already exists, check phase
		if ns.Status.Phase == corev1.NamespaceTerminating {
			return fmt.Errorf("error when creating '%s' Namespace: namespace exists but is in 'Terminating' phase", namespace)
		}
	}
	return nil
}

func (data *TestData) UpdateNamespace(namespace string, mutateFunc func(*corev1.Namespace)) error {
	ns, _ := data.clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	if mutateFunc != nil {
		mutateFunc(ns)
	}
	if ns, err := data.clientset.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{}); err != nil {
		// Check Namespace phase
		if ns.Status.Phase == corev1.NamespaceTerminating {
			return fmt.Errorf("error when updating '%s' Namespace: namespace is in 'Terminating' phase", namespace)
		}
		return fmt.Errorf("error when updating '%s' Namespace: %v", namespace, err)
	}
	return nil
}

// createNamespaceWithAnnotations creates the Namespace with Annotations.
func (data *TestData) createNamespaceWithAnnotations(namespace string, annotations map[string]string) error {
	mutateFunc := data.generateNamespaceAnnotationsMutateFunc(annotations)
	return data.CreateNamespace(namespace, mutateFunc)
}

// updateNamespaceWithAnnotations updates the given Namespace with Annotations.
func (data *TestData) updateNamespaceWithAnnotations(namespace string, annotations map[string]string) error {
	mutateFunc := data.generateNamespaceAnnotationsMutateFunc(annotations)
	return data.UpdateNamespace(namespace, mutateFunc)
}

// generateAnnotationsMutateFunc generates a mutate function to add given Annotations to a Namespace.
func (data *TestData) generateNamespaceAnnotationsMutateFunc(annotations map[string]string) func(*corev1.Namespace) {
	var mutateFunc func(*corev1.Namespace)
	if annotations != nil {
		mutateFunc = func(namespace *corev1.Namespace) {
			if namespace.Annotations == nil {
				namespace.Annotations = map[string]string{}
			}
			for k := range annotations {
				namespace.Annotations[k] = annotations[k]
			}
		}
	}
	return mutateFunc
}

// DeleteNamespace deletes the provided Namespace, and waits for deletion to actually complete if timeout>=0
func (data *TestData) DeleteNamespace(namespace string, timeout time.Duration) error {
	var gracePeriodSeconds int64
	var propagationPolicy = metav1.DeletePropagationForeground
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
		PropagationPolicy:  &propagationPolicy,
	}

	// To log time statistics
	startTime := time.Now()
	defer func() {
		log.Infof("Deleting Namespace %s took %v", namespace, time.Since(startTime))
	}()

	if err := data.clientset.CoreV1().Namespaces().Delete(context.TODO(), namespace, deleteOptions); err != nil {
		if errors.IsNotFound(err) {
			// namespace does not exist, we return right away
			return nil
		}
		return fmt.Errorf("error when deleting '%s' Namespace: %v", namespace, err)
	}
	if timeout >= 0 {
		return wait.Poll(defaultInterval, timeout, func() (bool, error) {
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
	}
	return nil
}

// deployAntreaCommon deploys Antrea using kubectl on the control-plane Node.
func (data *TestData) deployAntreaCommon(yamlFile string, extraOptions string, waitForAgentRollout bool) error {
	// TODO: use the K8s apiserver when server side apply is available?
	// See https://kubernetes.io/docs/reference/using-api/api-concepts/#server-side-apply
	rc, _, _, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply %s -f %s", extraOptions, yamlFile))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying Antrea; is %s available on the control-plane Node?", yamlFile)
	}
	rc, stdout, stderr, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status deploy/%s --timeout=%v", antreaNamespace, antreaDeployment, defaultTimeout))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when waiting for antrea-controller rollout to complete - rc: %v - stdout: %v - stderr: %v - err: %v", rc, stdout, stderr, err)
	}
	if waitForAgentRollout {
		rc, stdout, stderr, err = data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status ds/%s --timeout=%v", antreaNamespace, antreaDaemonSet, defaultTimeout))
		if err != nil || rc != 0 {
			return fmt.Errorf("error when waiting for antrea-agent rollout to complete - rc: %v - stdout: %v - stderr: %v - err: %v", rc, stdout, stderr, err)
		}
	}

	return nil
}

// deployAntrea deploys Antrea with deploy options.
func (data *TestData) deployAntrea(option deployAntreaOptions) error {
	if testOptions.enableCoverage {
		option = option.WithCoverage()
	}
	return data.deployAntreaCommon(option.DeployYML(), "", true)
}

// deployFlowVisibilityClickHouse deploys ClickHouse operator and DB.
func (data *TestData) deployFlowVisibilityClickHouse(o flowVisibilityTestOptions) (string, error) {
	err := data.CreateNamespace(flowVisibilityNamespace, nil)
	if err != nil {
		return "", err
	}

	visibilityYML := flowVisibilityYML
	if o.secureConnection {
		visibilityYML = flowVisibilityTLSYML
	}

	rc, _, _, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s", chOperatorYML))
	if err != nil || rc != 0 {
		return "", fmt.Errorf("error when deploying the ClickHouse Operator YML; %s not available on the control-plane Node", chOperatorYML)
	}
	if err := wait.Poll(2*time.Second, 10*time.Second, func() (bool, error) {
		rc, stdout, stderr, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s", visibilityYML))
		if err != nil || rc != 0 {
			// ClickHouseInstallation CRD from ClickHouse Operator install bundle applied soon before
			// applying CR. Sometimes apiserver validation fails to recognize resource of
			// kind: ClickHouseInstallation. Retry in such scenario.
			if strings.Contains(stderr, "ClickHouseInstallation") || strings.Contains(stdout, "ClickHouseInstallation") {
				return false, nil
			}
			return false, fmt.Errorf("error when deploying the flow visibility YML %s: %s, %s, %v", visibilityYML, stdout, stderr, err)
		}
		return true, nil
	}); err != nil {
		return "", err
	}

	// check for clickhouse pod Ready. Wait for 2x timeout as ch operator needs to be running first to handle chi
	if err = data.podWaitForReady(2*defaultTimeout, flowVisibilityCHPodName, flowVisibilityNamespace); err != nil {
		return "", err
	}

	// check clickhouse service http port for service connectivity
	var chSvc *corev1.Service
	if err := wait.PollImmediate(defaultInterval, defaultTimeout, func() (bool, error) {
		chSvc, err = data.GetService(flowVisibilityNamespace, "clickhouse-clickhouse")
		if err != nil {
			return false, nil
		} else {
			return true, nil
		}
	}); err != nil {
		return "", fmt.Errorf("timeout waiting for ClickHouse Service: %v", err)
	}

	if err := wait.PollImmediate(defaultInterval, defaultTimeout, func() (bool, error) {
		rc, stdout, stderr, err := testData.RunCommandOnNode(controlPlaneNodeName(),
			fmt.Sprintf("curl -Ss %s:%s", chSvc.Spec.ClusterIP, clickHouseHTTPPort))
		if rc != 0 || err != nil {
			log.Infof("Failed to curl clickhouse Service: %s", strings.Trim(stderr, "\n"))
			return false, nil
		} else {
			log.Infof("Successfully curl'ed clickhouse Service: %s", strings.Trim(stdout, "\n"))
			return true, nil
		}
	}); err != nil {
		return "", fmt.Errorf("timeout checking http port connectivity of clickhouse service: %v", err)
	}

	return chSvc.Spec.ClusterIP, nil
}

func (data *TestData) deleteFlowVisibility() error {
	startTime := time.Now()
	defer func() {
		log.Infof("Deleting K8s resources created by flow visibility YAML took %v", time.Since(startTime))
	}()
	rc, _, _, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s", flowVisibilityYML))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deleting K8s resources created by flow visibility YAML: %v", err)
	}
	return nil
}

func (data *TestData) deleteClickHouseOperator() error {
	startTime := time.Now()
	defer func() {
		log.Infof("Deleting ClickHouse Operator took %v", time.Since(startTime))
	}()
	rc, _, _, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl delete -f %s -n kube-system", chOperatorYML))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deleting ClickHouse Operator: %v", err)
	}
	return nil
}

// deployFlowAggregator deploys the Flow Aggregator with ipfix collector and clickHouse address.
func (data *TestData) deployFlowAggregator(ipfixCollector string, o flowVisibilityTestOptions) error {

	flowAggYaml := flowAggregatorYML
	if testOptions.enableCoverage {
		flowAggYaml = flowAggregatorCovYML
	}
	rc, _, _, err := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl apply -f %s", flowAggYaml))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying the Flow Aggregator; %s not available on the control-plane Node", flowAggYaml)
	}
	// clickhouse-ca Secret is created in the flow-visibility Namespace. In order to make it accessible to the Flow Aggregator,
	// we copy it from Namespace flow-visibility to Namespace flow-aggregator when secureConnection is true.
	if o.secureConnection {
		secret, err := data.clientset.CoreV1().Secrets(flowVisibilityNamespace).Get(context.TODO(), flowAggregatorCHSecret, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get Secret with name %s in Namespace %s: %v", flowAggregatorCHSecret, flowVisibilityNamespace, err)
		}
		newSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: flowAggregatorNamespace,
				Name:      flowAggregatorCHSecret,
			},
			Data: secret.Data,
		}
		_, err = data.clientset.CoreV1().Secrets(flowAggregatorNamespace).Create(context.TODO(), newSecret, metav1.CreateOptions{})
		if errors.IsAlreadyExists(err) {
			_, err = data.clientset.CoreV1().Secrets(flowAggregatorNamespace).Update(context.TODO(), newSecret, metav1.UpdateOptions{})
		}
		if err != nil {
			return fmt.Errorf("unable to copy ClickHouse CA secret '%s' from Namespace '%s' to Namespace '%s': %v", flowAggregatorCHSecret, flowVisibilityNamespace, flowAggregatorNamespace, err)
		}
	}

	if err = data.mutateFlowAggregatorConfigMap(ipfixCollector, o); err != nil {
		return err
	}
	if rc, _, _, err = data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s rollout status deployment/%s --timeout=%v", flowAggregatorNamespace, flowAggregatorDeployment, 2*defaultTimeout)); err != nil || rc != 0 {
		_, stdout, _, _ := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s describe pod", flowAggregatorNamespace))
		_, logStdout, _, _ := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s logs -l app=flow-aggregator", flowAggregatorNamespace))
		return fmt.Errorf("error when waiting for the Flow Aggregator rollout to complete. kubectl describe output: %s, logs: %s", stdout, logStdout)
	}
	// Check for flow-aggregator Pod running again for db connection establishment
	flowAggPod, err := data.getFlowAggregator()
	if err != nil {
		return fmt.Errorf("error when getting flow-aggregator Pod: %v", err)
	}
	if err = data.podWaitForReady(2*defaultTimeout, flowAggPod.Name, flowAggregatorNamespace); err != nil {
		return err
	}
	return nil
}

func (data *TestData) mutateFlowAggregatorConfigMap(ipfixCollectorAddr string, o flowVisibilityTestOptions) error {
	configMap, err := data.GetFlowAggregatorConfigMap()
	if err != nil {
		return err
	}

	var flowAggregatorConf flowaggregatorconfig.FlowAggregatorConfig
	if err := yaml.Unmarshal([]byte(configMap.Data[flowAggregatorConfName]), &flowAggregatorConf); err != nil {
		return fmt.Errorf("failed to unmarshal FlowAggregator config from ConfigMap: %v", err)
	}

	flowAggregatorConf.FlowCollector = flowaggregatorconfig.FlowCollectorConfig{
		Enable:  true,
		Address: ipfixCollectorAddr,
	}
	flowAggregatorConf.ClickHouse = flowaggregatorconfig.ClickHouseConfig{
		Enable:         true,
		CommitInterval: aggregatorClickHouseCommitInterval.String(),
	}
	flowAggregatorConf.ActiveFlowRecordTimeout = aggregatorActiveFlowRecordTimeout.String()
	flowAggregatorConf.InactiveFlowRecordTimeout = aggregatorInactiveFlowRecordTimeout.String()
	flowAggregatorConf.RecordContents.PodLabels = true
	flowAggregatorConf.ClickHouse.DatabaseURL = o.databaseURL
	if o.secureConnection {
		flowAggregatorConf.ClickHouse.TLS.CACert = true
	}

	b, err := yaml.Marshal(&flowAggregatorConf)
	if err != nil {
		return fmt.Errorf("failed to marshal FlowAggregator config")
	}
	configMap.Data[flowAggregatorConfName] = string(b)
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
		getDS := func(dsName string, os string) (*appsv1.DaemonSet, error) {
			ds, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), dsName, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("error when getting Antrea %s daemonset: %v", os, err)
			}
			return ds, nil
		}
		var dsLinux *appsv1.DaemonSet
		var err error
		var desiredNum int32
		if dsLinux, err = getDS(antreaDaemonSet, "Linux"); err != nil {
			return false, err
		}
		if dsLinux.Generation != dsLinux.Status.ObservedGeneration {
			return false, nil
		}
		desiredNum += dsLinux.Status.DesiredNumberScheduled

		if len(clusterInfo.windowsNodes) != 0 {
			var dsWindows *appsv1.DaemonSet
			if dsWindows, err = getDS(antreaWindowsDaemonSet, "Windows"); err != nil {
				return false, err
			}
			if dsWindows.Generation != dsWindows.Status.ObservedGeneration {
				return false, nil
			}
			desiredNum += dsWindows.Status.DesiredNumberScheduled
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
		if len(pods.Items) != int(desiredNum) {
			return false, nil
		}
		for i := range pods.Items {
			pod := pods.Items[i]
			if pod.DeletionTimestamp != nil || !podutils.IsPodReady(&pod) {
				return false, nil
			}
		}
		return true, nil
	})
	if err == wait.ErrWaitTimeout {
		_, stdout, _, _ := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s describe pod", antreaNamespace))
		return fmt.Errorf("antrea-agent DaemonSet not ready within %v; kubectl describe pod output: %v", defaultTimeout, stdout)
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
	return retryOnConnectionLostError(retry.DefaultRetry, func() error { return data.waitForCoreDNSPods(timeout) })
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

// CreateClient initializes the K8s clientset in the TestData structure.
func (data *TestData) CreateClient(kubeconfigPath string) error {
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
	crdClient, err := crdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("error when creating CRD client: %v", err)
	}
	data.kubeConfig = kubeConfig
	data.clientset = clientset
	data.aggregatorClient = aggregatorClient
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

	deleteDS := func(ds string) error {
		if err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Delete(context.TODO(), ds, deleteOptions); err != nil {
			if errors.IsNotFound(err) {
				// no Antrea DaemonSet running, we return right away
				return nil
			}
			return fmt.Errorf("error when trying to delete Antrea DaemonSet: %v", err)
		}
		err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
			if _, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), ds, metav1.GetOptions{}); err != nil {
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
	if err := deleteDS(antreaDaemonSet); err != nil {
		return err
	}
	if err := deleteDS(antreaWindowsDaemonSet); err != nil {
		return err
	}

	return nil
}

// getImageName gets the image name from the fully qualified URI.
// For example: "gcr.io/kubernetes-e2e-test-images/agnhost:2.8" gets "agnhost".
func getImageName(uri string) string {
	registryAndImage := strings.Split(uri, ":")[0]
	paths := strings.Split(registryAndImage, "/")
	return paths[len(paths)-1]
}

type PodBuilder struct {
	Name               string
	Namespace          string
	VolumeMounts       []corev1.VolumeMount
	Volumes            []corev1.Volume
	Image              string
	ContainerName      string
	Command            []string
	Args               []string
	Env                []corev1.EnvVar
	Ports              []corev1.ContainerPort
	HostNetwork        bool
	IsPrivileged       bool
	ServiceAccountName string
	Annotations        map[string]string
	Labels             map[string]string
	NodeName           string
	MutateFunc         func(*corev1.Pod)
	ResourceRequests   corev1.ResourceList
	ResourceLimits     corev1.ResourceList
	ReadinessProbe     *corev1.Probe
}

func NewPodBuilder(name, ns, image string) *PodBuilder {
	return &PodBuilder{
		Name:      name,
		Namespace: ns,
		Image:     image,
	}
}

func (b *PodBuilder) WithContainerName(ctrName string) *PodBuilder {
	b.ContainerName = ctrName
	return b
}

func (b *PodBuilder) WithCommand(command []string) *PodBuilder {
	b.Command = command
	return b
}

func (b *PodBuilder) WithArgs(args []string) *PodBuilder {
	b.Args = args
	return b
}

func (b *PodBuilder) WithEnv(env []corev1.EnvVar) *PodBuilder {
	b.Env = env
	return b
}

func (b *PodBuilder) WithPorts(ports []corev1.ContainerPort) *PodBuilder {
	b.Ports = ports
	return b
}

func (b *PodBuilder) WithHostNetwork(v bool) *PodBuilder {
	b.HostNetwork = v
	return b
}

func (b *PodBuilder) InHostNetwork() *PodBuilder {
	return b.WithHostNetwork(true)
}

func (b *PodBuilder) Privileged() *PodBuilder {
	b.IsPrivileged = true
	return b
}

func (b *PodBuilder) WithServiceAccountName(name string) *PodBuilder {
	b.ServiceAccountName = name
	return b
}

func (b *PodBuilder) WithAnnotations(annotations map[string]string) *PodBuilder {
	b.Annotations = annotations
	return b
}

func (b *PodBuilder) WithLabels(labels map[string]string) *PodBuilder {
	b.Labels = labels
	return b
}

func (b *PodBuilder) OnNode(nodeName string) *PodBuilder {
	b.NodeName = nodeName
	return b
}

func (b *PodBuilder) WithMutateFunc(f func(*corev1.Pod)) *PodBuilder {
	b.MutateFunc = f
	return b
}

func (b *PodBuilder) WithResources(ResourceRequests, ResourceLimits corev1.ResourceList) *PodBuilder {
	b.ResourceRequests = ResourceRequests
	b.ResourceLimits = ResourceLimits
	return b
}

func (b *PodBuilder) AddVolume(volume []corev1.Volume) *PodBuilder {
	b.Volumes = volume
	return b
}

func (b *PodBuilder) AddVolumeMount(volumeMount []corev1.VolumeMount) *PodBuilder {
	b.VolumeMounts = volumeMount
	return b
}

func (b *PodBuilder) MountConfigMap(configMapName string, mountPath string, volumeName string) *PodBuilder {
	volumeMount := corev1.VolumeMount{Name: volumeName, MountPath: mountPath}
	volume := corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configMapName,
				},
			},
		},
	}
	return b.AddVolume([]corev1.Volume{volume}).AddVolumeMount([]corev1.VolumeMount{volumeMount})
}

func (b *PodBuilder) MountHostPath(hostPath string, hostPathType corev1.HostPathType, mountPath string, volumeName string) *PodBuilder {
	volumeMount := corev1.VolumeMount{Name: volumeName, MountPath: mountPath}
	volume := corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: hostPath,
				Type: &hostPathType,
			},
		},
	}
	return b.AddVolume([]corev1.Volume{volume}).AddVolumeMount([]corev1.VolumeMount{volumeMount})
}

func (b *PodBuilder) WithReadinessProbe(probe *corev1.Probe) *PodBuilder {
	b.ReadinessProbe = probe
	return b
}

func (b *PodBuilder) Create(data *TestData) error {
	containerName := b.ContainerName
	if containerName == "" {
		containerName = getImageName(b.Image)
	}
	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:            containerName,
				Image:           b.Image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         b.Command,
				Args:            b.Args,
				Env:             b.Env,
				Ports:           b.Ports,
				Resources: corev1.ResourceRequirements{
					Requests: b.ResourceRequests,
					Limits:   b.ResourceLimits,
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged: &b.IsPrivileged,
				},
				VolumeMounts:   b.VolumeMounts,
				ReadinessProbe: b.ReadinessProbe,
			},
		},
		Volumes:            b.Volumes,
		RestartPolicy:      corev1.RestartPolicyNever,
		HostNetwork:        b.HostNetwork,
		ServiceAccountName: b.ServiceAccountName,
		// Set it to 1s for immediate shutdown to reduce test run time and to avoid affecting subsequent tests.
		TerminationGracePeriodSeconds: pointer.Int64(1),
	}
	if b.NodeName != "" {
		podSpec.NodeSelector = map[string]string{
			"kubernetes.io/hostname": b.NodeName,
		}
	}
	if b.NodeName == controlPlaneNodeName() {
		// tolerate NoSchedule taint if we want Pod to run on control-plane Node
		podSpec.Tolerations = controlPlaneNoScheduleTolerations()
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        b.Name,
			Annotations: map[string]string{},
			Labels: map[string]string{
				"antrea-e2e": b.Name,
				"app":        containerName,
			},
		},
		Spec: podSpec,
	}
	for k, v := range b.Annotations {
		pod.Annotations[k] = v
	}
	for k, v := range b.Labels {
		pod.Labels[k] = v
	}
	if b.MutateFunc != nil {
		b.MutateFunc(pod)
	}
	if _, err := data.clientset.CoreV1().Pods(b.Namespace).Create(context.TODO(), pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func (data *TestData) UpdatePod(namespace, name string, mutateFunc func(*corev1.Pod)) error {
	pod, err := data.clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error when getting '%s/%s' Pod: %v", namespace, name, err)
	}
	if mutateFunc != nil {
		mutateFunc(pod)
	}
	if _, err := data.clientset.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error when updating '%s/%s' Pod: %v", namespace, name, err)
	}
	return nil
}

// createBusyboxPodOnNode creates a Pod in the test namespace with a single busybox container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createBusyboxPodOnNode(name string, ns string, nodeName string, hostNetwork bool) error {
	return NewPodBuilder(name, ns, busyboxImage).OnNode(nodeName).WithCommand([]string{"sleep", "3600"}).WithHostNetwork(hostNetwork).Create(data)
}

// createMcJoinPodOnNode creates a Pod in the test namespace with a single mcjoin container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createMcJoinPodOnNode(name string, ns string, nodeName string, hostNetwork bool) error {
	return NewPodBuilder(name, ns, mcjoinImage).OnNode(nodeName).WithCommand([]string{"sleep", "3600"}).WithHostNetwork(hostNetwork).Create(data)
}

// createToolboxPodOnNode creates a Pod in the test namespace with a single toolbox container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createToolboxPodOnNode(name string, ns string, nodeName string, hostNetwork bool) error {
	return NewPodBuilder(name, ns, ToolboxImage).OnNode(nodeName).WithCommand([]string{"sleep", "3600"}).WithHostNetwork(hostNetwork).Create(data)
}

// createNginxPodOnNode creates a Pod in the test namespace with a single nginx container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createNginxPodOnNode(name string, ns string, nodeName string, hostNetwork bool) error {
	image := nginxImage
	if clusterInfo.nodesOS[nodeName] == "windows" {
		image = iisImage
	}
	return NewPodBuilder(name, ns, image).OnNode(nodeName).WithPorts([]corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
	}).WithHostNetwork(hostNetwork).Create(data)
}

// createServerPod creates a Pod that can listen to specified port and have named port set.
func (data *TestData) createServerPod(name string, ns string, portName string, portNum int32, setHostPort bool, hostNetwork bool) error {
	// See https://github.com/kubernetes/kubernetes/blob/master/test/images/agnhost/porter/porter.go#L17 for the image's detail.
	cmd := "porter"
	env := corev1.EnvVar{Name: fmt.Sprintf("SERVE_PORT_%d", portNum), Value: "foo"}
	port := corev1.ContainerPort{Name: portName, ContainerPort: portNum}
	if setHostPort {
		// If hostPort is to be set, it must match the container port number.
		port.HostPort = int32(portNum)
	}
	return NewPodBuilder(name, ns, agnhostImage).WithArgs([]string{cmd}).WithEnv([]corev1.EnvVar{env}).WithPorts([]corev1.ContainerPort{port}).WithHostNetwork(hostNetwork).Create(data)
}

// createCustomPod creates a Pod in given Namespace with custom labels.
func (data *TestData) createServerPodWithLabels(name, ns string, portNum int32, labels map[string]string) error {
	cmd := []string{"/agnhost", "serve-hostname", "--tcp", "--http=false", "--port", fmt.Sprintf("%d", portNum)}
	env := corev1.EnvVar{Name: fmt.Sprintf("SERVE_PORT_%d", portNum), Value: "foo"}
	port := corev1.ContainerPort{ContainerPort: portNum}
	containerName := fmt.Sprintf("c%v", portNum)
	return NewPodBuilder(name, ns, agnhostImage).WithContainerName(containerName).WithCommand(cmd).WithEnv([]corev1.EnvVar{env}).WithPorts([]corev1.ContainerPort{port}).WithLabels(labels).Create(data)
}

func (data *TestData) PatchPod(namespace, name string, patch []byte) error {
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, err := data.clientset.CoreV1().Pods(namespace).Patch(context.TODO(), name, types.MergePatchType, patch, metav1.PatchOptions{})
		return err
	}); err != nil {
		return err
	}
	return nil
}

// DeletePod deletes a Pod in the test namespace.
func (data *TestData) DeletePod(namespace, name string) error {
	var gracePeriodSeconds int64 = 5
	deleteOptions := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriodSeconds,
	}
	if err := data.clientset.CoreV1().Pods(namespace).Delete(context.TODO(), name, deleteOptions); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// Deletes a Pod in the test namespace then waits us to timeout for the Pod not to be visible to the
// client anymore.
func (data *TestData) DeletePodAndWait(timeout time.Duration, name string, ns string) error {
	if err := data.DeletePod(ns, name); err != nil {
		return err
	}
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if _, err := data.clientset.CoreV1().Pods(ns).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, fmt.Errorf("error when getting Pod: %v", err)
		}
		// Keep trying
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return fmt.Errorf("Pod '%s' still visible to client after %v", name, timeout)
	}
	return err
}

type PodCondition func(*corev1.Pod) (bool, error)

// PodWaitFor polls the K8s apiserver until the specified Pod is found (in the test Namespace) and
// the condition predicate is met (or until the provided timeout expires).
func (data *TestData) PodWaitFor(timeout time.Duration, name, namespace string, condition PodCondition) (*corev1.Pod, error) {
	var pod *corev1.Pod
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		var err error
		pod, err = data.clientset.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("error when getting Pod '%s': %v", name, err)
		}
		return condition(pod)
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && pod != nil {
			return nil, fmt.Errorf("timed out waiting for the condition, Pod.Status: %s", pod.Status.String())
		}
		return nil, err
	}
	return pod, nil
}

// podWaitForRunning polls the k8s apiserver until the specified Pod is in the "running" state (or
// until the provided timeout expires).
func (data *TestData) podWaitForRunning(timeout time.Duration, name, namespace string) error {
	_, err := data.PodWaitFor(timeout, name, namespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	return err
}

// podWaitForReady polls the k8s apiserver until the specified Pod is in the "Ready" status (or
// until the provided timeout expires).
func (data *TestData) podWaitForReady(timeout time.Duration, name, namespace string) error {
	_, err := data.PodWaitFor(timeout, name, namespace, func(p *corev1.Pod) (bool, error) {
		for _, condition := range p.Status.Conditions {
			if condition.Type == corev1.PodReady {
				return condition.Status == corev1.ConditionTrue, nil
			}
		}
		return false, nil
	})
	return err
}

// podWaitForIPs polls the K8s apiserver until the specified Pod is in the "running" state (or until
// the provided timeout expires). The function then returns the IP addresses assigned to the Pod. If the
// Pod is not using "hostNetwork", the function also checks that an IP address exists in each required
// Address Family in the cluster.
func (data *TestData) podWaitForIPs(timeout time.Duration, name, namespace string) (*PodIPs, error) {
	pod, err := data.PodWaitFor(timeout, name, namespace, func(pod *corev1.Pod) (bool, error) {
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
	podIPStrings := sets.New[string](pod.Status.PodIP)
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
		if clusterInfo.podV4NetworkCIDR != "" && ips.IPv4 == nil {
			return nil, fmt.Errorf("no IPv4 address is assigned while cluster was configured with IPv4 Pod CIDR %s", clusterInfo.podV4NetworkCIDR)
		}
		if clusterInfo.podV6NetworkCIDR != "" && ips.IPv6 == nil {
			return nil, fmt.Errorf("no IPv6 address is assigned while cluster was configured with IPv6 Pod CIDR %s", clusterInfo.podV6NetworkCIDR)
		}
	}
	return ips, nil
}

func parsePodIPs(podIPStrings sets.Set[string]) (*PodIPs, error) {
	ips := new(PodIPs)
	for idx := range sets.List(podIPStrings) {
		ipStr := sets.List(podIPStrings)[idx]
		ip := net.ParseIP(ipStr)
		if ip.To4() != nil {
			if ips.IPv4 != nil && ipStr != ips.IPv4.String() {
				return nil, fmt.Errorf("Pod is assigned multiple IPv4 addresses: %s and %s", ips.IPv4.String(), ipStr)
			}
			if ips.IPv4 == nil {
				ips.IPv4 = &ip
				ips.IPStrings = append(ips.IPStrings, ipStr)
			}
		} else {
			if ips.IPv6 != nil && ipStr != ips.IPv6.String() {
				return nil, fmt.Errorf("Pod is assigned multiple IPv6 addresses: %s and %s", ips.IPv6.String(), ipStr)
			}
			if ips.IPv6 == nil {
				ips.IPv6 = &ip
				ips.IPStrings = append(ips.IPStrings, ipStr)
			}
		}
	}
	if len(ips.IPStrings) == 0 {
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

func (data *TestData) RunCommandFromAntreaPodOnNode(nodeName string, cmd []string) (string, string, error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return "", "", err
	}
	return data.RunCommandFromPod(antreaNamespace, antreaPodName, agentContainerName, cmd)
}

// getFlowAggregator retrieves the name of the Flow-Aggregator Pod (flow-aggregator-*) running on a specific Node.
func (data *TestData) getFlowAggregator() (*corev1.Pod, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "app=flow-aggregator",
	}
	pods, err := data.clientset.CoreV1().Pods(flowAggregatorNamespace).List(context.TODO(), listOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to list Flow Aggregator Pod: %v", err)
	}
	if len(pods.Items) != 1 {
		return nil, fmt.Errorf("expected *exactly* one Pod")
	}
	return &pods.Items[0], nil
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

// RestartAntreaAgentPods deletes all the antrea-agent Pods to force them to be re-scheduled. It
// then waits for the new Pods to become available.
func (data *TestData) RestartAntreaAgentPods(timeout time.Duration) error {
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

// CreateService creates a service with port and targetPort.
func (data *TestData) CreateService(serviceName, namespace string, port, targetPort int32, selector map[string]string, affinity, nodeLocalExternal bool,
	serviceType corev1.ServiceType, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	annotation := make(map[string]string)
	return data.CreateServiceWithAnnotations(serviceName, namespace, port, targetPort, corev1.ProtocolTCP, selector, affinity, nodeLocalExternal, serviceType, ipFamily, annotation)
}

// CreateServiceWithAnnotations creates a service with Annotation
func (data *TestData) CreateServiceWithAnnotations(serviceName, namespace string, port, targetPort int32, protocol corev1.Protocol, selector map[string]string, affinity, nodeLocalExternal bool,
	serviceType corev1.ServiceType, ipFamily *corev1.IPFamily, annotations map[string]string) (*corev1.Service, error) {
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
				"antrea-e2e": serviceName,
				"app":        serviceName,
			},
			Annotations: annotations,
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
	return data.clientset.CoreV1().Services(namespace).Create(context.TODO(), &service, metav1.CreateOptions{})
}

// createNginxClusterIPServiceWithAnnotations creates nginx service with Annotation
func (data *TestData) createNginxClusterIPServiceWithAnnotations(nodeName string, affinity bool, ipFamily *corev1.IPFamily, annotation map[string]string) (*corev1.Service, error) {
	selectorLabel := "nginx"
	if clusterInfo.nodesOS[nodeName] == "windows" {
		selectorLabel = "iis"
	}
	return data.CreateServiceWithAnnotations("nginx", data.testNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": selectorLabel}, affinity, false, corev1.ServiceTypeClusterIP, ipFamily, annotation)
}

// createNginxClusterIPService creates a nginx service with the given name.
func (data *TestData) createNginxClusterIPService(name, namespace string, affinity bool, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	if name == "" {
		name = "nginx"
	}
	return data.CreateService(name, namespace, 80, 80, map[string]string{"app": "nginx"}, affinity, false, corev1.ServiceTypeClusterIP, ipFamily)
}

// createAgnhostClusterIPService creates a ClusterIP agnhost service with the given name.
func (data *TestData) createAgnhostClusterIPService(serviceName string, affinity bool, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	return data.CreateService(serviceName, data.testNamespace, 8080, 8080, map[string]string{"app": "agnhost"}, affinity, false, corev1.ServiceTypeClusterIP, ipFamily)
}

// createAgnhostNodePortService creates a NodePort agnhost service with the given name.
func (data *TestData) createAgnhostNodePortService(serviceName string, affinity, nodeLocalExternal bool, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	return data.CreateService(serviceName, data.testNamespace, 8080, 8080, map[string]string{"app": "agnhost"}, affinity, nodeLocalExternal, corev1.ServiceTypeNodePort, ipFamily)
}

// createNginxNodePortService creates a NodePort nginx service with the given name.
func (data *TestData) createNginxNodePortService(serviceName, namespace string, affinity, nodeLocalExternal bool, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	return data.CreateService(serviceName, namespace, 80, 80, map[string]string{"app": "nginx"}, affinity, nodeLocalExternal, corev1.ServiceTypeNodePort, ipFamily)
}

func (data *TestData) updateServiceExternalTrafficPolicy(serviceName string, nodeLocalExternal bool) (*corev1.Service, error) {
	svc, err := data.clientset.CoreV1().Services(data.testNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return svc, err
	}
	if nodeLocalExternal {
		svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	} else {
		svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeCluster
	}

	return data.clientset.CoreV1().Services(data.testNamespace).Update(context.TODO(), svc, metav1.UpdateOptions{})
}

func (data *TestData) updateService(serviceName string, mutateFunc func(service *corev1.Service)) (*corev1.Service, error) {
	svc, err := data.clientset.CoreV1().Services(data.testNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if mutateFunc != nil {
		mutateFunc(svc)
	}
	if svc, err = data.clientset.CoreV1().Services(data.testNamespace).Update(context.TODO(), svc, metav1.UpdateOptions{}); err != nil {
		return nil, fmt.Errorf("error when updating '%s' Service: %v", serviceName, err)
	}
	return svc, nil
}

// createAgnhostLoadBalancerService creates a LoadBalancer agnhost service with the given name.
func (data *TestData) createAgnhostLoadBalancerService(serviceName string, affinity, nodeLocalExternal bool, ingressIPs []string, ipFamily *corev1.IPFamily, annotations map[string]string) (*corev1.Service, error) {
	svc, err := data.CreateServiceWithAnnotations(serviceName, data.testNamespace, 8080, 8080, corev1.ProtocolTCP, map[string]string{"app": "agnhost"}, affinity, nodeLocalExternal, corev1.ServiceTypeLoadBalancer, ipFamily, annotations)
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

func (data *TestData) createNginxLoadBalancerService(affinity bool, ingressIPs []string, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	svc, err := data.CreateService(nginxLBService, data.testNamespace, 80, 80, map[string]string{"app": "nginx"}, affinity, false, corev1.ServiceTypeLoadBalancer, ipFamily)
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
func (data *TestData) deleteService(namespace, name string) error {
	if err := data.clientset.CoreV1().Services(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("unable to cleanup service %v: %v", name, err)
	}
	return nil
}

// Deletes a Service in the test namespace then waits us to timeout for the Service not to be visible to the
// client anymore.
func (data *TestData) deleteServiceAndWait(timeout time.Duration, name, namespace string) error {
	if err := data.deleteService(namespace, name); err != nil {
		return err
	}
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		if _, err := data.clientset.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, fmt.Errorf("error when getting Service: %v", err)
		}
		// Keep trying
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return fmt.Errorf("Service '%s' still visible to client after %v", name, timeout)
	}
	return err
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
	return data.clientset.NetworkingV1().NetworkPolicies(data.testNamespace).Create(context.TODO(), policy, metav1.CreateOptions{})
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

// randName generates a DNS-1123 subdomain name
func randName(prefix string) string {
	nameSuffixLength := 8
	return prefix + randSeq(nameSuffixLength)
}

// Run the provided command in the specified Container for the give Pod and returns the contents of
// stdout and stderr as strings. An error either indicates that the command couldn't be run or that
// the command returned a non-zero error code.
func (data *TestData) RunCommandFromPod(podNamespace string, podName string, containerName string, cmd []string) (stdout string, stderr string, err error) {
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
	ctx, cancelFn := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancelFn()
	var stdoutB, stderrB bytes.Buffer
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
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
	v, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil {
		return 0, 0, 0.0, fmt.Errorf("Error when retrieving 'sent probes' from arpping output: %v", err)
	}
	sent = uint32(v)

	v, err = strconv.ParseUint(matches[2], 10, 32)
	if err != nil {
		return 0, 0, 0.0, fmt.Errorf("Error when retrieving 'received responses' from arpping output: %v", err)
	}
	received = uint32(v)
	loss = 100. * float32(sent-received) / float32(sent)
	return sent, received, loss, nil
}

// RunPingCommandFromTestPod uses ping to check connectivity between the Pod and the given target Pod IPs.
// If dontFragment is true and size is 0, it will set the size to the maximum value allowed by the Pod's MTU.
func (data *TestData) RunPingCommandFromTestPod(podInfo PodInfo, ns string, targetPodIPs *PodIPs, ctrName string, count int, size int, dontFragment bool) error {
	if podInfo.OS != "windows" && podInfo.OS != "linux" {
		return fmt.Errorf("OS of Pod '%s' is not clear", podInfo.Name)
	}
	var sizeIPv4, sizeIPv6 int
	// TODO: GetPodInterfaceMTU should work for Windows.
	if dontFragment && size == 0 && podInfo.OS == "linux" {
		mtu, err := data.GetPodInterfaceMTU(ns, podInfo.Name, ctrName)
		if err != nil {
			return fmt.Errorf("error when retrieving MTU of Pod '%s': %w", podInfo.Name, err)
		}
		// 8 ICMP header, 20 IPv4 header, 40 IPv6 header
		sizeIPv4 = mtu - 28
		sizeIPv6 = mtu - 48
	} else {
		sizeIPv4 = size
		sizeIPv6 = size
	}

	if targetPodIPs.IPv4 != nil {
		cmdV4 := getPingCommand(count, sizeIPv4, podInfo.OS, targetPodIPs.IPv4, dontFragment)
		if stdout, stderr, err := data.RunCommandFromPod(ns, podInfo.Name, ctrName, cmdV4); err != nil {
			return fmt.Errorf("error when running ping command '%s': %v - stdout: %s - stderr: %s", strings.Join(cmdV4, " "), err, stdout, stderr)
		}
	}
	if targetPodIPs.IPv6 != nil {
		cmdV6 := getPingCommand(count, sizeIPv6, podInfo.OS, targetPodIPs.IPv6, dontFragment)
		if stdout, stderr, err := data.RunCommandFromPod(ns, podInfo.Name, ctrName, cmdV6); err != nil {
			return fmt.Errorf("error when running ping command '%s': %v - stdout: %s - stderr: %s", strings.Join(cmdV6, " "), err, stdout, stderr)
		}
	}
	return nil
}

func (data *TestData) runNetcatCommandFromTestPod(podName string, ns string, server string, port int32) error {
	return data.runNetcatCommandFromTestPodWithProtocol(podName, ns, busyboxContainerName, server, port, "tcp")
}

func (data *TestData) runNetcatCommandFromTestPodWithProtocol(podName string, ns string, containerName string, server string, port int32, protocol string) error {
	// No parameter required for TCP connections.
	protocolOption := ""
	if protocol == "udp" {
		protocolOption = "-u"
	}
	// Retrying several times to avoid flakes as the test may involve DNS (coredns) and Service/Endpoints (kube-proxy).
	cmd := []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf("for i in $(seq 1 5); do nc -vz -w 4 %s %s %d && exit 0 || sleep 1; done; exit 1",
			protocolOption, server, port),
	}

	stdout, stderr, err := data.RunCommandFromPod(ns, podName, containerName, cmd)
	if err == nil {
		return nil
	}
	return fmt.Errorf("nc stdout: <%v>, stderr: <%v>, err: <%v>", stdout, stderr, err)
}

func (data *TestData) runWgetCommandOnBusyboxWithRetry(podName string, ns string, url string, maxAttempts int) (string, string, error) {
	return data.runWgetCommandFromTestPodWithRetry(podName, ns, busyboxContainerName, url, maxAttempts)
}

func (data *TestData) runWgetCommandFromTestPodWithRetry(podName string, ns string, containerName string, url string, maxAttempts int) (string, string, error) {
	var stdout, stderr string
	var err error
	cmd := []string{"wget", "-O", "-", url, "-T", "5"}
	for i := 0; i < maxAttempts; i++ {
		stdout, stderr, err = data.RunCommandFromPod(ns, podName, containerName, cmd)
		if err != nil {
			if i < maxAttempts-1 {
				time.Sleep(time.Second)
			}
		} else {
			break
		}
	}
	return stdout, stderr, err
}

func (data *TestData) doesOVSPortExist(antreaPodName string, portName string) (bool, error) {
	cmd := []string{"ovs-vsctl", "port-to-br", portName}
	_, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
	if err == nil {
		return true, nil
	} else if strings.Contains(stderr, "no port named") {
		return false, nil
	}
	return false, fmt.Errorf("error when running ovs-vsctl command on Pod '%s': %v", antreaPodName, err)
}

func (data *TestData) doesOVSPortExistOnWindows(nodeName, portName string) (bool, error) {
	cmd := fmt.Sprintf("ovs-vsctl port-to-br %s", portName)
	_, _, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	if strings.Contains(stderr, "no port named") {
		return false, nil
	} else if err == nil {
		return true, nil
	}
	return false, fmt.Errorf("error when running ovs-vsctl command on Windows Node '%s': %v", nodeName, err)
}

func (data *TestData) GetAntreaAgentConf() (*agentconfig.AgentConfig, error) {
	configMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		return nil, err
	}
	var agentConf agentconfig.AgentConfig
	if err := yaml.Unmarshal([]byte(configMap.Data["antrea-agent.conf"]), &agentConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Agent config from ConfigMap: %v", err)
	}
	return &agentConf, nil
}

func (data *TestData) GetEncapMode() (config.TrafficEncapModeType, error) {
	agentConf, err := data.GetAntreaAgentConf()
	if err != nil {
		return config.TrafficEncapModeInvalid, fmt.Errorf("failed to get Antrea Agent config: %w", err)
	}
	if agentConf.TrafficEncapMode == "" {
		// default encap mode
		return config.TrafficEncapModeEncap, nil
	}
	_, encapMode := config.GetTrafficEncapModeFromStr(agentConf.TrafficEncapMode)
	return encapMode, nil
}

func (data *TestData) isProxyAll() (bool, error) {
	agentConf, err := data.GetAntreaAgentConf()
	if err != nil {
		return false, fmt.Errorf("failed to get Antrea Agent config: %w", err)
	}
	return agentConf.AntreaProxy.ProxyAll, nil
}

func GetAgentFeatures() (featuregate.FeatureGate, error) {
	featureGate := features.DefaultMutableFeatureGate.DeepCopy()
	var cfg agentconfig.AgentConfig
	if err := yaml.Unmarshal([]byte(AntreaConfigMap.Data[antreaAgentConfName]), &cfg); err != nil {
		return nil, err
	}
	err := featureGate.SetFromMap(cfg.FeatureGates)
	if err != nil {
		return nil, err
	}
	return featureGate, nil
}

func GetControllerFeatures() (featuregate.FeatureGate, error) {
	featureGate := features.DefaultMutableFeatureGate.DeepCopy()
	var cfg controllerconfig.ControllerConfig
	if err := yaml.Unmarshal([]byte(AntreaConfigMap.Data[antreaControllerConfName]), &cfg); err != nil {
		return nil, err
	}
	err := featureGate.SetFromMap(cfg.FeatureGates)
	if err != nil {
		return nil, err
	}
	return featureGate, nil
}

func (data *TestData) GetAntreaWindowsConfigMap(antreaNamespace string) (*corev1.ConfigMap, error) {
	daemonset, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), antreaWindowsDaemonSet, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Antrea Windows DaemonSet: %v", err)
	}
	var configMapName string
	for _, volume := range daemonset.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil && volume.Name == antreaWindowsConfigVolume {
			configMapName = volume.ConfigMap.Name
			break
		}
	}
	if len(configMapName) == 0 {
		return nil, fmt.Errorf("failed to locate Windows %s ConfigMap volume", antreaWindowsConfigVolume)
	}
	configMap, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Windows ConfigMap %s: %v", configMapName, err)
	}
	return configMap, nil
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

func (data *TestData) getAgentConf(antreaNamespace string) (*agentconfig.AgentConfig, error) {
	configMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		return nil, err
	}
	agentConfData := configMap.Data[antreaAgentConfName]
	var agentConf agentconfig.AgentConfig
	if err := yaml.Unmarshal([]byte(agentConfData), &agentConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Agent config from ConfigMap: %v", configMap)
	}
	return &agentConf, nil
}

func (data *TestData) GetGatewayInterfaceName(antreaNamespace string) (string, error) {
	agentConf, err := data.getAgentConf(antreaNamespace)
	if err != nil {
		return "", err
	}
	if agentConf.HostGateway != "" {
		return agentConf.HostGateway, nil
	}
	return antreaDefaultGW, nil
}

func (data *TestData) GetMulticastInterfaces(antreaNamespace string) ([]string, error) {
	agentConf, err := data.getAgentConf(antreaNamespace)
	if err != nil {
		return []string{}, err
	}
	return agentConf.Multicast.MulticastInterfaces, nil
}

func (data *TestData) GetTransportInterface() (string, error) {
	// It assumes all Nodes have the same transport interface name.
	nodeName := nodeName(0)
	nodeIP := nodeIP(0)
	antreaPod, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return "", fmt.Errorf("failed to get Antrea Pod on Node %s: %v", nodeName, err)
	}
	cmd := []string{"ip", "-br", "addr", "show"}
	stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
	if stdout == "" || stderr != "" || err != nil {
		return "", fmt.Errorf("failed to show ip address, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
	}
	// Example stdout:
	// eth0@if461       UP             172.18.0.2/16 fc00:f853:ccd:e793::2/64 fe80::42:acff:fe12:2/64
	// eno1             UP             10.176.3.138/22 fe80::e643:4bff:fe43:a30e/64
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		if strings.Contains(line, nodeIP+"/") {
			fields := strings.Fields(line)
			name, _, _ := strings.Cut(fields[0], "@")
			return name, nil
		}
	}
	return "", fmt.Errorf("no interface was assigned with Node IP %s", nodeIP)
}

func (data *TestData) GetPodInterfaceMTU(namespace string, podName string, containerName string) (int, error) {
	cmd := []string{"cat", "/sys/class/net/eth0/mtu"}
	stdout, stderr, err := data.RunCommandFromPod(namespace, podName, containerName, cmd)
	if stdout == "" || stderr != "" || err != nil {
		return 0, fmt.Errorf("failed to get interface MTU, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
	}

	mtu, err := strconv.Atoi(strings.TrimSpace(stdout))
	if err != nil {
		return 0, fmt.Errorf("failed to convert MTU to int: %v", err)
	}
	return mtu, nil
}

func (data *TestData) GetNodeMACAddress(node, device string) (string, error) {
	antreaPod, err := data.getAntreaPodOnNode(node)
	if err != nil {
		return "", fmt.Errorf("failed to get Antrea Pod on Node %s: %v", node, err)
	}
	cmd := []string{"cat", fmt.Sprintf("/sys/class/net/%s/address", device)}
	stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
	if stdout == "" || stderr != "" || err != nil {
		return "", fmt.Errorf("failed to get MAC address, stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
	}
	return strings.TrimSpace(stdout), nil
}

// mutateAntreaConfigMap will perform the specified updates on the antrea-agent config and the
// antrea-controller config by updating the antrea-config ConfigMap. It will then restart Agents and
// Controller if needed. Note that if the specified updates do not result in any actual change to
// the ConfigMap, this function is a complete no-op.
func (data *TestData) mutateAntreaConfigMap(
	controllerChanges func(config *controllerconfig.ControllerConfig),
	agentChanges func(config *agentconfig.AgentConfig),
	restartController bool,
	restartAgent bool,
) error {
	includeWindowsAgent := false
	var antreaWindowsConfigMap *corev1.ConfigMap
	if len(clusterInfo.windowsNodes) != 0 {
		var err error
		includeWindowsAgent = true
		antreaWindowsConfigMap, err = data.GetAntreaWindowsConfigMap(antreaNamespace)
		if err != nil {
			return err
		}
	}
	configMap, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		return err
	}

	// for each config (Agent and Controller), we unmarshal twice and apply changes on one of
	// the copy. We use the unchanged copy to detect whether any actual change was made to the
	// config by the client-provided functions (controllerConfOut and agentChanges).

	getControllerConf := func() (*controllerconfig.ControllerConfig, error) {
		var controllerConf controllerconfig.ControllerConfig
		if err := yaml.Unmarshal([]byte(configMap.Data["antrea-controller.conf"]), &controllerConf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Controller config from ConfigMap: %v", err)
		}
		// as a convenience, we initialize the FeatureGates map if it is nil
		if controllerConf.FeatureGates == nil {
			controllerConf.FeatureGates = make(map[string]bool)
		}
		return &controllerConf, nil
	}

	controllerConfChanged := false
	if controllerChanges != nil {
		controllerConfIn, err := getControllerConf()
		if err != nil {
			return err
		}
		controllerConfOut, err := getControllerConf()
		if err != nil {
			return err
		}

		controllerChanges(controllerConfOut)
		controllerConfChanged = !reflect.DeepEqual(controllerConfIn, controllerConfOut)

		b, err := yaml.Marshal(controllerConfOut)
		if err != nil {
			return fmt.Errorf("failed to marshal Controller config: %v", err)
		}
		configMap.Data["antrea-controller.conf"] = string(b)
	}
	//getAgentConf should be able to process both windows and linux configmap.
	getAgentConf := func(cm *corev1.ConfigMap) (*agentconfig.AgentConfig, error) {
		var agentConf agentconfig.AgentConfig
		if err := yaml.Unmarshal([]byte(cm.Data["antrea-agent.conf"]), &agentConf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Agent config from ConfigMap: %v", err)
		}
		// as a convenience, we initialize the FeatureGates map if it is nil
		if agentConf.FeatureGates == nil {
			agentConf.FeatureGates = make(map[string]bool)
		}
		return &agentConf, nil
	}

	agentConfChanged := false
	agentConfigMaps := []*corev1.ConfigMap{configMap}
	if agentChanges != nil {
		if includeWindowsAgent {
			agentConfigMaps = append(agentConfigMaps, antreaWindowsConfigMap)
		}
		for _, cm := range agentConfigMaps {
			agentConfIn, err := getAgentConf(cm)
			if err != nil {
				return err
			}
			agentConfOut, err := getAgentConf(cm)
			if err != nil {
				return err
			}

			agentChanges(agentConfOut)
			agentConfChanged = !reflect.DeepEqual(agentConfIn, agentConfOut)

			b, err := yaml.Marshal(agentConfOut)
			if err != nil {
				return fmt.Errorf("failed to marshal Agent config: %v", err)
			}
			cm.Data["antrea-agent.conf"] = string(b)
		}
	}

	if !agentConfChanged && !controllerConfChanged {
		// no config was changed, no need to call Update or restart anything
		return nil
	}

	for _, cm := range agentConfigMaps {
		if _, err := data.clientset.CoreV1().ConfigMaps(antreaNamespace).Update(context.TODO(), cm, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update ConfigMap %s: %v", cm.Name, err)
		}
	}

	if restartAgent && agentConfChanged {
		err = data.RestartAntreaAgentPods(defaultTimeout)
		if err != nil {
			return fmt.Errorf("error when restarting antrea-agent Pod: %v", err)
		}
	}
	// we currently restart the controller after the agents
	if restartController && controllerConfChanged {
		_, err = data.restartAntreaControllerPod(defaultTimeout)
		if err != nil {
			return fmt.Errorf("error when restarting antrea-controller Pod: %v", err)
		}
	}
	return nil
}

func (data *TestData) killProcessAndCollectCovFiles(namespace, podName, containerName, processName, covFile, covDir string) error {
	if err := data.collectAntctlCovFiles(podName, containerName, namespace, covDir); err != nil {
		return fmt.Errorf("error when copying antctl coverage files out: %v", err)
	}

	cmds := []string{"pgrep", "-f", processName, "-P", "1"}
	stdout, stderr, err := data.RunCommandFromPod(namespace, podName, containerName, cmds)
	if err != nil {
		return fmt.Errorf("error when getting pid of '%s', stderr: <%v>, err: <%v>", processName, stderr, err)
	}
	cmds = []string{"kill", "-SIGINT", strings.TrimSpace(stdout)}
	log.Infof("Sending SIGINT to '%s'", processName)
	_, stderr, err = data.RunCommandFromPod(namespace, podName, containerName, cmds)
	if err != nil {
		return fmt.Errorf("error when sending SIGINT signal to '%s', stderr: <%v>, err: <%v>", processName, stderr, err)
	}

	log.Infof("Copying coverage files from Pod '%s'", podName)
	if err := wait.PollImmediate(1*time.Second, 5*time.Second, func() (bool, error) {
		if err = data.copyPodFiles(podName, containerName, namespace, covFile, covDir); err != nil {
			log.Infof("Coverage file not available yet for copy: %v", err)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("timeout when waiting for coverage file")
	}

	return nil
}

// gracefulExitAntreaController copies the Antrea controller binary coverage data file out before terminating the Pod
func (data *TestData) gracefulExitAntreaController(covDir string) error {
	antreaController, err := data.getAntreaController()
	if err != nil {
		return fmt.Errorf("error when getting antrea-controller Pod: %w", err)
	}
	podName := antreaController.Name

	if err := data.killProcessAndCollectCovFiles(antreaNamespace, podName, "antrea-controller", antreaControllerCovBinary, antreaControllerCovFile, covDir); err != nil {
		return fmt.Errorf("error when gracefully exiting Antrea Controller: %w", err)
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
		if err := data.killProcessAndCollectCovFiles(antreaNamespace, podName, "antrea-agent", antreaAgentCovBinary, antreaAgentCovFile, covDir); err != nil {
			return fmt.Errorf("error when gracefully exiting Antrea Agent: %w", err)
		}
	}
	return nil
}

// gracefulExitFlowAggregator copies the Flow Aggregator binary coverage data file out before terminating the Pod.
func (data *TestData) gracefulExitFlowAggregator(covDir string) error {
	flowAggPod, err := data.getFlowAggregator()
	if err != nil {
		return fmt.Errorf("error when getting flow-aggregator Pod: %v", err)
	}
	podName := flowAggPod.Name

	if err := data.killProcessAndCollectCovFiles(flowAggregatorNamespace, podName, "flow-aggregator", flowAggregatorCovBinary, flowAggregatorCovFile, covDir); err != nil {
		return fmt.Errorf("error when gracefully exiting Flow Aggregator: %w", err)
	}

	return nil
}

// collectAntctlCovFiles collects coverage files for the antctl binary from the Pod and saves them to the coverage directory
func (data *TestData) collectAntctlCovFiles(podName string, containerName string, nsName string, covDir string) error {
	// copy antctl coverage files from Pod to the coverage directory
	cmds := []string{"bash", "-c", "find . -maxdepth 1 -name 'antctl*.out' -exec basename {} ';'"}
	stdout, stderr, err := data.RunCommandFromPod(nsName, podName, containerName, cmds)
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
		cmd = fmt.Sprintf("/bin/sh -c find %s -maxdepth 1 -name 'antctl*.out'", cpNodeCoverageDir)
	} else {
		cmd = fmt.Sprintf("find %s -maxdepth 1 -name 'antctl*.out'", cpNodeCoverageDir)
	}
	rc, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
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
func (data *TestData) copyPodFiles(podName string, containerName string, nsName string, fileName string, destDir string) error {
	// getPodWriter creates the file with name podName-fileName-suffix. It returns nil if the
	// file cannot be created. File must be closed by the caller.
	getPodWriter := func(podName, fileName, suffix string) *os.File {
		destFile := filepath.Join(destDir, fmt.Sprintf("%s-%s-%s", podName, fileName, suffix))
		f, err := os.Create(destFile)
		if err != nil {
			_ = fmt.Errorf("error when creating destination file '%s': %v", destFile, err)
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
	stdout, stderr, err := data.RunCommandFromPod(nsName, podName, containerName, cmd)
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
	rc, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
	if err != nil || rc != 0 {
		return fmt.Errorf("cannot retrieve content of file '%s' from Node '%s', stderr: <%v>, err: <%v>", fileName, controlPlaneNodeName(), stderr, err)
	}
	if stdout == "" {
		return nil
	}
	w.WriteString(stdout)
	return nil
}

// createAgnhostPodOnNode creates a Pod in the test namespace with a single agnhost container. The
// Pod will be scheduled on the specified Node (if nodeName is not empty).
func (data *TestData) createAgnhostPodOnNode(name string, ns string, nodeName string, hostNetwork bool) error {
	return NewPodBuilder(name, ns, agnhostImage).OnNode(nodeName).WithCommand([]string{"sleep", "3600"}).WithHostNetwork(hostNetwork).Create(data)
}

// createAgnhostPodWithSAOnNode creates a Pod in the test namespace with a single
// agnhost container and a specific ServiceAccount. The Pod will be scheduled on
// the specified Node (if nodeName is not empty).
func (data *TestData) createAgnhostPodWithSAOnNode(name string, ns string, nodeName string, hostNetwork bool, serviceAccountName string) error {
	return NewPodBuilder(name, ns, agnhostImage).OnNode(nodeName).WithCommand([]string{"sleep", "3600"}).WithHostNetwork(hostNetwork).WithServiceAccountName(serviceAccountName).Create(data)
}

func (data *TestData) createDaemonSet(name string, ns string, ctrName string, image string, cmd []string, args []string) (*appsv1.DaemonSet, func() error, error) {
	podSpec := corev1.PodSpec{
		Tolerations: controlPlaneNoScheduleTolerations(),
		// Set it to 1s for immediate shutdown to reduce test run time and to avoid affecting subsequent tests.
		TerminationGracePeriodSeconds: pointer.Int64(1),
		Containers: []corev1.Container{
			{
				Name:            ctrName,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         cmd,
				Args:            args,
			},
		},
	}
	dsSpec := appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": name,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"antrea-e2e": name,
				},
			},
			Spec: podSpec,
		},
		UpdateStrategy:       appsv1.DaemonSetUpdateStrategy{},
		MinReadySeconds:      0,
		RevisionHistoryLimit: nil,
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-e2e": name,
			},
		},
		Spec: dsSpec,
	}
	resDS, err := data.clientset.AppsV1().DaemonSets(ns).Create(context.TODO(), ds, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error {
		if err := data.clientset.AppsV1().DaemonSets(ns).Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
			return err
		}
		return nil
	}

	return resDS, cleanup, nil
}

func (data *TestData) waitForDaemonSetPods(timeout time.Duration, dsName string, namespace string) error {
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		ds, err := data.clientset.AppsV1().DaemonSets(namespace).Get(context.TODO(), dsName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if ds.Status.NumberReady != int32(clusterInfo.numNodes) {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (data *TestData) createStatefulSet(name string, ns string, size int32, ctrName string, image string, cmd []string, args []string, mutateFunc func(*appsv1.StatefulSet)) (*appsv1.StatefulSet, func() error, error) {
	podSpec := corev1.PodSpec{
		Tolerations: controlPlaneNoScheduleTolerations(),
		Containers: []corev1.Container{
			{
				Name:            ctrName,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         cmd,
				Args:            args,
			},
		},
		// Set it to 1s for immediate shutdown to reduce test run time and to avoid affecting subsequent tests.
		TerminationGracePeriodSeconds: pointer.Int64(1),
	}
	stsSpec := appsv1.StatefulSetSpec{
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": name,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"antrea-e2e": name,
				},
			},
			Spec: podSpec,
		},
		UpdateStrategy:       appsv1.StatefulSetUpdateStrategy{},
		Replicas:             &size,
		RevisionHistoryLimit: nil,
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"antrea-e2e": name,
			},
		},
		Spec: stsSpec,
	}
	mutateFunc(sts)
	resSTS, err := data.clientset.AppsV1().StatefulSets(ns).Create(context.TODO(), sts, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error {
		return data.clientset.AppsV1().StatefulSets(ns).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}

	return resSTS, cleanup, nil
}

func (data *TestData) updateStatefulSetSize(name string, ns string, size int32) (*appsv1.StatefulSet, error) {
	sts, err := data.clientset.AppsV1().StatefulSets(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	sts.Spec.Replicas = &size
	resSTS, err := data.clientset.AppsV1().StatefulSets(ns).Update(context.TODO(), sts, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return resSTS, nil
}

func (data *TestData) restartStatefulSet(name string, ns string) (*appsv1.StatefulSet, error) {
	sts, err := data.clientset.AppsV1().StatefulSets(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if sts.Spec.Template.Annotations == nil {
		sts.Spec.Template.Annotations = map[string]string{}
	}
	// Modify StatefulSet PodTemplate annotation to trigger a restart for StatefulSet Pods.
	sts.Spec.Template.Annotations[statefulSetRestartAnnotationKey] = time.Now().UTC().Format(time.RFC3339)
	resSTS, err := data.clientset.AppsV1().StatefulSets(ns).Update(context.TODO(), sts, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}
	return resSTS, nil
}

func (data *TestData) waitForStatefulSetPods(timeout time.Duration, stsName string, namespace string) error {
	err := wait.Poll(defaultInterval, timeout, func() (bool, error) {
		sts, err := data.clientset.AppsV1().StatefulSets(namespace).Get(context.TODO(), stsName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if sts.Status.ReadyReplicas != *sts.Spec.Replicas {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func isConnectionLostError(err error) bool {
	return strings.Contains(err.Error(), connectionLostError.Error())
}

// retryOnConnectionLostError allows the caller to retry fn in case the error is ConnectionLost.
// e2e script might get ConnectionLost error when accessing k8s apiserver if AntreaIPAM is enabled and antrea-agent is restarted.
func retryOnConnectionLostError(backoff wait.Backoff, fn func() error) error {
	return retry.OnError(backoff, isConnectionLostError, fn)
}

func (data *TestData) checkAntreaAgentInfo(interval time.Duration, timeout time.Duration, name string) error {
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		aai, err := data.crdClient.CrdV1beta1().AntreaAgentInfos().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("failed to get AntreaAgentInfo %s: %v", name, err)
		}
		if aai.NodeRef.Name == "" {
			// keep trying
			return false, nil
		}
		// Validate that the podRef in AntreaAgentInfo matches the name of the current Pod for the Node
		pod, err := data.clientset.CoreV1().Pods(aai.PodRef.Namespace).Get(context.TODO(), aai.PodRef.Name, metav1.GetOptions{})
		if err != nil {
			// If err is NotFound, we should keep trying
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if pod.Spec.NodeName != aai.NodeRef.Name {
			return false, fmt.Errorf("expected Node name %s for Pod %s, got %s", aai.NodeRef.Name, aai.PodRef.Name, pod.Spec.NodeName)
		}
		return true, nil
	})
	return err
}

func getPingCommand(count int, size int, os string, ip *net.IP, dontFragment bool) []string {
	countOption, sizeOption := "-c", "-s"
	if os == "windows" {
		countOption = "-n"
		sizeOption = "-l"
	}
	cmd := []string{"ping", countOption, strconv.Itoa(count)}
	if size != 0 {
		cmd = append(cmd, sizeOption, strconv.Itoa(size))
	}
	if dontFragment {
		cmd = append(cmd, "-M", "do")
	}

	if ip.To4() != nil {
		cmd = append(cmd, "-4", ip.String())
	} else {
		cmd = append(cmd, "-6", ip.String())
	}
	return cmd
}

// getCommandInFakeExternalNetwork fakes executing a command from external network by creating a netns and link the netns
// with the host network.
func getCommandInFakeExternalNetwork(cmd string, prefixLength int, externalIP string, localIP string, otherLocalIPs ...string) (string, string) {
	// Create another netns to fake an external network on the host network Pod.
	suffix := randSeq(5)
	netns := fmt.Sprintf("ext-%s", suffix)
	linkInHost := fmt.Sprintf("%s-a", netns)
	linkInNetns := fmt.Sprintf("%s-b", netns)
	cmds := []string{
		fmt.Sprintf("ip netns add %s", netns),
		fmt.Sprintf("ip link add dev %s type veth peer name %s", linkInHost, linkInNetns),
		fmt.Sprintf("ip link set dev %s netns %s", linkInNetns, netns),
		fmt.Sprintf("ip addr add %s/%d dev %s", localIP, prefixLength, linkInHost),
		fmt.Sprintf("ip link set dev %s up", linkInHost),
		fmt.Sprintf("ip netns exec %s ip addr add %s/%d dev %s", netns, externalIP, prefixLength, linkInNetns),
		fmt.Sprintf("ip netns exec %s ip link set dev %s up", netns, linkInNetns),
		fmt.Sprintf("ip netns exec %s ip route replace default via %s", netns, localIP),
	}
	for _, ip := range otherLocalIPs {
		cmds = append(cmds, fmt.Sprintf("ip addr add %s/%d dev %s", ip, prefixLength, linkInHost))
	}
	cmds = append(cmds, fmt.Sprintf("ip netns exec %s %s", netns, cmd))
	return strings.Join(cmds, " && "), netns
}

// GetPodLogs returns the current logs for the specified Pod container. If container is empty, it
// defaults to only container when there is one container in the Pod.
func (data *TestData) GetPodLogs(ctx context.Context, namespace, name, container string) (string, error) {
	req := data.clientset.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
		Container: container,
	})
	podLogs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("error when opening stream to retrieve logs for Pod '%s/%s': %w", namespace, name, err)
	}
	defer podLogs.Close()

	var b bytes.Buffer
	if _, err := io.Copy(&b, podLogs); err != nil {
		return "", fmt.Errorf("error when copying logs for Pod '%s/%s': %w", namespace, name, err)
	}
	return b.String(), nil
}
