// Copyright 2020 Antrea Authors
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

package usagereport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/controller/usagereport/api"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/pkg/util/env"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

const (
	defaultServerURL          = "https://telemetry.antrea.io/report"
	defaultReportInterval     = 24 * time.Hour
	defaultReportInitialDelay = 30 * time.Minute
	defaultAntreaNamespace    = "kube-system"
	uuidConfigMapName         = "antrea-cluster-uuid"
	uuidConfigMapKey          = "uuid"
)

type agentConfig struct {
	FeatureGates            map[string]bool `yaml:"featureGates,omitempty"`
	OVSDatapathType         string          `yaml:"ovsDatapathType,omitempty"`
	TrafficEncapMode        string          `yaml:"trafficEncapMode,omitempty"`
	NoSNAT                  bool            `yaml:"noSNAT,omitempty"`
	TunnelType              string          `yaml:"tunnelType,omitempty"`
	EnableIPSecTunnel       bool            `yaml:"enableIPSecTunnel,omitempty"`
	EnablePrometheusMetrics bool            `yaml:"enablePrometheusMetrics,omitempty"`
}

type controllerConfig struct {
	FeatureGates            map[string]bool `yaml:"featureGates,omitempty"`
	EnablePrometheusMetrics bool            `yaml:"enablePrometheusMetrics,omitempty"`
}

// TODO: avoid duplicating defaults from cmd package

var (
	agentConfigDefaults = agentConfig{
		OVSDatapathType:         "system",
		TrafficEncapMode:        "encap",
		NoSNAT:                  false,
		TunnelType:              "geneve",
		EnableIPSecTunnel:       false,
		EnablePrometheusMetrics: true,
	}
	controllerConfigDefaults = controllerConfig{
		EnablePrometheusMetrics: true,
	}
)

type ReporterConfig struct {
	ServerURL           string
	ReportInterval      time.Duration
	ReportInitialDelay  time.Duration
	AntreaNamespace     string
	AntreaConfigMapName string
}

type Reporter struct {
	ReporterConfig
	k8sClient        clientset.Interface
	clusterUUID      uuid.UUID
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	// networkPolicyUsageReporter is an interface pointer to the Antrea
	// NetworkPolicyController. It is useful to retrieve some stats about the cluster, which are
	// already available to the Controller, without having to duplicate all the informers
	// here. In the future, it may also be useful to provide more advanced stats, based on the
	// objects computed by the Controller.
	networkPolicyUsageReporter networkpolicy.NetworkPolicyUsageReporter
	antreaDeploymentTime       time.Time
}

func NewReporter(
	k8sClient clientset.Interface,
	nodeInformer coreinformers.NodeInformer,
	networkPolicyUsageReporter networkpolicy.NetworkPolicyUsageReporter,
	configFns ...func(*ReporterConfig),
) *Reporter {
	config := ReporterConfig{
		ServerURL:          defaultServerURL,
		ReportInterval:     defaultReportInterval,
		ReportInitialDelay: defaultReportInitialDelay,
	}
	for _, fn := range configFns {
		fn(&config)
	}
	r := &Reporter{
		ReporterConfig:             config,
		k8sClient:                  k8sClient,
		nodeInformer:               nodeInformer,
		nodeLister:                 nodeInformer.Lister(),
		nodeListerSynced:           nodeInformer.Informer().HasSynced,
		networkPolicyUsageReporter: networkPolicyUsageReporter,
	}
	return r
}

func (r *Reporter) getNodes() ([]api.NodeInfo, error) {
	nodes, err := r.nodeLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("error when listing all Nodes: %v", err)
	}

	nodesInfo := make([]api.NodeInfo, 0, len(nodes))
	for _, node := range nodes {
		var hasIPv4Address, hasIPv6Address bool
		for _, addr := range node.Status.Addresses {
			if addr.Type != corev1.NodeInternalIP {
				continue
			}
			ip := net.ParseIP(addr.Address)
			if ip != nil {
				hasIPv4Address = hasIPv4Address || (ip.To4() != nil)
				hasIPv6Address = hasIPv6Address || (ip.To4() == nil)
			}
		}
		i := &node.Status.NodeInfo
		nodesInfo = append(nodesInfo, api.NodeInfo{
			KernelVersion:           i.KernelVersion,
			OSImage:                 i.OSImage,
			ContainerRuntimeVersion: i.ContainerRuntimeVersion,
			KubeletVersion:          i.KubeletVersion,
			KubeProxyVersion:        i.KubeProxyVersion,
			OperatingSystem:         i.OperatingSystem,
			Architecture:            i.Architecture,
			HasIPv4Address:          hasIPv4Address,
			HasIPv6Address:          hasIPv6Address,
		})
	}
	return nodesInfo, nil
}

func (r *Reporter) getK8sAPIVersion() (string, error) {
	serverVersion, err := r.k8sClient.Discovery().ServerVersion()
	if err != nil {
		return "", err
	}
	return serverVersion.String(), nil
}

func (r *Reporter) getAntreaConfig() (*api.AgentConfig, *api.ControllerConfig, error) {
	configMap, err := r.k8sClient.CoreV1().ConfigMaps(r.AntreaNamespace).Get(context.TODO(), r.AntreaConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("error when getting ConfigMap \"%s/%s\": %v", r.AntreaNamespace, r.AntreaConfigMapName, err)
	}
	addDefaultFeatureGates := func(featureGates map[string]bool) []api.FeatureGate {
		r := make([]api.FeatureGate, 0)
		for feature, spec := range features.DefaultAntreaFeatureGates {
			if enabled, ok := featureGates[string(feature)]; ok {
				r = append(r, api.FeatureGate{Name: string(feature), Enabled: enabled})
			} else {
				r = append(r, api.FeatureGate{Name: string(feature), Enabled: spec.Default})
			}
		}
		return r
	}

	agentConfigIn := agentConfigDefaults
	if err := yaml.Unmarshal([]byte(configMap.Data["antrea-agent.conf"]), &agentConfigIn); err != nil {
		return nil, nil, fmt.Errorf("error when unmarshalling Agent configuration: %v", err)
	}
	agentConfigOut := api.AgentConfig{
		FeatureGates:            addDefaultFeatureGates(agentConfigIn.FeatureGates),
		OVSDatapathType:         agentConfigIn.OVSDatapathType,
		TrafficEncapMode:        agentConfigIn.TrafficEncapMode,
		NoSNAT:                  agentConfigIn.NoSNAT,
		TunnelType:              agentConfigIn.TunnelType,
		EnableIPSecTunnel:       agentConfigIn.EnableIPSecTunnel,
		EnablePrometheusMetrics: agentConfigIn.EnablePrometheusMetrics,
	}

	controllerConfigIn := controllerConfigDefaults
	if err := yaml.Unmarshal([]byte(configMap.Data["antrea-controller.conf"]), &controllerConfigIn); err != nil {
		return nil, nil, fmt.Errorf("error when unmarshalling Controller configuration: %v", err)
	}
	controllerConfigOut := api.ControllerConfig{
		FeatureGates:            addDefaultFeatureGates(controllerConfigIn.FeatureGates),
		EnablePrometheusMetrics: controllerConfigIn.EnablePrometheusMetrics,
	}

	return &agentConfigOut, &controllerConfigOut, nil
}

func (r *Reporter) getPrimaryIPFamily() (api.IPFamily, error) {
	k8sServiceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	if k8sServiceHost == "" {
		return api.IPFamilyIPv4, fmt.Errorf("KUBERNETES_SERVICE_HOST is not set")
	}
	ip := net.ParseIP(k8sServiceHost)
	if ip == nil {
		return api.IPFamilyIPv4, fmt.Errorf("KUBERNETES_SERVICE_HOST is not a valid IP")
	}
	if ip.To4() != nil {
		return api.IPFamilyIPv4, nil
	}
	return api.IPFamilyIPv6, nil
}

func (r *Reporter) getK8sDistribution() api.K8sDistributionName {
	// TODO: support more distributions
	switch {
	case env.IsCloudAKS():
		return api.K8sDistributionAKS
	case env.IsCloudEKS():
		return api.K8sDistributionEKS
	case env.IsCloudGKE():
		return api.K8sDistributionGKE
	default:
		return api.K8sDistributionUnknown
	}
}

func (r *Reporter) generateReport() *api.UsageReport {
	nodesInfo, err := r.getNodes()
	var numNodesPtr *int32
	if err != nil {
		klog.V(2).Infof("Could not get system info for Nodes, omitting in report: %v", err)
	} else {
		numNodesPtr = new(int32)
		*numNodesPtr = int32(len(nodesInfo))
	}
	k8sVersion, err := r.getK8sAPIVersion()
	if err != nil {
		klog.V(2).Infof("Could not get K8s API version, omitting in report: %v", err)
	}
	agentConfig, controllerConfig, err := r.getAntreaConfig()
	if err != nil {
		klog.V(2).Infof("Could not get Agent and Controller configs, omitting in report: %v", err)
	}

	var hasIPv4Address, hasIPv6Address bool
	for _, node := range nodesInfo {
		hasIPv4Address = hasIPv4Address || node.HasIPv4Address
		hasIPv6Address = hasIPv6Address || node.HasIPv6Address
	}
	primaryIPFamily, err := r.getPrimaryIPFamily()
	var ipFamilies []api.IPFamily
	if err != nil {
		klog.V(2).Infof("Could not determine primary IP family for cluster, will default to IPv4 in report if enabled: %v", err)
		if hasIPv4Address {
			ipFamilies = append(ipFamilies, api.IPFamilyIPv4)
		}
		if hasIPv6Address {
			ipFamilies = append(ipFamilies, api.IPFamilyIPv6)
		}
	} else {
		switch {
		case hasIPv4Address && hasIPv6Address && primaryIPFamily == api.IPFamilyIPv4:
			ipFamilies = []api.IPFamily{api.IPFamilyIPv4, api.IPFamilyIPv6}
		case hasIPv4Address && hasIPv6Address && primaryIPFamily == api.IPFamilyIPv6:
			ipFamilies = []api.IPFamily{api.IPFamilyIPv6, api.IPFamilyIPv4}
		case hasIPv4Address && primaryIPFamily == api.IPFamilyIPv4:
			ipFamilies = []api.IPFamily{api.IPFamilyIPv4}
		case hasIPv6Address && primaryIPFamily == api.IPFamilyIPv6:
			ipFamilies = []api.IPFamily{api.IPFamilyIPv6}
		default:
			klog.V(2).Infof("Encountered invalid case when determining cluster IP families")
		}
	}

	var numNamespacesPtr *int32
	numNamespaces, err := r.networkPolicyUsageReporter.GetNumNamespaces()
	if err != nil {
		klog.V(2).Infof("Could not get Namespace count, omitting in report: %v", err)
		numNamespacesPtr = new(int32)
		*numNamespacesPtr = int32(numNamespaces)
	}
	var numPodsPtr *int32
	numPods, err := r.networkPolicyUsageReporter.GetNumPods()
	if err != nil {
		klog.V(2).Infof("Could not get Pod count, omitting in report: %v", err)
	} else {
		numPodsPtr = new(int32)
		*numPodsPtr = int32(numPods)
	}
	var numTiersPtr *int32
	numTiers, err := r.networkPolicyUsageReporter.GetNumTiers()
	if err != nil {
		klog.V(2).Infof("Could not get Tier count, omitting in report: %v", err)
	} else {
		numTiersPtr = new(int32)
		*numTiersPtr = int32(numTiers)
	}
	var numNetworkPoliciesPtr *int32
	numNetworkPolicies, err := r.networkPolicyUsageReporter.GetNumNetworkPolicies()
	if err != nil {
		klog.V(2).Infof("Could not get NetworkPolicy count, omitting in report: %v", err)
	} else {
		numNetworkPoliciesPtr = new(int32)
		*numNetworkPoliciesPtr = int32(numNetworkPolicies)
	}
	var numAntreaNetworkPoliciesPtr *int32
	numAntreaNetworkPolicies, err := r.networkPolicyUsageReporter.GetNumAntreaNetworkPolicies()
	if err != nil {
		klog.V(2).Infof("Could not get AntreaNetworkPolicy count, omitting in report: %v", err)
	} else {
		numAntreaNetworkPoliciesPtr = new(int32)
		*numAntreaNetworkPoliciesPtr = int32(numAntreaNetworkPolicies)
	}
	var numAntreaClusterNetworkPoliciesPtr *int32
	numAntreaClusterNetworkPolicies, err := r.networkPolicyUsageReporter.GetNumAntreaClusterNetworkPolicies()
	if err != nil {
		klog.V(2).Infof("Could not get AntreaClusterNetworkPolicy count, omitting in report: %v", err)
	} else {
		numAntreaClusterNetworkPoliciesPtr = new(int32)
		*numAntreaClusterNetworkPoliciesPtr = int32(numAntreaClusterNetworkPolicies)
	}

	k8sDistribution := r.getK8sDistribution()

	return &api.UsageReport{
		ClusterUUID:      r.clusterUUID.String(),
		Version:          version.Version,
		FullVersion:      version.GetFullVersion(),
		IsReleased:       version.ReleaseStatus == "released",
		AgentConfig:      agentConfig,
		ControllerConfig: controllerConfig,
		ClusterInfo: api.ClusterInfo{
			K8sVersion:      k8sVersion,
			K8sDistribution: k8sDistribution,
			NumNodes:        numNodesPtr,
			Nodes:           nodesInfo,
			NumNamespaces:   numNamespacesPtr,
			NumPods:         numPodsPtr,
			NetworkPolicies: api.NetworkPolicyInfo{
				NumTiers:                        numTiersPtr,
				NumNetworkPolicies:              numNetworkPoliciesPtr,
				NumAntreaNetworkPolicies:        numAntreaNetworkPoliciesPtr,
				NumAntreaClusterNetworkPolicies: numAntreaClusterNetworkPoliciesPtr,
			},
			IPFamilies: ipFamilies,
		},
		AntreaDeploymentTime: r.antreaDeploymentTime,
	}
}

func (r *Reporter) sendReport() error {
	report := r.generateReport()

	url := r.ServerURL
	jsonBytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("error when marshalling JSON report: %v", err)
	}
	klog.V(4).Infof("Usage report has size %d bytes", len(jsonBytes))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return fmt.Errorf("error when building HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error when posting JSON report to \"%s\": %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error when posting JSON report to \"%s\": %v", url, err)
	}

	return nil
}

func (r *Reporter) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting usage reporter")

	if !cache.WaitForNamedCacheSync("usage reporter", stopCh, r.nodeListerSynced) {
		return
	}

	// useful for unit tests, to avoid warnings
	if r.AntreaNamespace == "" {
		namespace := env.GetPodNamespace()
		if namespace == "" {
			klog.Warningf("Failed to get Pod Namespace from environment; using \"%s\" as the ConfigMap Namespace", defaultAntreaNamespace)
			namespace = defaultAntreaNamespace
		}
		r.AntreaNamespace = namespace
	}

	// useful for unit tests, to support defining an arbitrary  test ConfigMap
	if r.AntreaConfigMapName == "" {
		r.AntreaConfigMapName = env.GetAntreaConfigMapName()
		if r.AntreaConfigMapName == "" {
			klog.Warningf("Failed to get Antrea ConfigMap name from environment; some information will be missing from usage reports")
		}
	}

	// TODO: access to the cluster UUID may be useful to other parts of Antrea, consider moving
	// it out of the usage reporting code.

	retryInterval := time.Second
	var configMap *corev1.ConfigMap
	wait.PollImmediateUntil(time.Second, func() (bool, error) {
		var err error
		configMap, err = r.k8sClient.CoreV1().ConfigMaps(r.AntreaNamespace).Get(context.TODO(), uuidConfigMapName, metav1.GetOptions{})
		if err != nil {
			klog.Warningf("Error when getting ConfigMap \"%s\": %v - retrying in %v", uuidConfigMapName, err, retryInterval)
			return false, nil
		}
		return true, nil
	}, stopCh)

	if configMap == nil { // stopCh was closed
		return
	}

	r.antreaDeploymentTime = configMap.CreationTimestamp.Time

	clusterUUID, ok := configMap.Data[uuidConfigMapKey]
	if !ok || clusterUUID == "" {
		r.clusterUUID = uuid.New()
		klog.Infof("Persisting cluster UUID \"%s\" to ConfigMap \"%s\"", r.clusterUUID, uuidConfigMapName)
		configMap.Data = map[string]string{uuidConfigMapKey: r.clusterUUID.String()}
		if _, err := r.k8sClient.CoreV1().ConfigMaps(r.AntreaNamespace).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
			klog.Errorf("Error when persisting cluster UUID \"%s\" to ConfigMap \"%s\": %v", r.clusterUUID, uuidConfigMapName, err)
		}
	} else {
		var err error
		r.clusterUUID, err = uuid.Parse(clusterUUID)
		if err != nil {
			klog.Errorf("Error when parsing cluster UUID stored in ConfigMap \"%s\": %v", uuidConfigMapName, err)
		}
		klog.Infof("Retrieved cluster UUID \"%s\" from ConfigMap \"%s\"", r.clusterUUID, uuidConfigMapName)
	}

	klog.V(2).Infof("Waiting for %v before sending first usage report", r.ReportInitialDelay)
	time.Sleep(r.ReportInitialDelay)

	wait.Until(func() {
		klog.V(2).Infof("Sending usage report")
		if err := r.sendReport(); err != nil {
			klog.V(2).Infof("Error when sending usage report: %v", err)
			return
		}
		klog.V(2).Infof("Usage report sent successfully")
	}, r.ReportInterval, stopCh)
}
