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

package e2e

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/test/e2e/utils"
)

/*
1) Create the KIND cluster.
2) Once the cluster is up , create a service for custom DNS.
3) Configure and update Antrea configmap with above service's IP.

5) Create agnHost 2 pods (deployment?).
6) Get IP of one of the pods of agnHost.
7) create and configure the custom CoreDNS configMap with the IP received above.
8) Create a custom DNS pod and configure it to use above configMap with agnHost pod's IP.
9) Create and apply antrea FQDN policy.
10) Deploy antrea-toolbox.

11) curl the FQDN from within toolbox.
12) imitate caching the IP belonging to above FQDN resolution by keeping it in a variable.
13) change the existing IP in dns configmap with the other agnHost pod's IP.
14) wait for new IP to get updated in configMap and let the changes be reflected in dns pod.
15) curl the FQDN again with old IP , simulating usage of cache -- and it must fail with no connectivity.
*/

const (
	testFullyQualifiedDomainName = "fqdn-test-pod.lfx.test"

	customDnsServiceName = "custom-dns-service"
	customDnsConfigName  = "custom-dns-config"
	customDnsPort        = 53
	customDnsTargetPort  = 53

	customDnsImage         = "coredns/coredns:latest"
	customDnsPodName       = "custom-dns-server"
	customDnsContainerName = "coredns"
	customDnsLabelKey      = "app"
	customDnsLabelValue    = "custom-dns"
	customDnsVolume        = "config-volume"

	fqdnPolicyName            = "test-anp-fqdn"
	fqdnPodSelectorLabelKey   = "app"
	fqdnPodSelectorLabelValue = "fqdn-cache-test"
	toolBoxPodName            = "toolbox"

	agnHostPort          = 80
	agnHostLabelKey      = "app"
	agnHostLabelValue    = "agnhost"
	agnHostPodNamePreFix = "agnhost-"
)

func TestFQDNPolicyWithCachedDNS(t *testing.T) {
	skipIfAntreaPolicyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardown(t, data)

	ipFamily := corev1.IPv4Protocol
	customDnsService, err := data.CreateServiceWithAnnotations(customDnsServiceName, data.testNamespace, customDnsPort, customDnsTargetPort, corev1.ProtocolUDP,
		map[string]string{customDnsLabelKey: customDnsLabelValue}, false, false, corev1.ServiceTypeClusterIP, &ipFamily, map[string]string{})
	require.NoError(t, err, "Error when creating custom DNS service: %v", err)

	setDnsServerAddressInAntrea(t, data, customDnsService.Spec.ClusterIP)

	// I think creating 2 pods with a deployment might be better.
	createHttpAgnhostPod(t, data, randName(agnHostPodNamePreFix), map[string]string{agnHostLabelKey: agnHostLabelValue})
	createHttpAgnhostPod(t, data, randName(agnHostPodNamePreFix), map[string]string{agnHostLabelKey: agnHostLabelValue})

	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "error getting k8s utils %+v", err)

	agnHostPods, err := k8sUtils.GetPodsByLabel(data.testNamespace, agnHostLabelKey, agnHostLabelValue)
	require.NoError(t, err, "error getting Pods by label  %+v", err)

	//domainMapping holds whether the IP is mapped to Domain or not.
	domainMapping := make(map[string]bool)

	// pick an IP to be added in config
	var ipForDnsConfig string
	for idx, pod := range agnHostPods {
		ipStr := strings.TrimSpace(pod.Status.PodIP)
		domainMapping[ipStr] = false
		//pick last IP for config
		if idx == len(agnHostPods)-1 {
			ipForDnsConfig = ipStr
		}
	}

	dnsConfigData := createDnsConfig(ipForDnsConfig)

	customDnsConfigMapObject, err := data.CreateConfigMap(data.testNamespace, customDnsConfigName, dnsConfigData, nil, false)
	require.NoError(t, err, "failed to create custom dns ConfigMap: %v", err)
	domainMapping[ipForDnsConfig] = true

	createDnsPod(t, data)

	_ = buildFqdnPolicy(t, data)

	createToolBoxPod(t, data, customDnsService.Spec.ClusterIP)

	curlFqdn := func(podName, containerName, fqdn string) error {
		t.Logf("trying to curl the fqdn %v", fqdn)
		cmd := []string{"curl", fqdn}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
				strings.Join(cmd, " "), podName, err, stdout, stderr)
		}
		return nil
	}

	err = curlFqdn(toolBoxPodName, toolboxContainerName, testFullyQualifiedDomainName)
	require.NoError(t, err, "failed to curl FQDN from antrea toolbox on initial run : %v", err)

	// DIG to get actual IP , to be sure.
	digResponse, err := k8sUtils.runDNSQuery(toolBoxPodName, toolboxContainerName, data.testNamespace, testFullyQualifiedDomainName, false, customDnsService.Spec.ClusterIP)
	require.NoError(t, err, "failed to get IP of FQDN using DIG from toolbox pod : %v", err)
	fqdnIp := digResponse.String()

	t.Logf("received ip using dig for test fqdn %+v ", fqdnIp)

	var newIP string
	for ip, mapped := range domainMapping {
		if ip != fqdnIp && mapped == false {
			newIP = ip
		}
	}

	t.Logf("New IP to update to DNS %v", newIP)

	// Curl the old ip and it should be a success.
	err = curlFqdn(toolBoxPodName, toolboxContainerName, fqdnIp)
	require.NoError(t, err, "failed to curl FQDN from antrea toolbox on initial run : %v", err)

	// Update the custom DNS configMap
	UpdatedCustomDNSconfig := createDnsConfig(newIP)

	customDnsConfigMapObject.Data = UpdatedCustomDNSconfig
	err = data.UpdateConfigMap(customDnsConfigMapObject)
	require.NoError(t, err, "failed to update configmap with new IP : %v", err)
	t.Logf("successfully updated dns configMap with new IP : %+v", newIP)

	updateDnsPodAnnotations(t, data)

	for {
		err = curlFqdn(toolBoxPodName, toolboxContainerName, fqdnIp)
		require.NoError(t, err, "curl to ip failed with error : %v", err)

		// Wait for 1 second before retrying
		time.Sleep(1 * time.Second)
	}

}

func setDnsServerAddressInAntrea(t *testing.T, data *TestData, dnsServiceIP string) {
	var agentConf agentconfig.AgentConfig
	cm, err := data.GetAntreaConfigMap(antreaNamespace)
	require.NoError(t, err, "Error when getting antrea configMap : %v", err)

	err = yaml.Unmarshal([]byte(cm.Data["antrea-agent.conf"]), &agentConf)
	require.NoError(t, err, "failed to unmarshal antrea agent config from ConfigMap: %v", err)

	agentChanges := func(config *agentconfig.AgentConfig) {
		config.DNSServerOverride = dnsServiceIP
	}
	err = data.mutateAntreaConfigMap(nil, agentChanges, false, true)
	require.NoError(t, err, "Error when setting up customDNS server IP in Antrea configmap : %v", err)

	t.Logf("dns server value set to %+v in antrea \n", dnsServiceIP)

}

func createDnsConfig(ipForConfig string) map[string]string {
	config := fmt.Sprintf(`lfx.test:53 {
    errors
    health
    hosts {
        %s %s
        no_reverse
        pods verified
        ttl 10
    }
    loop
    reload
}`, ipForConfig, testFullyQualifiedDomainName)

	configData := map[string]string{
		"Corefile": config,
	}

	return configData
}

func createDnsPod(t *testing.T, data *TestData) {
	volume := []corev1.Volume{
		{
			Name: customDnsVolume,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: customDnsConfigName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "Corefile",
							Path: "Corefile",
						},
					},
				},
			},
		},
	}

	volumeMount := []corev1.VolumeMount{
		{
			Name:      customDnsVolume,
			MountPath: "/etc/coredns",
		},
	}

	label := map[string]string{customDnsLabelKey: customDnsLabelValue}
	pb := NewPodBuilder(customDnsPodName, data.testNamespace, customDnsImage)
	pb.WithLabels(label)
	pb.WithAnnotations(map[string]string{"Foo": "Bar"})
	pb.WithContainerName(customDnsContainerName)
	pb.WithArgs([]string{"-conf", "/etc/coredns/Corefile"})
	pb.AddVolume(volume)
	pb.AddVolumeMount(volumeMount)

	require.NoError(t, pb.Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, customDnsPodName, data.testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, customDnsPodName, data.testNamespace))

}

func buildFqdnPolicy(t *testing.T, data *TestData) *utils.AntreaNetworkPolicySpecBuilder {
	podSelectorLabel := map[string]string{
		fqdnPodSelectorLabelKey: fqdnPodSelectorLabelValue,
	}
	port := int32(80)
	udpPort := int32(53)
	builder := &utils.AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(data.testNamespace, fqdnPolicyName).
		SetTier(defaultTierName).
		SetPriority(1.0).
		SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: podSelectorLabel}})
	builder.AddFQDNRule(testFullyQualifiedDomainName, utils.ProtocolTCP, &port, nil, nil, "AllowForFQDN", nil,
		crdv1beta1.RuleActionAllow)
	builder.AddEgress(utils.ProtocolUDP, &udpPort, nil, nil, nil, nil,
		nil, nil, nil, nil, map[string]string{customDnsLabelKey: customDnsLabelValue},
		nil, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionAllow, "", "AllowDnsQueries")
	builder.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionReject, "", "DropAllRemainingTraffic")

	annp, err := k8sUtils.CreateOrUpdateANNP(builder.Get())
	require.NoError(t, err, "error while deploying antrea policy %+v", err)
	failOnError(err, t)
	failOnError(waitForResourceReady(t, 30*time.Second, annp), t)

	return builder
}

func createToolBoxPod(t *testing.T, data *TestData, dnsServiceIP string) {
	toolBoxLabel := map[string]string{fqdnPodSelectorLabelKey: fqdnPodSelectorLabelValue}
	pb := NewPodBuilder(toolBoxPodName, data.testNamespace, ToolboxImage)
	pb.WithLabels(toolBoxLabel)
	pb.WithContainerName(toolboxContainerName)
	mutateSpecForAddingCustomDNS := func(pod *corev1.Pod) {
		pod.Spec.DNSPolicy = corev1.DNSNone
		if pod.Spec.DNSConfig == nil {
			pod.Spec.DNSConfig = &corev1.PodDNSConfig{}
		}
		pod.Spec.DNSConfig.Nameservers = []string{dnsServiceIP}

	}
	pb.WithMutateFunc(mutateSpecForAddingCustomDNS)
	require.NoError(t, pb.Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, toolBoxPodName, data.testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, toolBoxPodName, data.testNamespace))
}

func updateDnsPodAnnotations(t *testing.T, data *TestData) {
	dnsPod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), customDnsPodName, metav1.GetOptions{})
	require.NoError(t, err, "Error getting DNS pod for annotation update.")

	if dnsPod.Annotations == nil {
		dnsPod.Annotations = make(map[string]string)
	}
	dnsPod.Annotations["Bar"] = "Foo"
	delete(dnsPod.Annotations, "Foo")

	updatedPod, err := data.clientset.CoreV1().Pods(data.testNamespace).Update(context.TODO(), dnsPod, metav1.UpdateOptions{})
	require.NoError(t, err, "error updating dns pod annotations.")

	t.Logf("updated dns pod annotations %+v\n", updatedPod.Annotations)
}

func createHttpAgnhostPod(t *testing.T, data *TestData, podName string, agnLabels map[string]string) {
	args := []string{"netexec", "--http-port=" + strconv.Itoa(agnHostPort)}
	ports := []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: agnHostPort,
			Protocol:      corev1.ProtocolTCP,
		},
	}

	require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).WithArgs(args).WithPorts(ports).WithLabels(agnLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, data.testNamespace))
}

func teardown(t *testing.T, data *TestData) {
	// delete the namespace, hence removing all resources attached to it.
	// Also remove the dnsServerOverRide value.
	exportLogs(t, data, "beforeTeardown", true)
	if empty, _ := IsDirEmpty(data.logsDirForTestCase); empty {
		_ = os.Remove(data.logsDirForTestCase)
	}
	t.Logf("Deleting '%s' K8s Namespace", testData.testNamespace)
	if err := data.DeleteNamespace(testData.testNamespace, -1); err != nil {
		t.Logf("Error when tearing down test: %v", err)
	}
	setDnsServerAddressInAntrea(t, data, "")
}
