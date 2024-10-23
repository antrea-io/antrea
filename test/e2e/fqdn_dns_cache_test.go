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
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

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

// agnHostPodIpv4Addresses type stores the IPv4 addresses of the 2 agnHost pods created for the test.
type agnHostPodIpv4Addresses struct {
	pod1Ipv4 string
	pod2Ipv4 string
}

func TestFQDNPolicyWithCachedDNS(t *testing.T) {
	const testFQDN = "fqdn-test-pod.lfx.test"

	skipIfAntreaPolicyDisabled(t)
	skipIfNotIPv4Cluster(t)
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	dnsServiceIP := setCustomDnsServerAddressInAntrea(t, data, false)
	defer setCustomDnsServerAddressInAntrea(t, data, true)

	agnHostPodIp := createAgnHostPods(t, data)

	customDnsConfigMap, err := createAndDeployCustomDnsConfigMap(t, data, agnHostPodIp.pod1Ipv4, testFQDN)
	require.NoError(t, err, "failed to create custom dns ConfigMap: %v", err)

	createDnsPod(t, data)
	createFqdnPolicyInNamespace(t, data, testFQDN)

	t.Logf("Creating Toolbox pod...")
	createToolBoxPod(t, data, dnsServiceIP)

	fqdnIp, err := curlAndVerifyFQDN(t, data, testFQDN, dnsServiceIP)
	require.NoError(t, err, "failed to resolve FQDN to an IP from toolbox pod : %v", err)
	require.Equalf(t, agnHostPodIp.pod1Ipv4, fqdnIp, "The IP set against the FQDN in the DNS server should be the same, but got %s instead of %s", fqdnIp, agnHostPodIp.pod1Ipv4)

	t.Logf("Successfully received the expected IP %s using the dig command against the FQDN", fqdnIp)

	t.Logf("New IP to update to DNS | ipv4 : %s", agnHostPodIp.pod2Ipv4)
	err = updateCustomDnsConfigMap(t, data, agnHostPodIp.pod2Ipv4, testFQDN, customDnsConfigMap)
	require.NoError(t, err, "failed to update configmap with new IP : %v", err)
	t.Logf("successfully updated dns configMap with new IPs | ipv4 : %s", agnHostPodIp.pod2Ipv4)

	require.NoError(t, data.setPodAnnotation(data.testNamespace, "custom-dns-server", randomPatchAnnotationKey,
		randSeq(annotationValueLen)), "failed to update custom dns pod annotation.")

	cachedIpTest(t, fqdnIp, data)
}

// createAgnHostPods creates two agnHost pods and returns their IPv4 addresses filled in agnHostPodIpv4Addresses type.
func createAgnHostPods(t *testing.T, data *TestData) *agnHostPodIpv4Addresses {
	const agnHostPodNamePreFix = "agnhost-"

	var agnHostPodIpv4AddressesObj agnHostPodIpv4Addresses

	podCount := 2
	agnHostPodIps := make([]*PodIPs, podCount)
	for i := 0; i < podCount; i++ {
		agnHostPodIps[i] = createHttpAgnhostPod(t, data, randName(agnHostPodNamePreFix), map[string]string{"app": "agnhost"})
	}

	agnHostPodIpv4AddressesObj.pod1Ipv4, _ = agnHostPodIps[0].AsStrings()
	agnHostPodIpv4AddressesObj.pod2Ipv4, _ = agnHostPodIps[1].AsStrings()

	return &agnHostPodIpv4AddressesObj
}

// curlTarget runs a curl command from a specified pod to the given FQDN and returns the output.
func curlTarget(podName, containerName, fqdn string, data *TestData) (string, error) {
	cmd := []string{"curl", fqdn}
	stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
	if err != nil {
		return "", fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
			strings.Join(cmd, " "), podName, err, stdout, stderr)
	}
	return stdout, nil
}

// cachedIpTest verifies that curling the previously cached IP fails after DNS update.
func cachedIpTest(t *testing.T, fqdnIp string, data *TestData) {
	assert.Eventually(t, func() bool {
		t.Logf("Trying to curl the existing cached IP of the domain - %v", fqdnIp)
		stdout, err := curlTarget(toolboxPodName, toolboxContainerName, fqdnIp, data)
		if err != nil {
			t.Logf("The test failed because of error :  %+v", err)
		} else {
			t.Logf("response of curl to cached IP - %+v", stdout)
		}
		return assert.Error(t, err)
	}, 20*time.Second, 1*time.Second)
}

// curlAndVerifyFQDN curls the specified FQDN and verifies its resolution to the expected IP.
func curlAndVerifyFQDN(t *testing.T, data *TestData, testFQDN string, dnsServiceIP string) (string, error) {
	t.Logf("Trying to curl FQDN ...")
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		stdout, err := curlTarget(toolboxPodName, toolboxContainerName, testFQDN, data)
		assert.NoError(t, err)
		t.Logf("response of curl to FQDN - %s", stdout)
	}, 2*time.Second, 100*time.Millisecond, "trying to curl the fqdn : ", testFQDN)

	t.Logf("Resolving FQDN to simulate caching the current IP inside Toolbox pod...")
	resolvedIP, err := data.runDNSQuery(toolboxPodName, toolboxContainerName, data.testNamespace, testFQDN, false, dnsServiceIP)

	if err != nil {
		return "", err
	}

	return resolvedIP.String(), nil
}

// createAndDeployCustomDnsConfigMap creates and deploys the custom DNS ConfigMap with the specified IP and FQDN.
func createAndDeployCustomDnsConfigMap(t *testing.T, data *TestData, ipv4 string, testFQDN string) (*corev1.ConfigMap, error) {
	const customDnsConfigName = "custom-dns-config"
	dnsConfigData := createDnsConfig(t, ipv4, testFQDN)
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      customDnsConfigName,
			Namespace: data.testNamespace,
		},
		Data: dnsConfigData,
	}
	return data.CreateConfigMap(configMap)

}

// updateCustomDnsConfigMap updates the existing custom DNS ConfigMap with a new IP for the specified FQDN.
func updateCustomDnsConfigMap(t *testing.T, data *TestData, ipv4 string, testFullyQualifiedDomainName string, customDnsConfigMap *corev1.ConfigMap) error {
	customDnsConfigMap.Data = createDnsConfig(t, ipv4, testFullyQualifiedDomainName)
	return data.UpdateConfigMap(customDnsConfigMap)
}

// setCustomDnsServerAddressInAntrea sets or resets the custom DNS server IP address in Antrea configMap.
func setCustomDnsServerAddressInAntrea(t *testing.T, data *TestData, teardown bool) string {
	var dnsServiceIP string

	// Create or reset DNS service based on teardown flag
	if !teardown {
		var err error
		dnsServiceIP, err = createCustomDnsService(data)
		require.NoError(t, err, "Error when creating custom DNS service: %v", err)
	}

	err := updateAntreaConfigMap(data, dnsServiceIP)
	require.NoError(t, err, "Error when updating Antrea configmap with custom dns ip : %v", err)

	if teardown {
		t.Logf("removing dns server IP from antrea agent during teardown")
		return ""
	}
	t.Logf("Set DNS server IP in Antrea : %s", dnsServiceIP)
	return dnsServiceIP
}

// updateAntreaConfigMap updates the Antrea configuration with the specified DNS server IP.
func updateAntreaConfigMap(data *TestData, dnsServiceIP string) error {
	agentChanges := func(config *agentconfig.AgentConfig) {
		config.DNSServerOverride = dnsServiceIP
	}
	return data.mutateAntreaConfigMap(nil, agentChanges, false, true)
}

// createCustomDnsService creates the custom DNS service and returns its ClusterIP as ipv4 address.
func createCustomDnsService(data *TestData) (string, error) {
	const dnsPort = 53
	customDnsService, err := data.CreateServiceWithAnnotations("custom-dns-service", data.testNamespace, dnsPort,
		dnsPort, corev1.ProtocolUDP, map[string]string{"app": "custom-dns"}, false,
		false, corev1.ServiceTypeClusterIP, ptr.To[corev1.IPFamily](corev1.IPv4Protocol), map[string]string{})
	if err != nil {
		return "", err
	}
	return customDnsService.Spec.ClusterIP, nil

}

// createDnsConfig generates a DNS configuration for the specified IP address and domain name.
func createDnsConfig(t *testing.T, ipv4Address, domainName string) map[string]string {
	const coreFileTemplate = `lfx.test:53 {
        errors
        log
        health
        hosts {
            {{ if .IPv4 }}{{ .IPv4 }} {{ $.FQDN }}{{ end }}
            no_reverse
            pods verified
            ttl 10
        }
        loop
        reload
    }`

	generateConfigData := func() (string, error) {
		data := struct {
			IPv4 string
			FQDN string
		}{
			IPv4: ipv4Address,
			FQDN: domainName,
		}

		tmpl, err := template.New("configMapData").Parse(coreFileTemplate)
		if err != nil {
			return "", err
		}
		var output bytes.Buffer
		err = tmpl.Execute(&output, data)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(output.String()), nil
	}

	configMapData, err := generateConfigData()
	require.NoError(t, err, "error processing configData template for DNS, ", err)
	configData := map[string]string{
		"Corefile": configMapData,
	}

	return configData
}

// createDnsPod creates the CoreDNS pod configured to use the custom DNS ConfigMap.
func createDnsPod(t *testing.T, data *TestData) {
	const customDnsImage = "coredns/coredns:1.11.3"

	volume := []corev1.Volume{
		{
			Name: "config-volume",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "custom-dns-config",
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
			Name:      "config-volume",
			MountPath: "/etc/coredns",
		},
	}

	require.NoError(t, NewPodBuilder("custom-dns-server", data.testNamespace, customDnsImage).
		WithLabels(map[string]string{"app": "custom-dns"}).
		WithContainerName("coredns").
		WithArgs([]string{"-conf", "/etc/coredns/Corefile"}).
		AddVolume(volume).AddVolumeMount(volumeMount).
		WithAnnotations(map[string]string{randomPatchAnnotationKey: randSeq(annotationValueLen)}).
		Create(data))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "custom-dns-server", data.testNamespace))
}

// createFqdnPolicyInNamespace creates an FQDN policy in the specified namespace.
func createFqdnPolicyInNamespace(t *testing.T, data *TestData, testFQDN string) {
	const (
		fqdnPolicyName            = "test-anp-fqdn"
		customDnsLabelValue       = "custom-dns"
		fqdnPodSelectorLabelValue = "fqdn-cache-test"
	)

	podSelectorLabel := map[string]string{
		"app": fqdnPodSelectorLabelValue,
	}
	port := int32(80)
	udpPort := int32(53)
	builder := &utils.AntreaNetworkPolicySpecBuilder{}
	builder = builder.SetName(data.testNamespace, fqdnPolicyName).
		SetTier(defaultTierName).
		SetPriority(1.0).
		SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: podSelectorLabel}})
	builder.AddFQDNRule(testFQDN, utils.ProtocolTCP, &port, nil, nil, "AllowForFQDN", nil,
		crdv1beta1.RuleActionAllow)
	builder.AddEgress(utils.ProtocolUDP, &udpPort, nil, nil, nil, nil,
		nil, nil, nil, nil, map[string]string{"app": customDnsLabelValue},
		nil, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionAllow, "", "AllowDnsQueries")
	builder.AddEgress(utils.ProtocolTCP, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
		nil, nil, crdv1beta1.RuleActionReject, "", "DropAllRemainingTraffic")

	annp, err := data.CreateOrUpdateANNP(builder.Get())
	require.NoError(t, err, "error while deploying antrea policy %+v", err)
	require.NoError(t, data.waitForANNPRealized(t, annp.Namespace, annp.Name, 10*time.Second))
}

// createToolBoxPod creates the toolbox pod with custom DNS settings for test purpose.
func createToolBoxPod(t *testing.T, data *TestData, dnsServiceIP string) {
	toolBoxLabel := map[string]string{"app": "fqdn-cache-test"}
	mutateSpecForAddingCustomDNS := func(pod *corev1.Pod) {
		pod.Spec.DNSPolicy = corev1.DNSNone
		if pod.Spec.DNSConfig == nil {
			pod.Spec.DNSConfig = &corev1.PodDNSConfig{}
		}
		pod.Spec.DNSConfig.Nameservers = []string{dnsServiceIP}

	}
	require.NoError(t, NewPodBuilder(toolboxPodName, data.testNamespace, ToolboxImage).
		WithLabels(toolBoxLabel).
		WithContainerName(toolboxContainerName).
		WithMutateFunc(mutateSpecForAddingCustomDNS).
		Create(data))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, toolboxPodName, data.testNamespace))
}

// createHttpAgnhostPod creates an agnHost pod that serves HTTP requests and returns the IP of pod created.
func createHttpAgnhostPod(t *testing.T, data *TestData, podName string, agnLabels map[string]string) *PodIPs {
	const agnHostPort = 80
	args := []string{"netexec", "--http-port=" + strconv.Itoa(agnHostPort)}
	ports := []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: agnHostPort,
			Protocol:      corev1.ProtocolTCP,
		},
	}

	require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).
		WithArgs(args).
		WithPorts(ports).
		WithLabels(agnLabels).
		Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	require.NoError(t, err)
	return podIPs
}
