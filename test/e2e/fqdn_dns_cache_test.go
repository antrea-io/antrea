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

func TestFQDNPolicyWithCachedDNS(t *testing.T) {
	const (
		testFQDN = "fqdn-test-pod.lfx.test"
		dnsPort  = 53
	)

	skipIfAntreaPolicyDisabled(t)
	skipIfNotIPv4Cluster(t)
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// create two agnHost pods and get their IPv4 addresses. The IP of these pods will be mapped against the FQDN.
	podCount := 2
	agnHostPodIps := make([]*PodIPs, podCount)
	for i := 0; i < podCount; i++ {
		agnHostPodIps[i] = createHttpAgnHostPod(t, data)
	}

	// get IPv4 addresses of the agnHost pods created.
	agnHostPodOneIP, _ := agnHostPodIps[0].AsStrings()
	agnHostPodTwoIP, _ := agnHostPodIps[1].AsStrings()

	// create customDNS service and get its ClusterIP.
	customDnsService, err := data.CreateServiceWithAnnotations("custom-dns-service", data.testNamespace, dnsPort,
		dnsPort, corev1.ProtocolUDP, map[string]string{"app": "custom-dns"}, false,
		false, corev1.ServiceTypeClusterIP, ptr.To[corev1.IPFamily](corev1.IPv4Protocol), map[string]string{})
	require.NoError(t, err, "Error creating customDNS service: %+v", err)
	dnsServiceIP := customDnsService.Spec.ClusterIP

	// create a ConfigMap for the custom DNS server, mapping IP of agnHost pod 1 to the FQDN.
	dnsConfigData := createDnsConfig(t, map[string]string{"ipAddress": agnHostPodOneIP, "domainName": testFQDN})
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-dns-config",
			Namespace: data.testNamespace,
		},
		Data: dnsConfigData,
	}
	customDnsConfigMap, err := data.CreateConfigMap(configMap)
	require.NoError(t, err, "failed to create custom dns ConfigMap: %v", err)

	createCustomDnsPod(t, data)

	// set the custom DNS server IP address in Antrea configMap.
	setDnsServerAddressInAntrea(t, data, dnsServiceIP)
	defer setDnsServerAddressInAntrea(t, data, "") //reset after the test.

	createFqdnPolicyInNamespace(t, data, testFQDN)
	createToolboxPod(t, data, dnsServiceIP)

	curlTarget := func(podName, containerName, fqdn string) (string, error) {
		cmd := []string{"curl", fqdn}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
		if err != nil {
			return "", fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
				strings.Join(cmd, " "), podName, err, stdout, stderr)
		}
		return stdout, nil
	}

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		stdout, err := curlTarget(toolboxPodName, toolboxContainerName, testFQDN)
		assert.NoError(t, err)
		t.Logf("response of curl to FQDN - %s", stdout)
	}, 2*time.Second, 100*time.Millisecond, "trying to curl the fqdn : ", testFQDN)

	// confirm that the FQDN resolves to the expected IP address and store it to simulate caching of this IP associated with the FQDN.
	t.Logf("Resolving FQDN to simulate caching the current IP inside Toolbox pod...")
	resolvedIP, err := data.runDNSQuery(toolboxPodName, toolboxContainerName, data.testNamespace, testFQDN, false, dnsServiceIP)
	fqdnIp := resolvedIP.String()
	require.NoError(t, err, "failed to resolve FQDN to an IP from toolbox pod : %v", err)
	require.Equalf(t, agnHostPodOneIP, fqdnIp, "The IP set against the FQDN in the DNS server should be the same, but got %s instead of %s", fqdnIp, agnHostPodOneIP)
	t.Logf("Successfully received the expected IP %s using the dig command against the FQDN", fqdnIp)

	// update the IP address mapped to the FQDN in the custom DNS ConfigMap.
	t.Logf("New IP to update to DNS | ipAdress : %s", agnHostPodTwoIP)
	customDnsConfigMap.Data = createDnsConfig(t, map[string]string{"ipAddress": agnHostPodTwoIP, "domainName": testFQDN})
	require.NoError(t, data.UpdateConfigMap(customDnsConfigMap), "failed to update configmap with new IP : %v", err)
	t.Logf("successfully updated dns configMap with new IPs | ipAdress : %s", agnHostPodTwoIP)

	// try to trigger an immediate refresh of the configmap by setting annotations in custom DNS server pod, this way
	// we try to bypass the kubelet sync period which may be as long as (1 minute by default) + TTL of ConfigMaps.
	// Ref: https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/#mounted-configmaps-are-updated-automatically
	require.NoError(t, data.setPodAnnotation(data.testNamespace, "custom-dns-server", "test.antrea.io/random-value",
		randSeq(8)), "failed to update custom dns pod annotation.")

	// finally verify that Curling the previously cached IP fails after DNS update.
	assert.Eventually(t, func() bool {
		t.Logf("Trying to curl the existing cached IP of the domain - %v", fqdnIp)
		stdout, err := curlTarget(toolboxPodName, toolboxContainerName, fqdnIp)
		if err != nil {
			t.Logf("The test failed because of error :  %+v", err)
		} else {
			t.Logf("response of curl to cached IP - %+v", stdout)
		}
		return assert.Error(t, err)
	}, 20*time.Second, 1*time.Second)

}

// setDnsServerAddressInAntrea sets or resets the custom DNS server IP address in Antrea configMap.
func setDnsServerAddressInAntrea(t *testing.T, data *TestData, dnsServiceIP string) {
	agentChanges := func(config *agentconfig.AgentConfig) {
		config.DNSServerOverride = dnsServiceIP
	}
	err := data.mutateAntreaConfigMap(nil, agentChanges, false, true)
	require.NoError(t, err, "Error when setting up customDNS server IP in Antrea configmap : %v", err)

	if dnsServiceIP == "" {
		t.Logf("removing dns server IP from antrea agent as part of teardown")
	} else {
		t.Logf("dns server value set to %+v in antrea \n", dnsServiceIP)
	}

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
func createToolboxPod(t *testing.T, data *TestData, dnsServiceIP string) {
	mutateSpecForAddingCustomDNS := func(pod *corev1.Pod) {
		pod.Spec.DNSPolicy = corev1.DNSNone
		if pod.Spec.DNSConfig == nil {
			pod.Spec.DNSConfig = &corev1.PodDNSConfig{}
		}
		pod.Spec.DNSConfig.Nameservers = []string{dnsServiceIP}

	}
	//TODO: toolboxPodName ?
	require.NoError(t, NewPodBuilder(toolboxPodName, data.testNamespace, ToolboxImage).
		WithLabels(map[string]string{"app": "fqdn-cache-test"}).
		WithContainerName(toolboxContainerName).
		WithMutateFunc(mutateSpecForAddingCustomDNS).
		Create(data))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, toolboxPodName, data.testNamespace))
}

// createHttpAgnHostPod creates an agnHost pod that serves HTTP requests and returns the IP of pod created.
func createHttpAgnHostPod(t *testing.T, data *TestData) *PodIPs {
	const (
		agnHostPort          = 80
		agnHostPodNamePreFix = "agnhost-"
	)
	podName := randName(agnHostPodNamePreFix)
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
		WithLabels(map[string]string{"app": "agnhost"}).
		Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	require.NoError(t, err)
	return podIPs
}

// createDnsPod creates the CoreDNS pod configured to use the custom DNS ConfigMap.
func createCustomDnsPod(t *testing.T, data *TestData) {
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

	require.NoError(t, NewPodBuilder("custom-dns-server", data.testNamespace, "coredns/coredns:1.11.3").
		WithLabels(map[string]string{"app": "custom-dns"}).
		WithContainerName("coredns").
		WithArgs([]string{"-conf", "/etc/coredns/Corefile"}).
		AddVolume(volume).AddVolumeMount(volumeMount).
		Create(data))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "custom-dns-server", data.testNamespace))
}

// createDnsConfig generates a DNS configuration for the specified IP address and domain name.
func createDnsConfig(t *testing.T, hosts map[string]string) map[string]string {
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
			IPv4: hosts["ipAddress"],
			FQDN: hosts["domainName"],
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
