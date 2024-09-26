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
		dnsTTL   = 5
	)

	skipIfAntreaPolicyDisabled(t)
	skipIfNotIPv4Cluster(t)
	skipIfIPv6Cluster(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// create two agnHost Pods and get their IPv4 addresses. The IP of these Pods will be mapped against the FQDN.
	podCount := 2
	agnHostPodIPs := make([]*PodIPs, podCount)
	for i := 0; i < podCount; i++ {
		agnHostPodIPs[i] = createHttpAgnHostPod(t, data)
	}

	// get IPv4 addresses of the agnHost pods created.
	agnHostPodOneIP, _ := agnHostPodIPs[0].AsStrings()
	agnHostPodTwoIP, _ := agnHostPodIPs[1].AsStrings()

	// create customDNS service and get its ClusterIP.
	customDnsService, err := data.CreateServiceWithAnnotations("custom-dns-service", data.testNamespace, dnsPort,
		dnsPort, corev1.ProtocolUDP, map[string]string{"app": "custom-dns"}, false,
		false, corev1.ServiceTypeClusterIP, ptr.To[corev1.IPFamily](corev1.IPv4Protocol), map[string]string{})
	require.NoError(t, err, "Error creating custom DNS Service")
	dnsServiceIP := customDnsService.Spec.ClusterIP

	// create a ConfigMap for the custom DNS server, mapping IP of agnHost Pod 1 to the FQDN.
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-dns-config",
			Namespace: data.testNamespace,
		},
		Data: createDnsConfig(t, map[string]string{agnHostPodOneIP: testFQDN}, dnsTTL),
	}
	customDnsConfigMap, err := data.CreateConfigMap(configMap)
	require.NoError(t, err, "failed to create custom DNS ConfigMap")

	createCustomDnsPod(t, data, configMap.Name)

	// set the custom DNS server IP address in Antrea configMap.
	setDnsServerAddressInAntrea(t, data, dnsServiceIP)
	defer setDnsServerAddressInAntrea(t, data, "") //reset after the test.

	createFqdnPolicyInNamespace(t, data, testFQDN, "test-anp-fqdn", "custom-dns", "fqdn-cache-test")
	createToolboxPod(t, data, dnsServiceIP)

	curlFQDN := func(target string) (string, error) {
		cmd := []string{"curl", target}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, toolboxPodName, toolboxContainerName, cmd)
		if err != nil {
			return "", fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
				strings.Join(cmd, " "), toolboxPodName, err, stdout, stderr)
		}
		return stdout, nil
	}

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		stdout, err := curlFQDN(testFQDN)
		assert.NoError(t, err)
		t.Logf("Response of curl to FQDN: %s", stdout)
	}, 2*time.Second, 100*time.Millisecond, "trying to curl the FQDN: ", testFQDN)

	// confirm that the FQDN resolves to the expected IP address and store it to simulate caching of this IP associated with the FQDN.
	t.Logf("Resolving FQDN to simulate caching the current IP inside Toolbox Pod...")
	resolvedIP, err := data.runDNSQuery(toolboxPodName, toolboxContainerName, data.testNamespace, testFQDN, false, dnsServiceIP)
	fqdnIP := resolvedIP.String()
	require.NoError(t, err, "failed to resolve FQDN to an IP from toolbox Pod")
	require.Equalf(t, agnHostPodOneIP, fqdnIP, "The IP set against the FQDN in the DNS server should be the same, but got %s instead of %s", fqdnIP, agnHostPodOneIP)
	t.Logf("Successfully received the expected IP %s using the dig command against the FQDN", fqdnIP)

	// update the IP address mapped to the FQDN in the custom DNS ConfigMap.
	t.Logf("Updating host mapping in DNS server config to use new IP: %s", agnHostPodTwoIP)
	customDnsConfigMap.Data = createDnsConfig(t, map[string]string{agnHostPodTwoIP: testFQDN}, dnsTTL)
	require.NoError(t, data.UpdateConfigMap(customDnsConfigMap), "failed to update configmap with new IP")
	t.Logf("Successfully updated DNS ConfigMap with new IP: %s", agnHostPodTwoIP)

	// try to trigger an immediate refresh of the configmap by setting annotations in custom DNS server Pod, this way
	// we try to bypass the kubelet sync period which may be as long as (1 minute by default) + TTL of ConfigMaps.
	// Ref: https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/#mounted-configmaps-are-updated-automatically
	require.NoError(t, data.setPodAnnotation(data.testNamespace, "custom-dns-server", "test.antrea.io/random-value",
		randSeq(8)), "failed to update custom DNS Pod annotation.")

	// finally verify that Curling the previously cached IP fails after DNS update.
	// The wait time here should be slightly longer than the reload value specified in the custom DNS configuration.
	assert.EventuallyWithT(t, func(collectT *assert.CollectT) {
		t.Logf("Trying to curl the existing cached IP of the domain: %s", fqdnIP)
		stdout, err := curlFQDN(fqdnIP)
		if err != nil {
			t.Logf("Curling the cached IP failed")
		} else {
			t.Logf("Response of curl to cached IP: %+v", stdout)
		}
		assert.Error(collectT, err)
	}, 10*time.Second, 1*time.Second)
}

// setDnsServerAddressInAntrea sets or resets the custom DNS server IP address in Antrea configMap.
func setDnsServerAddressInAntrea(t *testing.T, data *TestData, dnsServiceIP string) {
	agentChanges := func(config *agentconfig.AgentConfig) {
		config.DNSServerOverride = dnsServiceIP
	}
	err := data.mutateAntreaConfigMap(nil, agentChanges, false, true)
	require.NoError(t, err, "Error when setting up custom DNS server IP in Antrea configmap")

	if dnsServiceIP == "" {
		t.Logf("Removing DNS server IP from antrea agent as part of teardown")
	} else {
		t.Logf("DNS server value set to %s in antrea \n", dnsServiceIP)
	}

}

// createFqdnPolicyInNamespace creates an FQDN policy in the specified namespace.
func createFqdnPolicyInNamespace(t *testing.T, data *TestData, testFQDN string, fqdnPolicyName, customDnsLabelValue, fqdnPodSelectorLabelValue string) {
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
	require.NoError(t, err, "error while deploying antrea policy")
	require.NoError(t, data.waitForANNPRealized(t, annp.Namespace, annp.Name, 10*time.Second))
}

// createToolBoxPod creates the toolbox Pod with custom DNS settings for test purpose.
func createToolboxPod(t *testing.T, data *TestData, dnsServiceIP string) {
	mutateSpecForAddingCustomDNS := func(pod *corev1.Pod) {
		pod.Spec.DNSPolicy = corev1.DNSNone
		if pod.Spec.DNSConfig == nil {
			pod.Spec.DNSConfig = &corev1.PodDNSConfig{}
		}
		pod.Spec.DNSConfig.Nameservers = []string{dnsServiceIP}

	}
	require.NoError(t, NewPodBuilder(toolboxPodName, data.testNamespace, ToolboxImage).
		WithLabels(map[string]string{"app": "fqdn-cache-test"}).
		WithContainerName(toolboxContainerName).
		WithMutateFunc(mutateSpecForAddingCustomDNS).
		Create(data))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, toolboxPodName, data.testNamespace))
}

// createHttpAgnHostPod creates an agnHost Pod that serves HTTP requests and returns the IP of Pod created.
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

// createDnsPod creates the CoreDNS Pod configured to use the custom DNS ConfigMap.
func createCustomDnsPod(t *testing.T, data *TestData, configName string) {
	volume := []corev1.Volume{
		{
			Name: "config-volume",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: configName,
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
func createDnsConfig(t *testing.T, hosts map[string]string, ttl int) map[string]string {
	const coreFileTemplate = `lfx.test:53 {
        errors
        log
        health
        hosts {
            {{ range $IP, $FQDN := .Hosts }}{{ $IP }} {{ $FQDN }}{{ end }}
            no_reverse
            pods verified
            ttl {{ .TTL }}
        }
        loop
        reload 2s
    }`

	generateConfigData := func() (string, error) {

		data := struct {
			Hosts map[string]string
			TTL   int
		}{
			Hosts: hosts,
			TTL:   ttl,
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
	require.NoError(t, err, "error processing configData template for DNS")
	configData := map[string]string{
		"Corefile": configMapData,
	}

	return configData
}
