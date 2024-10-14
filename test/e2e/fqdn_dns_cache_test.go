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

const (
	testFullyQualifiedDomainName = "fqdn-test-pod.lfx.test"
	customDnsConfigName          = "custom-dns-config"
	customDnsPodName             = "custom-dns-server"

	customDnsLabelKey   = "app"
	customDnsLabelValue = "custom-dns"

	fqdnPodSelectorLabelKey   = "app"
	fqdnPodSelectorLabelValue = "fqdn-cache-test"
)

func TestFQDNPolicyWithCachedDNS(t *testing.T) {
	const (
		agnHostLabelKey      = "app"
		agnHostLabelValue    = "agnhost"
		agnHostPodNamePreFix = "agnhost-"

		dnsPort              = 53
		customDnsServiceName = "custom-dns-service"
	)
	skipIfAntreaPolicyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	customDnsService, err := data.CreateServiceWithAnnotations(customDnsServiceName, data.testNamespace, dnsPort, dnsPort, corev1.ProtocolUDP,
		map[string]string{customDnsLabelKey: customDnsLabelValue}, false, false, corev1.ServiceTypeClusterIP, ptr.To[corev1.IPFamily](corev1.IPv4Protocol), map[string]string{})
	require.NoError(t, err, "Error when creating custom DNS service: %v", err)

	setDnsServerAddressInAntrea(t, data, customDnsService.Spec.ClusterIP)
	defer setDnsServerAddressInAntrea(t, data, "")

	podCount := 2
	agnHostPodIps := make([]*PodIPs, podCount)
	for i := 0; i < podCount; i++ {
		agnHostPodIps[i] = createHttpAgnhostPod(t, data, randName(agnHostPodNamePreFix), map[string]string{agnHostLabelKey: agnHostLabelValue})
	}

	ipv4, ipv6 := extractIPs(agnHostPodIps[0])

	dnsConfigData := createDnsConfig(t, ipv4, ipv6, testFullyQualifiedDomainName)
	customDnsConfigMapObject, err := data.CreateConfigMap(data.testNamespace, customDnsConfigName, dnsConfigData, nil, false)
	require.NoError(t, err, "failed to create custom dns ConfigMap: %v", err)

	createDnsPod(t, data)

	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "error getting k8s utils %+v", err)

	createFqdnPolicyInNamespace(t, data, testFullyQualifiedDomainName)

	t.Logf("Creating Toolbox pod...")
	require.NoError(t, data.createToolboxPodOnNode(toolboxPodName, data.testNamespace, "", false), "Error creating toolbox pod")
	_, err = data.PodWaitFor(defaultTimeout, toolboxPodName, data.testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err, "Error while waiting for Toolbox Pod to be in Running state")

	curlTarget := func(podName, containerName, fqdn string) error {
		cmd := []string{"curl", fqdn}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
				strings.Join(cmd, " "), podName, err, stdout, stderr)
		}
		return nil
	}

	//curl does not seem to support --dns-server flag unless we provide DNS IP in resolv.conf, same with --resolve flag.
	setDnsInPod := func(podName, containerName, fqdn string) error {
		cmd := []string{"bash", "-c", "echo 'nameserver " + customDnsService.Spec.ClusterIP + "' > /etc/resolv.conf"}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
				strings.Join(cmd, " "), podName, err, stdout, stderr)
		}
		return nil
	}

	t.Logf("Setting custom DNS IP in resolv.conf of Toolbox pod...")
	require.NoError(t, setDnsInPod(toolboxPodName, toolboxContainerName, testFullyQualifiedDomainName), "Error setting custom DNS in toolbox")

	t.Logf("Trying to curl FQDN ...")
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		err = curlTarget(toolboxPodName, toolboxContainerName, testFullyQualifiedDomainName)
		assert.NoError(t, err)
	}, 2*time.Second, 100*time.Millisecond, "trying to curl the fqdn : ", testFullyQualifiedDomainName)

	t.Logf("Trying to DIG the FQDN to simulate caching the current IP inside Toolbox pod...")
	digResponse, err := k8sUtils.runDNSQuery(toolboxPodName, toolboxContainerName, data.testNamespace, testFullyQualifiedDomainName, false, customDnsService.Spec.ClusterIP)
	require.NoError(t, err, "failed to get IP of FQDN using DIG from toolbox pod : %v", err)

	// Use an assertion to check if the received IPs are same.
	fqdnIp := digResponse.String()
	if digResponse.To4() == nil {
		require.Equalf(t, ipv6, fqdnIp, "The IP set against the FQDN in the DNS server should be the same, but got %+v instead of %+v", fqdnIp, ipv6)
	} else {
		require.Equalf(t, ipv4, fqdnIp, "The IP set against the FQDN in the DNS server should be the same, but got %+v instead of %+v", fqdnIp, ipv4)
	}
	t.Logf("Successfully received the expected IP %+v using the dig command against the FQDN", fqdnIp)

	ipv4, ipv6 = extractIPs(agnHostPodIps[1])
	if ipv6 != "" {
		t.Logf("New IPs to update to DNS | ipv4 : %v, ipv6 : %+v", ipv4, ipv6)
	} else {
		t.Logf("New IPs to update to DNS | ipv4 : %v", ipv4)
	}

	// Update the custom DNS configMap
	UpdatedCustomDNSconfig := createDnsConfig(t, ipv4, ipv6, testFullyQualifiedDomainName)

	customDnsConfigMapObject.Data = UpdatedCustomDNSconfig
	err = data.UpdateConfigMap(customDnsConfigMapObject)
	require.NoError(t, err, "failed to update configmap with new IP : %v", err)
	if ipv6 != "" {
		t.Logf("successfully updated dns configMap with new IPs | ipv4 : %+v, ipv6 :%+v", ipv4, ipv6)
	} else {
		t.Logf("successfully updated dns configMap with new IPs | ipv4 : %+v", ipv4)
	}

	require.NoError(t, data.setPodAnnotation(data.testNamespace, customDnsPodName, randomPatchAnnotationKey, randSeq(annotationValueLen)), "failed to update custom dns pod annotation.")

	assert.Eventually(t, func() bool {
		t.Logf("trying to curl the existing cached IP of the domain  %v", fqdnIp)
		err = curlTarget(toolboxPodName, toolboxContainerName, fqdnIp)
		if err != nil {
			t.Logf("The test failed because of error  %+v", err)
		}
		return assert.Error(t, err)
	}, 15*time.Second, 1*time.Second)

}

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

func createDnsConfig(t *testing.T, ipv4Address, ipv6Address, domainName string) map[string]string {
	const coreFileTemplate = `lfx.test:53 {
        errors
        log
        health
        hosts {
            {{ if .IPv4 }}{{ .IPv4 }} {{ $.FQDN }}{{ end }}
            {{ if .IPv6 }}{{ .IPv6 }} {{ $.FQDN }}{{ end }}
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
			IPv6 string
			FQDN string
		}{
			IPv4: ipv4Address,
			IPv6: ipv6Address,
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

func createDnsPod(t *testing.T, data *TestData) {
	const (
		customDnsImage         = "coredns/coredns:1.11.3"
		customDnsContainerName = "coredns"
		customDnsVolume        = "config-volume"
	)
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
	pb.WithContainerName(customDnsContainerName)
	pb.WithArgs([]string{"-conf", "/etc/coredns/Corefile"})
	pb.AddVolume(volume)
	pb.AddVolumeMount(volumeMount)

	require.NoError(t, pb.Create(data))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, customDnsPodName, data.testNamespace))
	require.NoError(t, data.setPodAnnotation(data.testNamespace, customDnsPodName, randomPatchAnnotationKey, randSeq(annotationValueLen)), "failed to annotate the custom dns pod.")

}

func createFqdnPolicyInNamespace(t *testing.T, data *TestData, domainName string) {
	const fqdnPolicyName = "test-anp-fqdn"
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
	builder.AddFQDNRule(domainName, utils.ProtocolTCP, &port, nil, nil, "AllowForFQDN", nil,
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
}

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

	require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).WithArgs(args).WithPorts(ports).WithLabels(agnLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	require.NoError(t, err)
	return podIPs
}

func extractIPs(podIPs *PodIPs) (string, string) {
	var ipv4, ipv6 string
	res := podIPs.AsSlice()
	if len(res) > 0 {
		ipv4 = res[0].String()
		if len(res) == 2 {
			ipv6 = res[1].String()
		}
	}
	return ipv4, ipv6
}
