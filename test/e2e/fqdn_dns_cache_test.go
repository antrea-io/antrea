package e2e

import (
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/test/e2e/utils"
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strconv"
	"strings"
	"testing"
	"time"
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

	fqdnPolicyName            = "test-acnp-fqdn"
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

	customDnsService, err := createCustomDnsService(data)
	require.NoError(t, err, "Error when creating custom DNS service: %v", err)

	dnsServiceIP := getCustomDnsServiceIP(t, data, customDnsService)

	setDnsServerAddressInAntrea(t, data, dnsServiceIP)

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

	builder := buildFqdnPolicy(t)

	defer tearDown(t, data, builder)

	createToolBoxPod(t, data, dnsServiceIP)

	// idea copied from antctl_test.go:284
	// getEndpointStatus will return "Success", "Failure", or the empty string when out is not a
	// marshalled metav1.Status object.
	getEndpointStatus := func(out []byte) string {
		var status metav1.Status
		if err := json.Unmarshal(out, &status); err != nil {
			// Output is not JSON or does not encode a metav1.Status object.
			return ""
		}
		return status.Status
	}

	curlFqdn := func(podName, containerName, fqdn string, checkStatus bool) error {
		t.Logf("trying to curl the fqdn %v", fqdn)
		cmd := []string{"curl", fqdn}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>",
				strings.Join(cmd, " "), podName, err, stdout, stderr)
		}
		if checkStatus && getEndpointStatus([]byte(stdout)) == "Failure" {
			return fmt.Errorf("failure status when accessing endpoint: <%v>", stdout)
		}
		t.Logf(stdout)
		return nil
	}

	err = curlFqdn(toolBoxPodName, toolboxContainerName, testFullyQualifiedDomainName, true)
	require.NoError(t, err, "failed to curl FQDN from antrea toolbox on initial run : %v", err)

	// DIG to get actual IP , to be sure.
	fqdnIp, err := k8sUtils.digUsingShort(toolBoxPodName, data.testNamespace, testFullyQualifiedDomainName, false, dnsServiceIP)
	require.NoError(t, err, "failed to get IP of FQDN using DIG from toolbox pod : %v", err)
	fqdnIp = strings.TrimSpace(fqdnIp)

	t.Logf("received ip using dig for test fqdn %+v ", fqdnIp)

	var newIP string
	for ip, mapped := range domainMapping {
		if ip != fqdnIp && mapped == false {
			newIP = ip
		}
	}

	t.Logf("New IP to update to DNS %v", newIP)

	// Curl the old ip and it should be a success.
	err = curlFqdn(toolBoxPodName, toolboxContainerName, fqdnIp, true)
	require.NoError(t, err, "failed to curl FQDN from antrea toolbox on initial run : %v", err)

	// Update the custom DNS configMap
	UpdatedCustomDNSconfig := createDnsConfig(newIP)

	customDnsConfigMapObject.Data = UpdatedCustomDNSconfig
	err = data.UpdateConfigMap(customDnsConfigMapObject)
	require.NoError(t, err, "failed to update configmap with new IP : %v", err)
	t.Logf("successfully updated dns configMap with new IP : %+v", newIP)

	updateDnsPodAnnotations(t, data)

	for {
		err = curlFqdn(toolBoxPodName, toolboxContainerName, fqdnIp, true)
		require.NoError(t, err, "curl to ip failed with error : %v", err)

		// Wait for 1 second before retrying
		time.Sleep(1 * time.Second)
	}

}

func tearDown(t *testing.T, data *TestData, builder *utils.ClusterNetworkPolicySpecBuilder) {
	// cleanup test resources
	teardownTest(t, data)
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}

func getCustomDnsServerPodLabel() map[string]string {
	return map[string]string{"app": "custom-dns"}
}

func createCustomDnsService(data *TestData) (*corev1.Service, error) {
	return testData.CreateUDPService(customDnsServiceName, data.testNamespace, customDnsPort, customDnsTargetPort,
		getCustomDnsServerPodLabel(), false, false, corev1.ServiceTypeClusterIP, getIPFamily())
}

// CreateUDPService creates a service with a UDP port and targetPort.
func (data *TestData) CreateUDPService(serviceName, namespace string, port, targetPort int32, selector map[string]string,
	affinity, nodeLocalExternal bool,
	serviceType corev1.ServiceType, ipFamily *corev1.IPFamily) (*corev1.Service, error) {
	annotation := make(map[string]string)
	return data.CreateServiceWithAnnotations(serviceName, namespace, port, targetPort, corev1.ProtocolUDP, selector,
		affinity, nodeLocalExternal, serviceType, ipFamily, annotation)
}

func getCustomDnsServiceIP(t *testing.T, data *TestData, customDnsService *corev1.Service) string {
	// Usually the IP gets assigned quickly to a service , but maybe it's a safe idea to use Get() for getting the IP.
	customCoreDnsServiceObject, err := data.clientset.CoreV1().Services(data.testNamespace).Get(context.Background(),
		customDnsService.Name, metav1.GetOptions{})
	require.NoError(t, err, "Error when getting custom DNS service object : %v", err)

	if customCoreDnsServiceObject.Spec.ClusterIP == "" {
		require.Fail(t, "ClusterIP is empty for the custom DNS service")
	}

	t.Logf("ClusterIP of the dns service: %s\n", customCoreDnsServiceObject.Spec.ClusterIP)
	return customCoreDnsServiceObject.Spec.ClusterIP
}

func getIPFamily() *corev1.IPFamily {
	ipFamily := corev1.IPv4Protocol
	return &ipFamily
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

func buildFqdnPolicy(t *testing.T) *utils.ClusterNetworkPolicySpecBuilder {
	podSelectorLabel := map[string]string{
		fqdnPodSelectorLabelKey: fqdnPodSelectorLabelValue,
	}
	port := int32(80)
	builder := &utils.ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName(fqdnPolicyName).
		SetTier("application").
		SetPriority(1.0).
		SetAppliedToGroup([]utils.ACNPAppliedToSpec{{PodSelector: podSelectorLabel}})
	builder.AddFQDNRule(testFullyQualifiedDomainName, "TCP", &port, nil, nil, "r1", nil,
		crdv1beta1.RuleActionAllow)
	builder.AddEgress("UDP", nil, nil, nil, nil, nil, nil, nil,
		nil, map[string]string{customDnsLabelKey: customDnsLabelValue}, nil,
		nil, nil, nil, nil, nil, nil,
		crdv1beta1.RuleActionAllow, "", "", nil)
	builder.AddEgress("TCP", nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil,
		nil, nil, nil, nil, nil, nil,
		crdv1beta1.RuleActionReject, "", "", nil)

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	require.NoError(t, err, "error while deploying antrea policy %+v", err)
	failOnError(err, t)
	failOnError(waitForResourceReady(t, 30*time.Second, acnp), t)

	return builder
}

func createToolBoxPod(t *testing.T, data *TestData, dnsServiceIP string) {
	toolBoxLabel := map[string]string{fqdnPodSelectorLabelKey: fqdnPodSelectorLabelValue}
	pb := NewPodBuilder(toolBoxPodName, data.testNamespace, ToolboxImage)
	pb.WithLabels(toolBoxLabel)
	pb.WithContainerName(toolboxContainerName)
	mutateSpecForAddingCustomDNS := func(pod *corev1.Pod) {
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
