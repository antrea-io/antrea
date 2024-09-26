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
	v1 "k8s.io/api/core/v1"
	v12 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"testing"
	"time"
)

/*
1) Create the KIND cluster.
2) Once cluster is up , create a  service.
3) Get the IP of above service and configure the same in antrea configMap.
4) Update antrea configMap.

5) Create NGINX deployment.
6) Get IP of one of the pods of nginx.
7) create and configure the custom CoreDNS configMap with the IP received above.
8) Create custom CoreDNS deployment.
9) Create and apply antrea FQDN policy.
10) Deploy antrea-toolbox.


---------- tic
11) curl the FQDN from within toolbox.
12) imitate caching the IP belonging to above FQDN resolution by keeping it in a variable.
13) edit configmap with the other IP.
14) wait for new IP to get updated in configMap and let the changes be reflected in dns pod.
15) curl the FQDN again with IP , simulating usage of cache -- and it must fail with no connectivity.
*/

func TestFQDNPolicyWithCachedDNS(t *testing.T) {
	skipIfAntreaPolicyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}

	testFqdn := "nginx-test-pod.lfx.test"

	//TODO: Check for IPv6 ?
	ipFamily := v1.IPv4Protocol

	// Create the service .
	//TODO: Should the names be put up as constants instead of direct strings here?
	customDnsService, err := testData.CreateUDPService("custom-dns-service", data.testNamespace, 53, 53, map[string]string{"app": "custom-dns"}, false, false, v1.ServiceTypeClusterIP, &ipFamily)
	if err != nil {
		t.Fatalf("Error when creating custom DNS service: %v", err)
	}
	require.NoError(t, err)

	// get the IP
	customCoreDnsServiceObject, err := data.clientset.CoreV1().Services(data.testNamespace).Get(context.Background(), customDnsService.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error when getting custom DNS service object : %v", err)
	}
	require.NoError(t, err)

	// Print the ClusterIP
	t.Logf("ClusterIP of the service: %s\n", customCoreDnsServiceObject.Spec.ClusterIP)

	// Get Antrea ConfigMap
	cm, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		t.Fatalf("Error when getting custom DNS configMap : %v", err)
	}
	require.NoError(t, err)

	// Read current value of dnsServer
	var agentConf agentconfig.AgentConfig

	if err := yaml.Unmarshal([]byte(cm.Data["antrea-agent.conf"]), &agentConf); err != nil {
		t.Fatalf("failed to unmarshal Agent config from ConfigMap: %v", err)
	}
	require.NoError(t, err)

	//Set up customDNS server IP in Antrea configmap.
	agentChanges := func(config *agentconfig.AgentConfig) {
		config.DNSServerOverride = customCoreDnsServiceObject.Spec.ClusterIP
	}
	err = data.mutateAntreaConfigMap(nil, agentChanges, false, true)
	if err != nil {
		t.Fatalf("Error when setting up customDNS server IP in Antrea configmap : %v", err)
	}

	cm2, err := data.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		t.Fatalf("Error when getting custom DNS configMap : %v", err)
	}
	require.NoError(t, err)

	// Read current value of dnsServer
	var agentConfChanged agentconfig.AgentConfig
	if err := yaml.Unmarshal([]byte(cm2.Data["antrea-agent.conf"]), &agentConfChanged); err != nil {
		t.Fatalf("failed to unmarshal Agent config from ConfigMap: %v", err)
	}
	require.NoError(t, err)

	t.Logf("dns server value set to %+v in antrea \n", agentConfChanged.DNSServerOverride)

	// Set up nginx server
	nginxConfig := `events {}

http {
    server {
        listen 80;

        location / {
            return 200 "Pod hostname: $hostname\n";
            add_header Content-Type text/plain;
        }
    }
}`

	configData := map[string]string{
		"nginx.conf": nginxConfig,
	}
	nginxConfiMapObject, err := data.CreateConfigMap(data.testNamespace, "nginx-config", configData, nil, false)
	if err != nil {
		t.Fatalf("failed to create nginx ConfigMap: %v", err)
	}
	require.NoError(t, err)

	deploymentLabels := map[string]string{
		"app": "nginx",
	}

	nginxDeployObject, err := data.CreateNginxDeploymentForTest("nginx-deployment", data.testNamespace, nginxConfiMapObject.Name, 2, deploymentLabels)
	if err != nil {
		t.Fatalf("failed to create nginx deployment: %v", err)
	}
	require.NoError(t, err)

	// Though this is used in vmagent_test.go but i think i needed it here to check for the deployment.
	//TODO: Time of 15 seconds is still large for a timeout.
	err = data.waitForDeploymentReady(t, data.testNamespace, nginxDeployObject.Name, 15*time.Second)
	if err != nil {
		t.Fatalf("error while waiting for nginx deployment to be ready : %v", err)
	}
	require.NoError(t, err)

	k8sUtils, err = NewKubernetesUtils(data)
	if err != nil {
		t.Fatalf("error getting k8s utils %+v", err)
	}
	require.NoError(t, err)

	nginxPods, err := k8sUtils.GetPodsByLabel(data.testNamespace, "app", "nginx")
	if err != nil {
		t.Fatalf("error getting Pods by label  %+v", err)
	}
	require.NoError(t, err)

	//domainMapping holds whether the IP is mapped to Domain or not.
	domainMapping := make(map[string]bool)

	// pick an IP to be added in config
	var ipForConfig string
	for idx, pod := range nginxPods {
		//TODO: Following wait time change ?
		_, err = data.podWaitForIPs(10*time.Second, pod.Name, data.testNamespace)
		if err != nil {
			t.Fatalf("error waiting for nginx pods to get IPs %+v", err)
		}
		require.NoError(t, err)

		ipStr := strings.TrimSpace(pod.Status.PodIP)
		domainMapping[ipStr] = false
		//pick last IP for config
		if idx == len(nginxPods)-1 {
			ipForConfig = ipStr
		}
	}

	// Create and update the custom DNS configMap
	customDNSconfig := fmt.Sprintf(`lfx.test:53 {
    errors
    t
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 60
    }
    hosts {
        %s %s
        no_reverse
        pods verified
        ttl 10
    }
    loop
    reload
}`, ipForConfig, testFqdn)

	customDNSconfigData := map[string]string{
		"Corefile": customDNSconfig,
	}

	customDNSconfigMapObject, err := data.CreateConfigMap(data.testNamespace, "custom-dns-config", customDNSconfigData, nil, false)

	if err != nil {
		t.Fatalf("failed to create custom dns ConfigMap: %v", err)
	}
	require.NoError(t, err)
	domainMapping[ipForConfig] = true

	// create supporting SA, Role and Role Binding for DNS deployment.
	saSpec := data.BuildServiceAccount("custom-dns-service-account", data.testNamespace, nil)
	sa, err := data.CreateOrUpdateServiceAccount(saSpec)
	if err != nil {
		t.Fatalf("failed to create service acount for custom dns : %v", err)
	}
	require.NoError(t, err)

	clusterRoleSpec := &v12.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-dns-role"},
		Rules: []v12.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces", "services"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
		},
	}
	// TODO: Delete role on teardown.
	role, err := data.CreateRole(clusterRoleSpec)
	if err != nil {
		t.Fatalf("failed to create cluster role for custom dns : %v", err)
	}
	require.NoError(t, err)

	clusterRoleBinding := &v12.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-dns-role-binding"},
		Subjects: []v12.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: data.testNamespace,
			},
		},
		RoleRef: v12.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     role.Name,
		},
	}

	err = data.CreateRoleBinding(clusterRoleBinding)
	if err != nil {
		t.Fatalf("failed to create cluster role binding for custom dns : %v", err)
	}
	require.NoError(t, err)

	// Create custom DNS deployment
	dnsDeploymentLabels := map[string]string{
		"app": "custom-dns",
	}
	dnsDeploymentObj, err := data.CreateCustomDnsDeployment("custom-dns-deployment", data.testNamespace, customDNSconfigMapObject.Name, sa.Name, dnsDeploymentLabels, 1)
	if err != nil {
		t.Fatalf("failed to create custom dns deployment : %v", err)
	}
	require.NoError(t, err)

	err = data.waitForDeploymentReady(t, data.testNamespace, dnsDeploymentObj.Name, 120*time.Second)
	if err != nil {
		t.Fatalf("error while waiting for custom dns deployment to be ready : %v", err)
	}
	require.NoError(t, err)

	// Create policy
	npPodSelectorLabel := map[string]string{
		"app": "fqdn-cache-test",
	}
	port := int32(80)
	builder := &utils.ClusterNetworkPolicySpecBuilder{}
	builder = builder.SetName("test-acnp-fqdn").
		SetTier("application").
		SetPriority(1.0).
		SetAppliedToGroup([]utils.ACNPAppliedToSpec{{PodSelector: npPodSelectorLabel}})
	builder.AddFQDNRule(testFqdn, "TCP", &port, nil, nil, "r1", nil, crdv1beta1.RuleActionAllow)
	builder.AddEgress("UDP", nil, nil, nil, nil, nil, nil, nil, nil, dnsDeploymentLabels, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionAllow, "", "", nil)
	builder.AddEgress("TCP", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, crdv1beta1.RuleActionReject, "", "", nil)

	acnp, err := k8sUtils.CreateOrUpdateACNP(builder.Get())
	failOnError(err, t)
	failOnError(waitForResourceReady(t, 30*time.Second, acnp), t)

	//TODO: deletion of a namespace deletes all resources under it, do we still need to explicitly delete resources created under that namespace during a test ?
	defer tearDownFQDN(t, data, builder)

	// create toolbox using their framework
	toolBoxLabel := npPodSelectorLabel
	pb := NewPodBuilder("toolbox", data.testNamespace, ToolboxImage)
	pb.WithLabels(toolBoxLabel)
	pb.WithContainerName("toolbox-container")
	mutateSpecForAddingCustomDNS := func(pod *v1.Pod) {
		if pod.Spec.DNSConfig == nil {
			pod.Spec.DNSConfig = &v1.PodDNSConfig{}
		}
		pod.Spec.DNSConfig.Nameservers = []string{customCoreDnsServiceObject.Spec.ClusterIP}

	}
	pb.WithMutateFunc(mutateSpecForAddingCustomDNS)
	err = pb.Create(data)
	if err != nil {
		t.Fatalf("failed to create antrea toolbox  : %v", err)
	}
	require.NoError(t, err)

	/* ------  Actual test ------ */

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

	checkFQDNaccess := func(podName, containerName, fqdn string, checkStatus bool) error {
		t.Logf("trying to curl the fqdn %v", fqdn)
		cmd := []string{"curl", fqdn}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, podName, containerName, cmd)
		if err != nil {
			return fmt.Errorf("error when running command '%s' on Pod '%s': %v, stdout: <%v>, stderr: <%v>", strings.Join(cmd, " "), podName, err, stdout, stderr)
		}
		if checkStatus && getEndpointStatus([]byte(stdout)) == "Failure" {
			return fmt.Errorf("failure status when accessing endpoint: <%v>", stdout)
		}
		fmt.Printf(" curl FQDN | running command '%s' on Pod '%s', stdout: <%v>, stderr: <%v>", strings.Join(cmd, " "), podName, stdout, stderr)
		return nil
	}

	err = checkFQDNaccess(pb.Name, pb.ContainerName, testFqdn, true)
	if err != nil {
		t.Fatalf("failed to curl FQDN from antrea toolbox on initial run : %v", err)
	}
	require.NoError(t, err)

	// DIG to get actual IP , to be sure.
	fqdnIp, err := k8sUtils.digDnSCustom(pb.Name, pb.Namespace, testFqdn, false)
	if err != nil {
		t.Fatalf("failed to get IP of FQDN using DIG from toolbox pod : %v", err)
	}
	require.NoError(t, err)
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
	err = checkFQDNaccess(pb.Name, pb.ContainerName, fqdnIp, true)
	if err != nil {
		t.Fatalf("failed to curl FQDN from antrea toolbox on initial run : %v", err)
	}
	require.NoError(t, err)

	// Create and update the custom DNS configMap
	UpdatedCustomDNSconfig := fmt.Sprintf(`lfx.test:53 {
    errors
    t
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 60
    }
    hosts {
        %s %s
        no_reverse
        pods verified
        ttl 10
    }
    loop
    reload
}`, newIP, testFqdn)

	// edit configmap with this IP
	dnsConfigMap, err := data.GetConfigMap(data.testNamespace, customDNSconfigMapObject.Name)
	if err != nil {
		t.Fatalf("failed to get configmap to replace IP : %v", err)
	}
	require.NoError(t, err)

	dnsConfigMap.Data["Corefile"] = UpdatedCustomDNSconfig
	err = data.UpdateConfigMap(dnsConfigMap)
	if err != nil {
		t.Fatalf("failed to update configmap with new IP : %v", err)
	}
	require.NoError(t, err)

	// Update the annotation
	if dnsDeploymentObj.Annotations == nil {
		dnsDeploymentObj.Annotations = make(map[string]string)
	}
	dnsDeploymentObj.Annotations["baar"] = "foo"

	// Get the Deployment
	updatedDnsDeploymentObj, err := data.clientset.AppsV1().Deployments(data.testNamespace).Get(context.TODO(), dnsDeploymentObj.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error getting Deployment: %s", err)
	}

	// Update the Deployment
	_, err = data.clientset.AppsV1().Deployments(data.testNamespace).Update(context.TODO(), updatedDnsDeploymentObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Error updating Deployment: %s", err)
	}
	require.NoError(t, err)

	for {
		err = checkFQDNaccess(pb.Name, pb.ContainerName, fqdnIp, true)
		if err != nil {
			t.Logf("curl to ip filed. Error %v", err)
			break
		}
		// Wait for 1 second before retrying
		time.Sleep(1 * time.Second)
	}

	// Ensuring that the test checks that an error occurred.
	require.Error(t, err)

}

func tearDownFQDN(t *testing.T, data *TestData, builder *utils.ClusterNetworkPolicySpecBuilder) {
	// cleanup test resources
	teardownTest(t, data)
	failOnError(k8sUtils.DeleteACNP(builder.Name), t)
}
