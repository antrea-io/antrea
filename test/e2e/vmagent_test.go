// Copyright 2022 Antrea Authors
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
	"net"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/externalnode"
	. "antrea.io/antrea/test/e2e/utils"
)

const (
	namespace            = "vm-ns"
	serviceAccount       = "vm-agent"
	externalNodeLabelKey = "antrea-external-node"
	iperfSeconds         = 2
	windowsOS            = "Windows"
	linuxOS              = "Linux"
)

var (
	icmpType = int32(8)
	icmpCode = int32(0)
)

type vmInfo struct {
	nodeName string
	osType   string
	ifName   string
	ip       string
	eeName   string
	ifIndex  string // Used only for Windows
}

// TestVMAgent is the top-level test which can contain some subtests for
// VMAgent so they can share setup, teardown.
func TestVMAgent(t *testing.T) {
	skipIfFeatureDisabled(t, features.ExternalNode, false, true)
	skipIfNoVMs(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	vmList, err := setupVMAgentTest(t, data)
	if err != nil {
		t.Fatalf("Error when setting up VMAgent test: %v", err)
	}
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	defer teardownVMAgentTest(t, data, vmList)
	t.Run("testExternalNode", func(t *testing.T) { testExternalNode(t, data, vmList) })
	t.Run("testExternalNodeWithANP", func(t *testing.T) { testExternalNodeWithANP(t, data, vmList) })
	t.Run("testExternalNodeSupportBundleCollection", func(t *testing.T) { testExternalNodeSupportBundleCollection(t, data, vmList) })
}

func (data *TestData) waitForDeploymentReady(t *testing.T, namespace string, name string, timeout time.Duration) error {
	t.Logf("Waiting for Deployment '%s/%s' to be ready", namespace, name)
	err := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		dp, err := data.clientset.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return dp.Status.ObservedGeneration == dp.Generation && dp.Status.ReadyReplicas == *dp.Spec.Replicas, nil
	})
	if wait.Interrupted(err) {
		_, stdout, _, _ := data.provider.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("kubectl -n %s describe pod -l app=sftp", namespace))
		return fmt.Errorf("some replicas for Deployment '%s/%s' are not ready after %v:\n%v", namespace, name, timeout, stdout)
	} else if err != nil {
		return fmt.Errorf("error when waiting for Deployment '%s/%s' to be ready: %w", namespace, name, err)
	}
	return nil
}

func (data *TestData) waitForSupportBundleCollectionRealized(t *testing.T, name string, timeout time.Duration) error {
	t.Logf("Waiting for SupportBundleCollection '%s' to be realized", name)
	var sbc *crdv1alpha1.SupportBundleCollection
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		var getErr error
		sbc, getErr = data.crdClient.CrdV1alpha1().SupportBundleCollections().Get(context.TODO(), name, metav1.GetOptions{})
		if getErr != nil {
			return false, getErr
		}
		for _, cond := range sbc.Status.Conditions {
			if cond.Status == metav1.ConditionTrue && cond.Type == crdv1alpha1.CollectionCompleted {
				return sbc.Status.DesiredNodes == sbc.Status.CollectedNodes, nil
			}
		}
		return false, nil
	}); err != nil {
		if sbc != nil {
			t.Logf("The conditions of SupportBundleCollection for the vms are %v", sbc.Status.Conditions)
		}
		return fmt.Errorf("error when waiting for SupportBundleCollection '%s' to be realized: %v", name, err)
	}
	return nil
}

func testExternalNodeSupportBundleCollection(t *testing.T, data *TestData, vmList []vmInfo) {
	sftpServiceYAML := "sftp-deployment.yml"
	secretUserName := "foo"
	secretPassword := "pass"
	uploadFolder := "upload"
	uploadPath := path.Join("/home", secretUserName, uploadFolder)
	secretName := "support-bundle-secret"
	vmNames := make([]string, 0, len(vmList))
	for _, vm := range vmList {
		vmNames = append(vmNames, vm.nodeName)
	}
	applySFTPYamlCommand := fmt.Sprintf("kubectl apply -f %s -n %s", sftpServiceYAML, data.testNamespace)
	code, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), applySFTPYamlCommand)
	require.NoError(t, err)
	defer func() {
		deleteSFTPYamlCommand := fmt.Sprintf("kubectl delete -f %s -n %s", sftpServiceYAML, data.testNamespace)
		data.RunCommandOnNode(controlPlaneNodeName(), deleteSFTPYamlCommand)
	}()
	t.Logf("Stdout of the command '%s': %s", applySFTPYamlCommand, stdout)
	if code != 0 {
		t.Errorf("Error when applying %s: %v", sftpServiceYAML, stderr)
	}
	failOnError(data.waitForDeploymentReady(t, data.testNamespace, "sftp", defaultTimeout), t)
	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{
			"username": []byte(secretUserName),
			"password": []byte(secretPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(namespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
	bundleName := "support-bundle-collection-external-node"
	sbc := &crdv1alpha1.SupportBundleCollection{
		ObjectMeta: metav1.ObjectMeta{
			Name: bundleName,
		},
		Spec: crdv1alpha1.SupportBundleCollectionSpec{
			ExternalNodes: &crdv1alpha1.BundleExternalNodes{
				NodeNames:    vmNames,
				NodeSelector: &metav1.LabelSelector{},
				Namespace:    namespace,
			},
			ExpirationMinutes: 300,
			FileServer: crdv1alpha1.BundleFileServer{
				URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
			},
			Authentication: crdv1alpha1.BundleServerAuthConfiguration{
				AuthType: "BasicAuthentication",
				AuthSecret: &v1.SecretReference{
					Name:      secretName,
					Namespace: namespace,
				},
			},
		},
	}
	_, err = data.crdClient.CrdV1alpha1().SupportBundleCollections().Create(context.TODO(), sbc, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.crdClient.CrdV1alpha1().SupportBundleCollections().Delete(context.TODO(), bundleName, metav1.DeleteOptions{})
	failOnError(data.waitForSupportBundleCollectionRealized(t, bundleName, 30*time.Second), t)
	pods, err := data.clientset.CoreV1().Pods(data.testNamespace).List(context.TODO(), metav1.ListOptions{LabelSelector: "app=sftp"})
	require.NoError(t, err)
	require.Len(t, pods.Items, 1)
	pod := pods.Items[0]
	for _, vm := range vmList {
		extractPath := path.Join(uploadPath, vm.nodeName)
		mkdirCommand := fmt.Sprintf("mkdir %s", extractPath)
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, pod.Name, "", []string{"sh", "-c", mkdirCommand})
		t.Logf("Stdout of the command '%s': %s", mkdirCommand, stdout)
		if stderr != "" {
			t.Errorf("error when creating folder %s on pod %s/%s: %s", extractPath, data.testNamespace, pod.Name, stderr)
		}
		require.NoError(t, err)
		extractCommand := fmt.Sprintf("tar xvf %s/%s_%s.tar.gz -C %s", uploadPath, vm.nodeName, bundleName, extractPath)
		stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, pod.Name, "", []string{"sh", "-c", extractCommand})
		t.Logf("Stdout of the command '%s': %s", extractCommand, stdout)
		if stderr != "" {
			t.Errorf("error when extracting tarball %s_%s.tar.gz: %s", vm.nodeName, bundleName, stderr)
		}
		require.NoError(t, err)
		lsCommand := fmt.Sprintf("ls %s", extractPath)
		stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, pod.Name, "", []string{"sh", "-c", lsCommand})
		t.Logf("Stdout of the command '%s': %s", lsCommand, stdout)
		if stderr != "" {
			t.Errorf("error when listing extracted path %s: %s", extractPath, stderr)
		}
		require.NoError(t, err)
		var expectedInfoEntries []string
		if vm.osType == linuxOS {
			expectedInfoEntries = []string{"address", "addressgroups", "agentinfo", "appliedtogroups", "flows", "goroutinestacks", "iptables", "link", "logs", "memprofile", "networkpolicies", "ovsports", "route"}
		} else if vm.osType == windowsOS {
			expectedInfoEntries = []string{"addressgroups", "agentinfo", "appliedtogroups", "flows", "goroutinestacks", "ipconfig", "logs\\ovs\\ovs-vswitchd.log", "logs\\ovs\\ovsdb-server.log", "memprofile", "network-adapters", "networkpolicies", "ovsports", "routes"}
		}
		actualExpectedInfoEntries := strings.Split(strings.Trim(stdout, "\n"), "\n")
		t.Logf("Actual files after extracting SupportBundleCollection tarball %s_%s: %v", vm.nodeName, bundleName, actualExpectedInfoEntries)
		assert.ElementsMatch(t, expectedInfoEntries, actualExpectedInfoEntries)
	}
}

// setupVMAgentTest creates ExternalNode, starts antrea-agent
// and returns a list of VMs upon success
func setupVMAgentTest(t *testing.T, data *TestData) ([]vmInfo, error) {
	t.Logf("List of Windows VMs: '%s', Linux VMs: '%s'", testOptions.windowsVMs, testOptions.linuxVMs)
	t.Logf("Using ServiceAccount %s, Namespace %s", serviceAccount, namespace)
	var vmList []vmInfo
	if testOptions.linuxVMs != "" {
		vms := strings.Split(testOptions.linuxVMs, " ")
		for _, vm := range vms {
			t.Logf("Get info for Linux VM: %s", vm)
			tempVM := getVMInfo(t, data, vm)
			vmList = append(vmList, tempVM)
		}
	}
	if testOptions.windowsVMs != "" {
		vms := strings.Split(testOptions.windowsVMs, " ")
		for _, vm := range vms {
			t.Logf("Get info for Windows VM: %s", vm)
			tempVM := getWindowsVMInfo(t, data, vm)
			vmList = append(vmList, tempVM)
		}
	}
	t.Logf("TestVMAgent setup")
	for i, vm := range vmList {
		stopAntreaAgent(t, data, vm)
		t.Logf("Creating ExternalNode for VM: %s", vm.nodeName)
		en, err := createExternalNodeCRD(data, vm.nodeName, vm.ifName, vm.ip)
		require.NoError(t, err, "Failed to create ExternalNode")
		vmList[i].eeName, err = externalnode.GenExternalEntityName(en)
		require.NoError(t, err, "Failed to generate ExternalEntity Name for ExternalNode %s", en.Name)
		startAntreaAgent(t, data, vm)
	}
	return vmList, nil
}

// teardownVMAgentTest deletes ExternalNode, verifies ExternalEntity is deleted
// and verifies uplink configuration is restored.
func teardownVMAgentTest(t *testing.T, data *TestData, vmList []vmInfo) {
	verifyUpLinkAfterCleanup := func(vm vmInfo) {
		err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 1*time.Minute, true, func(ctx context.Context) (done bool, err error) {
			var tempVM vmInfo
			if vm.osType == linuxOS {
				tempVM = getVMInfo(t, data, vm.nodeName)
			} else {
				tempVM = getWindowsVMInfo(t, data, vm.nodeName)
			}
			if vm.ifName != tempVM.ifName {
				t.Logf("Retry, unexpected uplink interface name, expected %s, got %s", vm.ifName, tempVM.ifName)
				return false, nil
			}
			if vm.ip != tempVM.ip {
				t.Logf("Retry, unexpected uplink IP, expected %s, got %s", vm.ip, tempVM.ip)
				return false, nil
			}
			return true, nil
		})
		assert.NoError(t, err, "Failed to verify uplink configuration after cleanup")
	}
	t.Logf("TestVMAgent teardown")
	for _, vm := range vmList {
		err := data.crdClient.CrdV1alpha1().ExternalNodes(namespace).Delete(context.TODO(), vm.nodeName, metav1.DeleteOptions{})
		assert.NoError(t, err, "Failed to delete ExternalNode %s", vm.nodeName)
		verifyExternalEntityExistence(t, data, vm.eeName, vm.nodeName, false)
		verifyUpLinkAfterCleanup(vm)
	}
}

func verifyExternalEntityExistence(t *testing.T, data *TestData, eeName string, vmNodeName string, expectExists bool) {
	if err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 1*time.Minute, true, func(ctx context.Context) (done bool, err error) {
		t.Logf("Verifying ExternalEntity %s, expectExists %t", eeName, expectExists)
		_, err = data.crdClient.CrdV1alpha2().ExternalEntities(namespace).Get(context.TODO(), eeName, metav1.GetOptions{})
		if err != nil && !errors.IsNotFound(err) {
			t.Errorf("Failed to get ExternalEntity %s by ExternalNode %s: %v", eeName, vmNodeName, err)
			return false, err
		}

		if expectExists {
			if err != nil {
				return false, err
			}
			return true, nil
		}
		// ExternalEntity is expected to be deleted, check for error
		if err != nil {
			return true, nil
		}
		return false, nil

	}); err != nil {
		op := "created"
		if !expectExists {
			op = "deleted"
		}
		assert.NoError(t, err, "Failed to verify ExternalEntity %s %s by ExternalNode %s", eeName, op, vmNodeName)
	}
}

func testExternalNode(t *testing.T, data *TestData, vmList []vmInfo) {
	verifyExternalNodeRealization := func(vm vmInfo) {
		err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 1*time.Minute, true, func(ctx context.Context) (done bool, err error) {
			t.Logf("Verify host interface configuration for VM: %s", vm.nodeName)
			exists, err := verifyInterfaceIsInOVS(t, data, vm)
			return exists, err
		})
		assert.NoError(t, err, "Failed to verify host interface in OVS, vmInfo %+v", vm)

		var tempVM vmInfo
		if vm.osType == windowsOS {
			tempVM = getWindowsVMInfo(t, data, vm.nodeName)
		} else {
			tempVM = getVMInfo(t, data, vm.nodeName)
		}
		assert.Equal(t, vm.ifName, tempVM.ifName, "Failed to verify uplink interface")
		assert.Equal(t, vm.ip, tempVM.ip, "Failed to verify uplink IP")
	}
	for _, vm := range vmList {
		t.Logf("Running verifyExternalEntityExistence")
		verifyExternalEntityExistence(t, data, vm.eeName, vm.nodeName, true)
		t.Logf("Running verifyExternalNodeRealization")
		verifyExternalNodeRealization(vm)
	}
}

func getVMInfo(t *testing.T, data *TestData, nodeName string) (info vmInfo) {
	var vm vmInfo
	vm.nodeName = nodeName
	var cmd string
	cmd = "ip -o -4 route show to default | awk '{print $5}'"
	vm.osType = linuxOS
	rc, ifName, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, ifName, stderr)

	vm.ifName = strings.TrimSpace(ifName)
	cmd = fmt.Sprintf("ifconfig %s | awk '/inet / {print $2}'| sed 's/addr://'", vm.ifName)
	rc, ifIP, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, ifIP, stderr)

	vm.ip = strings.TrimSpace(ifIP)
	return vm
}

func getWindowsVMInfo(t *testing.T, data *TestData, nodeName string) (vm vmInfo) {
	var err error
	vm.nodeName = nodeName
	vm.osType = windowsOS
	cmd := fmt.Sprintf("powershell 'Get-WmiObject -Class Win32_IP4RouteTable | Where { $_.destination -eq \"0.0.0.0\" -and $_.mask -eq \"0.0.0.0\"} | Sort-Object metric1 | select interfaceindex | ft -HideTableHeaders'")
	rc, ifIndex, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, ifIndex, stderr)

	vm.ifIndex = strings.TrimSpace(ifIndex)
	cmd = fmt.Sprintf("powershell 'Get-NetAdapter -IfIndex %s | select name | ft -HideTableHeaders'", vm.ifIndex)
	rc, ifName, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, ifName, stderr)

	vm.ifName = strings.TrimSpace(ifName)
	cmd = fmt.Sprintf("powershell 'Get-NetIPAddress -AddressFamily IPv4 -ifIndex %s| select IPAddress| ft -HideTableHeaders'", vm.ifIndex)
	rc, ifIP, stderr, err := data.RunCommandOnNode(nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, ifIP, stderr)

	vm.ip = strings.TrimSpace(ifIP)
	return vm

}

func startAntreaAgent(t *testing.T, data *TestData, vm vmInfo) {
	t.Logf("Starting antrea-agent on VM: %s", vm.nodeName)
	var cmd string
	if vm.osType == windowsOS {
		cmd = "nssm start antrea-agent"
	} else {
		cmd = "sudo systemctl start antrea-agent"
	}
	rc, stdout, stderr, err := data.RunCommandOnNode(vm.nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, vm.nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, stdout, stderr)
}

func stopAntreaAgent(t *testing.T, data *TestData, vm vmInfo) {
	t.Logf("Stopping antrea-agent on VM: %s", vm.nodeName)
	var cmd string
	if vm.osType == windowsOS {
		cmd = "nssm stop antrea-agent"
	} else {
		cmd = "sudo systemctl stop antrea-agent"
	}
	rc, stdout, stderr, err := data.RunCommandOnNode(vm.nodeName, cmd)
	require.NoError(t, err, "Failed to run command <%s> on VM %s, err %v", cmd, vm.nodeName, err)
	require.Equal(t, 0, rc, "Failed to run command: <%s>, stdout: <%v>, stderr: <%v>", cmd, stdout, stderr)
}

func verifyInterfaceIsInOVS(t *testing.T, data *TestData, vm vmInfo) (found bool, err error) {
	var cmd string
	if vm.osType == windowsOS {
		cmd = fmt.Sprintf("ovs-vsctl --column=name list port '%s'", vm.ifName)
	} else {
		cmd = fmt.Sprintf("sudo ovs-vsctl --column=name list port %s", vm.ifName)
	}
	rc, stdout, stderr, err := data.RunCommandOnNode(vm.nodeName, cmd)
	if err != nil {
		return false, fmt.Errorf("failed to run command <%s> on VM %s, err %v", cmd, vm.nodeName, err)
	}

	if strings.Contains(stdout, "no row") {
		t.Logf("Failed to find OVS port %s on VM %s, err %v, rc %d, stdout %v, stderr %v", vm.ifName, vm.nodeName, err, rc, stdout, stderr)
		return false, nil
	}

	if strings.Contains(stdout, vm.ifName) && strings.Contains(stdout, "name") {
		return true, nil
	}
	return false, nil
}

func createExternalNodeCRD(data *TestData, nodeName string, ifName string, ip string) (enode *crdv1alpha1.ExternalNode, err error) {
	testEn := &ExternalNodeSpecBuilder{}
	testEn.SetName(namespace, nodeName)
	var ipList []string
	ipList = append(ipList, ip)
	testEn.AddInterface(ifName, ipList)
	// Add labels on the VMs.
	testEn.AddLabels(map[string]string{externalNodeLabelKey: nodeName})
	return data.crdClient.CrdV1alpha1().ExternalNodes(namespace).Create(context.TODO(), testEn.Get(), metav1.CreateOptions{})
}

func testExternalNodeWithANP(t *testing.T, data *TestData, vmList []vmInfo) {
	if len(vmList) < 2 {
		t.Skipf("Skipping test as it requires 2 different VMs but the setup has %d", len(vmList))
	}
	t.Run("testANPOnLinuxVM", func(t *testing.T) { testANPOnVMs(t, data, vmList, linuxOS) })
	t.Run("testANPOnWindowsVM", func(t *testing.T) { testANPOnVMs(t, data, vmList, windowsOS) })
}

func testANPOnVMs(t *testing.T, data *TestData, vmList []vmInfo, osType string) {
	appliedToVM, peerVM, err := getVMsByOSType(vmList, osType)
	if err != nil {
		t.Skipf("Skip case testANPOnVMs: %v", err)
	}
	// Test TCP rules in ANP
	t.Run("testANPOnExternalNodeWithTCP", func(t *testing.T) {
		// Use ExternalEntity in an ingress rule configuration.
		testANPProtocolTCPOrUDP(t, data, "anp-vmagent-ingress-tcp-entity", namespace, *appliedToVM, peerVM, ProtocolTCP, true, crdv1beta1.RuleActionDrop, true)
		// Use IP in an egress rule configuration.
		testANPProtocolTCPOrUDP(t, data, "anp-vmagent-egress-tcp-ip", namespace, *appliedToVM, peerVM, ProtocolTCP, false, crdv1beta1.RuleActionDrop, false)
	})
	// Test UDP rules in ANP
	t.Run("testANPOnExternalNodeWithUDP", func(t *testing.T) {
		testANPProtocolTCPOrUDP(t, data, "anp-vmagent-ingress-udp-entity", namespace, *appliedToVM, peerVM, ProtocolUDP, true, crdv1beta1.RuleActionReject, false)
	})
	// Test ICMP rules in ANP
	t.Run("testANPOnExternalNodeWithICMP", func(t *testing.T) {
		testANPProtocolICMP(t, data, "anp-vmagent-ingress-icmp-ip", namespace, *appliedToVM, crdv1beta1.RuleActionDrop)
	})
	// Test FQDN rules in ANP
	t.Run("testANPOnExternalNodeWithFQDN", func(t *testing.T) {
		testANPWithFQDN(t, data, "anp-vmagent-fqdn", namespace, *appliedToVM, []string{"www.facebook.com"}, []string{"docs.google.com"}, []string{"github.com"})
	})
}

// getVMsByOSType returns the appliedTo VM and a different VM to run test. The appliedTo VM is configured with the given
// osType, and the other VM returned is the next one of the appliedTo VM in the given vmList.
func getVMsByOSType(vmList []vmInfo, osType string) (*vmInfo, *vmInfo, error) {
	for i := range vmList {
		if vmList[i].osType == osType {
			return &vmList[i], &vmList[(i+1)%len(vmList)], nil
		}
	}
	return nil, nil, fmt.Errorf("not found a VM configured with OS type %s in vmList", osType)
}

func testANPWithFQDN(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, allowedURLs []string, droppedURLs []string, rejectedURLs []string) {
	var err error
	allURLs := append(append(allowedURLs, droppedURLs...), rejectedURLs...)
	for _, url := range allURLs {
		err := runCurlCommandOnVM(data, appliedToVM, url, crdv1beta1.RuleActionAllow)
		assert.NoError(t, err, "Failed to run curl command on URL %s on VM %s", url, appliedToVM.nodeName)
	}

	fqdnSettings := make(map[string]*crdv1beta1.RuleAction, 0)
	for _, url := range allowedURLs {
		action := crdv1beta1.RuleActionAllow
		fqdnSettings[url] = &action
	}
	for _, url := range droppedURLs {
		action := crdv1beta1.RuleActionDrop
		fqdnSettings[url] = &action
	}
	for _, url := range rejectedURLs {
		action := crdv1beta1.RuleActionReject
		fqdnSettings[url] = &action
	}

	anp := createANPWithFQDN(t, data, name, namespace, appliedToVM, fqdnSettings)
	for url, action := range fqdnSettings {
		err = runCurlCommandOnVM(data, appliedToVM, url, *action)
		assert.NoError(t, err, "Failed to run curl command on URL %s on VM %s", url, appliedToVM.nodeName)
	}
	err = data.DeleteANNP(anp.Namespace, anp.Name)
	require.Nil(t, err)
	for _, url := range allURLs {
		err := runCurlCommandOnVM(data, appliedToVM, url, crdv1beta1.RuleActionAllow)
		assert.NoError(t, err, "Failed to run curl command on URL %s on VM %s", url, appliedToVM.nodeName)
	}
}

// testANPProtocolICMP uses a constant client to ping the given appliedToVM to verify ANP realization.
// Note: master Node is used as the client in the test. This is because the Windows native ping utility always uses 256
// as the identifier in any ICMP echo request packet, and this setting introduces a mis-match in OVS conntrack when
// identifying a new connection.
func testANPProtocolICMP(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, ruleAction crdv1beta1.RuleAction) {
	// The initial network connectivity is working as expected before ANP is created.
	err := runPingCommandOnVM(data, appliedToVM, true)
	require.NoError(t, err, "Failed to verify connectivity before applying ANP")
	anp := createANPForExternalNode(t, data, name, namespace, true, ProtocolICMP, appliedToVM, nil, false, ruleAction)
	// The network connectivity is impacted by ANP.
	err = runPingCommandOnVM(data, appliedToVM, false)
	assert.NoError(t, err, "Failed to verify connectivity after applying ANP")

	err = data.DeleteANNP(anp.Namespace, anp.Name)
	require.NoError(t, err, "Failed to remove ANP %s", name)
	t.Logf("ANP test with nameE %s is done", name)
}

func testANPProtocolTCPOrUDP(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, peerVM *vmInfo, proto AntreaPolicyProtocol, ingress bool, ruleAction crdv1beta1.RuleAction, matchPeerEntity bool) {
	var srcVM, dstVM vmInfo
	if ingress {
		srcVM = *peerVM
		dstVM = appliedToVM
	} else {
		srcVM = appliedToVM
		dstVM = *peerVM
	}
	err := runIperfServer(t, data, dstVM, iperfPort)
	require.NoError(t, err, "Failed to run iperf server on VM %s", dstVM.nodeName)
	defer func() {
		assert.NoError(t, stopIperfCommand(t, data, dstVM), "Failed to stop iperf3 command on VM %s", dstVM.nodeName)
	}()

	// The initial network connectivity is working as expected before ANP is created.
	err = runIperfCommandOnVMs(t, data, srcVM, dstVM, true, proto == ProtocolUDP, ruleAction)
	require.NoError(t, err, "Failed to verify connectivity before applying ANP")
	anp := createANPForExternalNode(t, data, name, namespace, ingress, proto, appliedToVM, peerVM, matchPeerEntity, ruleAction)
	// The network connectivity is impacted by ANP.
	err = runIperfCommandOnVMs(t, data, srcVM, dstVM, false, proto == ProtocolUDP, ruleAction)
	assert.NoError(t, err, "Failed to verify connectivity after applying ANP")

	err = data.DeleteANNP(anp.Namespace, anp.Name)
	require.NoError(t, err, "Failed to remove ANP %s", name)
	t.Logf("ANP test with name %s is done", name)
}

func createANPForExternalNode(t *testing.T, data *TestData, name, namespace string, ingress bool, proto AntreaPolicyProtocol,
	appliedToVM vmInfo, peerVM *vmInfo, matchLabel bool, ruleAction crdv1beta1.RuleAction) *crdv1beta1.NetworkPolicy {
	eeSelector := map[string]string{externalNodeLabelKey: appliedToVM.nodeName}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.
		SetName(namespace, name).
		SetPriority(1.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{ExternalEntitySelector: eeSelector}})

	ruleFunc := builder.AddIngress
	if !ingress {
		ruleFunc = builder.AddEgress
	}

	switch proto {
	case ProtocolTCP:
		fallthrough
	case ProtocolUDP:
		var peerLabel map[string]string
		var cidr *string
		if matchLabel {
			peerLabel = map[string]string{
				externalNodeLabelKey: peerVM.nodeName,
			}
		} else {
			peerIPCIDR := fmt.Sprintf("%s/32", peerVM.ip)
			cidr = &peerIPCIDR
		}
		port := int32(iperfPort)
		ruleFunc(proto, &port, nil, nil, nil, nil, nil, nil, nil, cidr, nil, nil, peerLabel,
			nil, nil, nil, nil, ruleAction, "", "")
	case ProtocolICMP:
		peerIPCIDR := fmt.Sprintf("%s/32", nodeIP(0))
		ruleFunc(ProtocolICMP, nil, nil, nil, &icmpType, &icmpCode, nil, nil, nil, &peerIPCIDR, nil, nil, nil,
			nil, nil, nil, nil, ruleAction, "", "")
	}
	anpRule := builder.Get()

	anp, err := data.CreateOrUpdateANNP(anpRule)
	assert.Nil(t, err, "Failed to create Antrea NetworkPolicy")
	assert.Nil(t, data.waitForANNPRealized(t, anp.Namespace, anp.Name, policyRealizedTimeout), "Failed to realize Antrea NetworkPolicy")
	return anp
}

func createANPWithFQDN(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, fqdnSettings map[string]*crdv1beta1.RuleAction) *crdv1beta1.NetworkPolicy {
	eeSelector := map[string]string{externalNodeLabelKey: appliedToVM.nodeName}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.
		SetName(namespace, name).
		SetPriority(3.0).
		SetAppliedToGroup([]ANNPAppliedToSpec{{ExternalEntitySelector: eeSelector}})
	anpRule := builder.Get()
	i := 0
	for fqdn, action := range fqdnSettings {
		ruleName := fmt.Sprintf("name-%d", i)
		policyPeer := []crdv1beta1.NetworkPolicyPeer{{FQDN: fqdn}}
		ports, _ := GenPortsOrProtocols(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		newRule := crdv1beta1.Rule{
			To:     policyPeer,
			Ports:  ports,
			Action: action,
			Name:   ruleName,
		}
		anpRule.Spec.Egress = append(anpRule.Spec.Egress, newRule)
		i += 1
	}

	anp, err := data.CreateOrUpdateANNP(anpRule)
	require.NoError(t, err, "Failed to create Antrea NetworkPolicy")
	require.NoError(t, data.waitForANNPRealized(t, anp.Namespace, anp.Name, policyRealizedTimeout), "Failed to realize Antrea NetworkPolicy")
	return anp
}

func runPingCommandOnVM(data *TestData, dstVM vmInfo, connected bool) error {
	dstIP := net.ParseIP(dstVM.ip)
	cmd := getPingCommand(pingCount, 0, strings.ToLower(linuxOS), &dstIP, false)
	cmdStr := strings.Join(cmd, " ")
	expCount := pingCount
	if !connected {
		expCount = 0
	}
	expOutput := fmt.Sprintf("%d packets transmitted, %d received", pingCount, expCount)
	// Use master Node to run ping command.
	pingClient := nodeName(0)
	err := wait.PollUntilContextTimeout(context.Background(), time.Second*5, time.Second*20, true, func(ctx context.Context) (done bool, err error) {
		if err := runCommandAndCheckResult(data, pingClient, cmdStr, expOutput, ""); err != nil {
			return false, nil
		}
		return true, nil
	})
	return err
}

func runIperfCommandOnVMs(t *testing.T, data *TestData, srcVM vmInfo, dstVM vmInfo, connected bool, isUDP bool, ruleAction crdv1beta1.RuleAction) error {
	svrIP := net.ParseIP(dstVM.ip)
	err := wait.PollUntilContextTimeout(context.Background(), time.Second*5, time.Second*20, true, func(ctx context.Context) (done bool, err error) {
		if err := runIperfClient(t, data, srcVM, svrIP, iperfPort, isUDP, connected, ruleAction); err != nil {
			return false, nil
		}
		return true, nil
	})
	return err
}

func runIperfServer(t *testing.T, data *TestData, vm vmInfo, dstPort int32) error {
	cmd := getIperf3Command(vm.osType, nil, dstPort, false, true)
	cmdStr := strings.Join(cmd, " ")
	if vm.osType == windowsOS {
		cmdStr = fmt.Sprintf(`cmd.exe /c "%s"`, cmdStr)
	}
	_, _, _, err := data.provider.RunCommandOnNode(vm.nodeName, cmdStr)
	if err != nil {
		return err
	}
	t.Logf("Run iperf3 server on VM %s with command %s", vm.nodeName, cmdStr)
	return nil
}

func stopIperfCommand(t *testing.T, data *TestData, vm vmInfo) error {
	cmdStr := `cmd.exe /c "taskkill /IM iperf3.exe /F"`
	if vm.osType == linuxOS {
		cmdStr = "pkill iperf3"
	}
	_, _, _, err := data.provider.RunCommandOnNode(vm.nodeName, cmdStr)
	if err != nil {
		return err
	}
	t.Logf("Stopped iperf3 on VM %s", vm.nodeName)
	return nil
}

func runIperfClient(t *testing.T, data *TestData, targetVM vmInfo, svrIP net.IP, dstPort int32, isUDP bool, connected bool, ruleAction crdv1beta1.RuleAction) error {
	cmd := getIperf3Command(targetVM.osType, svrIP, dstPort, isUDP, false)
	cmdStr := strings.Join(cmd, " ")
	if targetVM.osType == windowsOS {
		cmdStr = fmt.Sprintf(`cmd.exe /c "%s"`, cmdStr)
	}
	expectedOutput := "iperf Done"
	if !connected {
		switch ruleAction {
		case crdv1beta1.RuleActionDrop:
			expectedOutput = "Connection timed out"
		case crdv1beta1.RuleActionReject:
			if isUDP {
				expectedOutput = "No route to host"
			} else {
				expectedOutput = "Connection refused"
			}
		}
	}

	errCh := make(chan error, 0)
	go func() {
		err := runCommandAndCheckResult(data, targetVM.nodeName, cmdStr, expectedOutput, "")
		errCh <- err
	}()

	select {
	// Complete the iperf3 command in 10s forcibly if it does not return. The stuck in iperf3 command possibly happens
	// when it is running as a client on Windows, if the port opened on iperf server is blocking by ANP rule. To avoid
	// the test is blocking, we forcibly stop the client. As the iperf client is configured with parameter "-t 2" meaning
	// the utility is expected to send packets in 2s. The force quit should not break the testing workloads.
	case <-time.After(time.Second * 10):
		t.Logf("Iperf3 command %s did not return in 10s, stopping it forcibly", cmdStr)
		err := stopIperfCommand(t, data, targetVM)
		assert.NoError(t, err, "Failed to stop iperf3 command after 10s")
		if !connected {
			return nil
		}
		return fmt.Errorf("unable to complete iperf3 command %s in 10s", cmdStr)
	case err := <-errCh:
		return err
	}
}

func runCurlCommandOnVM(data *TestData, targetVM vmInfo, url string, action crdv1beta1.RuleAction) error {
	cmd := getCurlCommand(targetVM.osType, url)
	cmdStr := strings.Join(cmd, " ")

	var expectedErr, expectedOutput string
	switch action {
	case crdv1beta1.RuleActionAllow:
		expectedOutput = "HTTP/1.1"
	case crdv1beta1.RuleActionDrop:
		expectedErr = "Connection timed out"
	case crdv1beta1.RuleActionReject:
		expectedErr = "Connection refused"
	}
	err := wait.PollUntilContextTimeout(context.Background(), time.Second*5, time.Second*20, true, func(ctx context.Context) (done bool, err error) {
		if err := runCommandAndCheckResult(data, targetVM.nodeName, cmdStr, expectedOutput, expectedErr); err != nil {
			return false, nil
		}
		return true, nil
	})
	return err
}

func runCommandAndCheckResult(data *TestData, targetVM string, cmd string, expectedOutput string, expectedError string) error {
	_, out, stderr, err := data.provider.RunCommandOnNode(targetVM, cmd)
	if err != nil {
		return fmt.Errorf("failed to run command %s on VM %s: %v", cmd, targetVM, err)
	}
	if expectedError != "" && strings.Contains(stderr, expectedError) {
		return nil
	}
	if expectedOutput != "" && strings.Contains(out, expectedOutput) {
		return nil
	}
	return fmt.Errorf("command result is not as expected, out: %s, stderr: %s, expectOut: %s, expectErr: %s", out, stderr, expectedOutput, expectedError)
}

func getCurlCommand(osType string, url string) []string {
	var cmd []string
	if osType == windowsOS {
		cmd = append(cmd, "curl.exe")
	} else {
		cmd = append(cmd, "curl")
	}
	cmd = append(cmd, "--connect-timeout", "2", "-i", url)
	return cmd
}

func getIperf3Command(osType string, svrIP net.IP, port int32, isUDP bool, isServer bool) []string {
	var cmd []string
	if osType == windowsOS {
		cmd = append(cmd, "iperf3.exe")
	} else {
		cmd = append(cmd, "iperf3")
	}
	if isServer {
		cmd = append(cmd, "-s", "-D")
	} else {
		cmd = append(cmd, "-c")
		if svrIP.To4() == nil {
			cmd = append(cmd, "-6")
		}
		cmd = append(cmd, svrIP.String(), "-t", fmt.Sprintf("%d", iperfSeconds))
		if isUDP {
			cmd = append(cmd, "-u")
		}
	}
	cmd = append(cmd, "-p", fmt.Sprintf("%d", port))
	return cmd
}
