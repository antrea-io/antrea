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
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	. "antrea.io/antrea/test/e2e/utils"
)

const (
	interfaceNameLength  = 5
	nameSpace            = "vm-ns"
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
	defer teardownVMAgentTest(t, data, vmList)
	t.Run("testExternalNode", func(t *testing.T) { testExternalNode(t, data, vmList) })
	t.Run("testExternalNodeWithANP", func(t *testing.T) { testExternalNodeWithANP(t, data, vmList) })
}

// setupVMAgentTest creates ExternalNode, starts antrea-agent
// and returns a list of VMs upon success
func setupVMAgentTest(t *testing.T, data *TestData) ([]vmInfo, error) {
	t.Logf("List of Windows VMs: '%s', Linux VMs: '%s'", testOptions.windowsVMs, testOptions.linuxVMs)
	nsReturned, _ := data.clientset.CoreV1().Namespaces().Get(context.TODO(), nameSpace, metav1.GetOptions{})
	saReturned, _ := data.clientset.CoreV1().ServiceAccounts(nameSpace).Get(context.TODO(), serviceAccount, metav1.GetOptions{})
	t.Logf("Using service account %s", saReturned.Name)
	t.Logf("Using namespace %s", nsReturned.Name)
	var vmList []vmInfo
	if testOptions.linuxVMs != "" {
		vms := strings.Split(testOptions.linuxVMs, ",")
		for _, vm := range vms {
			t.Logf("Get info for Linux VM: %s", vm)
			tempVm := getVMInfo(t, data, vm)
			vmList = append(vmList, tempVm)
		}
	}
	if testOptions.windowsVMs != "" {
		vms := strings.Split(testOptions.windowsVMs, ",")
		for _, vm := range vms {
			t.Logf("Get info for Windows VM: %s", vm)
			tempVm := getWindowsVMInfo(t, data, vm)
			vmList = append(vmList, tempVm)
		}
	}
	t.Logf("TestVMAgent setup")
	for _, vm := range vmList {
		stopAntreaAgent(t, data, vm)
		t.Logf("Creating ExternalNode for VM: %s", vm.nodeName)
		_, err := createExternalNodeCRD(data, vm.nodeName, vm.ifName, vm.ip)
		require.Nil(t, err, "Failed to create ExternalNode")
		startAntreaAgent(t, data, vm)
	}
	return vmList, nil
}

// teardownVMAgentTest deletes ExternalNode, verifies ExternalEntity is deleted
// and verifies uplink configuration is restored.
func teardownVMAgentTest(t *testing.T, data *TestData, vmList []vmInfo) {
	verifyUpLinkAfterCleanup := func(vm vmInfo) {
		if err := wait.PollImmediate(30*time.Second, 1*time.Minute, func() (done bool, err error) {
			var tempVm vmInfo
			if vm.osType == linuxOS {
				tempVm = getVMInfo(t, data, vm.nodeName)
			} else {
				tempVm = getWindowsVMInfo(t, data, vm.nodeName)
			}
			if !assert.Equal(t, vm.ifName, tempVm.ifName, "Unexpected uplink interface name") {
				return false, nil
			}
			if !assert.Equal(t, vm.ip, tempVm.ip, "Unexpected uplink interface IP") {
				return false, nil
			}
			return true, nil
		}); err != nil {
			assert.Fail(t, "Failed to verify uplink configuration after cleanup")
			return
		}
	}
	t.Logf("TestVMAgent teardown")
	for _, vm := range vmList {
		hash := sha1.New() // #nosec G401: not used for security purposes
		io.WriteString(hash, vm.ifName)
		hashedIfName := hex.EncodeToString(hash.Sum(nil))
		// Generate ExternalEntity name from ExternalNode
		eeName := vm.nodeName + "-" + hashedIfName[:interfaceNameLength]
		if err := data.crdClient.CrdV1alpha1().ExternalNodes(nameSpace).Delete(context.TODO(), vm.nodeName, metav1.DeleteOptions{}); err != nil {
			t.Logf("Failed to delete externalnode, err: %v", err)
		}
		verifyExternalEntityExistence(t, data, eeName, vm.nodeName, false)
		verifyUpLinkAfterCleanup(vm)
	}
}

func verifyExternalEntityExistence(t *testing.T, data *TestData, eeName string, vmNodeName string, expectExists bool) {
	if err := wait.PollImmediate(10*time.Second, 1*time.Minute, func() (done bool, err error) {
		t.Logf("Verifying ExternalEntity %s, expectExists %t", eeName, expectExists)
		_, err = data.crdClient.CrdV1alpha2().ExternalEntities(nameSpace).Get(context.TODO(), eeName, metav1.GetOptions{})
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
		if err := wait.PollImmediate(30*time.Second, 1*time.Minute, func() (done bool, err error) {
			t.Logf("Verify host interface configuration for VM: %s", vm.nodeName)
			exists, err := verifyInterfaceIsInOVS(t, data, vm)
			return exists, err
		}); err != nil {
			assert.NoError(t, err, "Failed to verify host interface in OVS, vmInfo %+v", vm)
			return
		}

		var tempVm vmInfo
		if vm.osType == windowsOS {
			tempVm = getWindowsVMInfo(t, data, vm.nodeName)
		} else {
			tempVm = getVMInfo(t, data, vm.nodeName)
		}
		assert.Exactly(t, vm.ifName, tempVm.ifName, "Failed to verify uplink interface, Expected %s, Got %s", vm.ifName, tempVm.ifName)
		assert.Exactly(t, vm.ip, tempVm.ip, "Failed to verify uplink IP, Expected %s, Got %s", vm.ip, tempVm.ip)
	}
	for _, vm := range vmList {
		hash := sha1.New() // #nosec G401: not used for security purposes
		io.WriteString(hash, vm.ifName)
		hashedIfName := hex.EncodeToString(hash.Sum(nil))
		// Generate ExternalEntity name from ExternalNode
		eeName := vm.nodeName + "-" + hashedIfName[:interfaceNameLength]
		t.Logf("Running verifyExternalEntityExistence")
		verifyExternalEntityExistence(t, data, eeName, vm.nodeName, true)
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
	rc, ifName, _, err := data.RunCommandOnNode(nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v, rc %d", cmd, nodeName, err, rc)

	vm.ifName = strings.TrimSpace(ifName)
	cmd = fmt.Sprintf("ifconfig %s | awk '/inet / {print $2}'| sed 's/addr://'", vm.ifName)
	rc, ifIP, _, err := data.RunCommandOnNode(nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v, rc %d", cmd, nodeName, err, rc)

	vm.ip = strings.TrimSpace(ifIP)
	return vm
}

func getWindowsVMInfo(t *testing.T, data *TestData, nodeName string) (vm vmInfo) {
	var err error
	vm.nodeName = nodeName
	vm.osType = windowsOS
	cmd := fmt.Sprintf("powershell 'Get-WmiObject -Class Win32_IP4RouteTable | Where { $_.destination -eq \"0.0.0.0\" -and $_.mask -eq \"0.0.0.0\"} | Sort-Object metric1 | select interfaceindex | ft -HideTableHeaders'")
	rc, ifIndex, _, err := data.RunCommandOnNode(nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v, rc %d", cmd, nodeName, err, rc)

	vm.ifIndex = strings.TrimSpace(ifIndex)
	cmd = fmt.Sprintf("powershell 'Get-NetAdapter -IfIndex %s | select name | ft -HideTableHeaders'", vm.ifIndex)
	rc, ifName, _, err := data.RunCommandOnNode(nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v, rc %d", cmd, nodeName, err, rc)

	vm.ifName = strings.TrimSpace(ifName)
	cmd = fmt.Sprintf("powershell 'Get-NetIPAddress -AddressFamily IPv4 -ifIndex %s| select IPAddress| ft -HideTableHeaders'", vm.ifIndex)
	rc, ifIP, _, err := data.RunCommandOnNode(nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v, rc %d", cmd, nodeName, err, rc)

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
	_, _, _, err := data.RunCommandOnNode(vm.nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v", cmd, vm.nodeName, err)
}

func stopAntreaAgent(t *testing.T, data *TestData, vm vmInfo) {
	t.Logf("Stopping antrea-agent on VM: %s", vm.nodeName)
	var cmd string
	if vm.osType == windowsOS {
		cmd = "nssm stop antrea-agent"
	} else {
		cmd = "sudo systemctl stop antrea-agent"
	}
	_, _, _, err := data.RunCommandOnNode(vm.nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v", cmd, vm.nodeName, err)
}

func verifyInterfaceIsInOVS(t *testing.T, data *TestData, vm vmInfo) (found bool, err error) {
	var cmd string
	if vm.osType == windowsOS {
		cmd = fmt.Sprintf("ovs-vsctl --column=name list port '%s'", vm.ifName)
	} else {
		cmd = fmt.Sprintf("sudo ovs-vsctl --column=name list port %s", vm.ifName)
	}
	_, out, _, err := data.RunCommandOnNode(vm.nodeName, cmd)
	if err != nil {
		t.Errorf("Failed to run command %s on VM %s, err %v", cmd, vm.nodeName, err)
		return false, err
	}

	if strings.Contains(out, "no row") {
		t.Errorf("Failed to find OVS port %s on VM %s", vm.ifName, vm.nodeName)
		return false, err
	}

	if strings.Contains(out, vm.ifName) && strings.Contains(out, "name") {
		return true, nil
	}
	return false, nil
}

func createExternalNodeCRD(data *TestData, nodeName string, ifName string, ip string) (enode *crdv1alpha1.ExternalNode, err error) {
	testEn := &ExternalNodeSpecBuilder{}
	testEn.SetName(nameSpace, nodeName)
	var ipList []string
	ipList = append(ipList, ip)
	testEn.Spec.Interfaces = append(testEn.Spec.Interfaces, crdv1alpha1.NetworkInterface{
		Name: ifName,
		IPs:  ipList,
	})
	return data.crdClient.CrdV1alpha1().ExternalNodes(nameSpace).Create(context.TODO(), testEn.Get(), metav1.CreateOptions{})
}

func testExternalNodeWithANP(t *testing.T, data *TestData, vmList []vmInfo) {
	if len(vmList) < 2 {
		t.Skipf("Skipping test as it requires 2 different VMs but the setup has %d", len(vmList))
	}
	// Add labels on the VMs.
	addLabelsOnExternalNode(t, data, nameSpace, vmList)
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
		assert.Nil(t, testANPWithPeerVM(t, data, "anp-vmagent-ingress-tcp-entity", nameSpace, appliedToVM, peerVM, ProtocolTCP, true, crdv1alpha1.RuleActionDrop, true))
		// Use IP in an egress rule configuration.
		assert.Nil(t, testANPWithPeerVM(t, data, "anp-vmagent-egress-tcp-ip", nameSpace, appliedToVM, peerVM, ProtocolTCP, false, crdv1alpha1.RuleActionDrop, false))
	})
	// Test UDP rules in ANP
	t.Run("testANPOnExternalNodeWithUDP", func(t *testing.T) {
		assert.Nil(t, testANPWithPeerVM(t, data, "anp-vmagent-ingress-udp-entity", nameSpace, appliedToVM, peerVM, ProtocolUDP, true, crdv1alpha1.RuleActionReject, false))
	})
	// Test ICMP rules in ANP
	t.Run("testANPOnExternalNodeWithICMP", func(t *testing.T) {
		assert.Nil(t, testANPWithPeerVM(t, data, "anp-vmagent-ingress-icmp-ip", nameSpace, appliedToVM, peerVM, ProtocolICMP, true, crdv1alpha1.RuleActionDrop, false))
	})
	// Test FQDN rules in ANP
	t.Run("testANPOnExternalNodeWithFQDN", func(t *testing.T) {
		assert.Nil(t, testANPWithFQDN(t, data, "anp-vmagent-fqdn", nameSpace, appliedToVM, []string{"www.facebook.com"}, []string{"docs.google.com"}, []string{"maps.google.com"}))
	})
}

// getVMsByOSType returns the appliedTo VM and a different VM to run test. The appliedTo VM is configured with the given
// osType, and the other VM returned is the next one of the appliedTo VM in the given vmList.
func getVMsByOSType(vmList []vmInfo, osType string) (vmInfo, vmInfo, error) {
	for i, vm := range vmList {
		if vm.osType == osType {
			return vm, vmList[(i+1)%len(vmList)], nil
		}
	}
	return vmInfo{}, vmInfo{}, fmt.Errorf("not found a VM configured with OS type %s in vmList", osType)
}

func addLabelsOnExternalNode(t *testing.T, data *TestData, namespace string, vmList []vmInfo) {
	for _, vm := range vmList {
		nodeName := vm.nodeName
		en, err := data.crdClient.CrdV1alpha1().ExternalNodes(namespace).Get(context.TODO(), nodeName, metav1.GetOptions{})
		assert.Nil(t, err, fmt.Sprintf("Failed to get ExternalNode %s: %v", nodeName, err))
		if en.Labels == nil {
			en.Labels = make(map[string]string)
		}
		en.Labels[externalNodeLabelKey] = nodeName
		_, err = data.crdClient.CrdV1alpha1().ExternalNodes(namespace).Update(context.TODO(), en, metav1.UpdateOptions{})
		assert.Nil(t, err, fmt.Sprintf("Failed to add label on ExternalNode %s: %v", nodeName, err))
	}
}

func testANPWithFQDN(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, allowedURLs []string, droppedURLs []string, rejectedURLs []string) error {
	var err error
	allURLs := append(append(allowedURLs, droppedURLs...), rejectedURLs...)
	for _, url := range allURLs {
		err := runCurlCommandOnVM(t, data, appliedToVM, url, crdv1alpha1.RuleActionAllow)
		assert.Nil(t, err)
	}

	fqdnSettings := make(map[string]*crdv1alpha1.RuleAction, 0)
	for _, url := range allowedURLs {
		action := crdv1alpha1.RuleActionAllow
		fqdnSettings[url] = &action
	}
	for _, url := range droppedURLs {
		action := crdv1alpha1.RuleActionDrop
		fqdnSettings[url] = &action
	}
	for _, url := range rejectedURLs {
		action := crdv1alpha1.RuleActionReject
		fqdnSettings[url] = &action
	}

	anp := createANPWithFQDN(t, data, name, namespace, appliedToVM, fqdnSettings)
	for url, action := range fqdnSettings {
		err = runCurlCommandOnVM(t, data, appliedToVM, url, *action)
		assert.Nil(t, err)
	}
	err = data.DeleteANP(anp.Namespace, anp.Name)
	require.Nil(t, err)
	for _, url := range allURLs {
		err := runCurlCommandOnVM(t, data, appliedToVM, url, crdv1alpha1.RuleActionAllow)
		assert.Nil(t, err)
	}
	return nil
}

func testANPWithPeerVM(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, peerVM vmInfo, proto AntreaPolicyProtocol, ingress bool, ruleAction crdv1alpha1.RuleAction, matchPeerEntity bool) error {
	if proto != ProtocolTCP && proto != ProtocolUDP && proto != ProtocolICMP {
		return fmt.Errorf("unsupported protocol %s when applying ANP rule to ExternalNode", proto)
	}

	var srcVM, dstVM vmInfo
	if ingress {
		srcVM = peerVM
		dstVM = appliedToVM
	} else {
		srcVM = appliedToVM
		dstVM = peerVM
	}

	var initialConnected, anpConnected bool
	if ruleAction == crdv1alpha1.RuleActionDrop || ruleAction == crdv1alpha1.RuleActionReject {
		initialConnected = true
		anpConnected = false
	} else if ruleAction == crdv1alpha1.RuleActionAllow {
		initialConnected = false
		anpConnected = true
	}

	if proto == ProtocolTCP || proto == ProtocolUDP {
		err := runIperfServer(t, data, dstVM, iperfPort)
		require.Nil(t, err, fmt.Sprintf("Failed to run iperf server on VM %s: %v", dstVM.nodeName, err))
		defer func() {
			assert.Nil(t, stopIperfCommand(t, data, dstVM))
		}()
	}

	// The initial network connectivity is working as expected before ANP creation.
	err := verifyANPConnectivity(t, data, srcVM, dstVM, initialConnected, proto, ruleAction)
	require.Nil(t, err)
	anp := createANP(t, data, name, namespace, ingress, proto, appliedToVM, peerVM, matchPeerEntity, ruleAction)
	// The network connectivity is impacted by ANP.
	err = verifyANPConnectivity(t, data, srcVM, dstVM, anpConnected, proto, ruleAction)
	assert.Nil(t, err)

	err = data.DeleteANP(anp.Namespace, anp.Name)
	require.Nil(t, err, fmt.Sprintf("Failed to remove ANP %s: %v", name, err))
	t.Logf("ANP test on name %s is done", name)
	return nil
}

func createANP(t *testing.T, data *TestData, name, namespace string, ingress bool, proto AntreaPolicyProtocol,
	appliedToVM vmInfo, peerVM vmInfo, matchLabel bool, ruleAction crdv1alpha1.RuleAction) *crdv1alpha1.NetworkPolicy {
	eeSelector := map[string]string{externalNodeLabelKey: appliedToVM.nodeName}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.
		SetName(namespace, name).
		SetPriority(1.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{ExternalEntitySelector: eeSelector}})

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
		ruleFunc(proto, &port, nil, nil, nil, nil, nil, nil, cidr, nil, nil, peerLabel,
			nil, nil, nil, nil, ruleAction, "")
	case ProtocolICMP:
		peerIPCIDR := fmt.Sprintf("%s/32", nodeIP(0))
		ruleFunc(ProtocolICMP, nil, nil, nil, &icmpType, &icmpCode, nil, nil, &peerIPCIDR, nil, nil, nil,
			nil, nil, nil, nil, ruleAction, "")
	}
	anpRule := builder.Get()

	anp, err := data.CreateOrUpdateANP(anpRule)
	assert.Nil(t, err, "Failed to create Antrea NetworkPolicy")
	assert.Nil(t, data.waitForANPRealized(t, anp.Namespace, anp.Name, policyRealizedTimeout), "Failed to realize Antrea NetworkPolicy")
	return anp
}

func createANPWithFQDN(t *testing.T, data *TestData, name string, namespace string, appliedToVM vmInfo, fqdnSettings map[string]*crdv1alpha1.RuleAction) *crdv1alpha1.NetworkPolicy {
	eeSelector := map[string]string{externalNodeLabelKey: appliedToVM.nodeName}
	builder := &AntreaNetworkPolicySpecBuilder{}
	builder = builder.
		SetName(namespace, name).
		SetPriority(3.0).
		SetAppliedToGroup([]ANPAppliedToSpec{{ExternalEntitySelector: eeSelector}})
	anpRule := builder.Get()
	i := 0
	for fqdn, action := range fqdnSettings {
		ruleName := fmt.Sprintf("name-%d", i)
		policyPeer := []crdv1alpha1.NetworkPolicyPeer{{FQDN: fqdn}}
		ports, _ := GenPortsOrProtocols(ProtocolTCP, nil, nil, nil, nil, nil, nil, nil)
		newRule := crdv1alpha1.Rule{
			To:     policyPeer,
			Ports:  ports,
			Action: action,
			Name:   ruleName,
		}
		anpRule.Spec.Egress = append(anpRule.Spec.Egress, newRule)
		i += 1
	}

	anp, err := data.CreateOrUpdateANP(anpRule)
	require.Nil(t, err, "Failed to create Antrea NetworkPolicy")
	assert.Nil(t, data.waitForANPRealized(t, anp.Namespace, anp.Name, policyRealizedTimeout), "Failed to realize Antrea NetworkPolicy")
	return anp
}

func verifyANPConnectivity(t *testing.T, data *TestData, srcVM vmInfo, dstVM vmInfo, connected bool, proto AntreaPolicyProtocol, ruleAction crdv1alpha1.RuleAction) error {
	var err error
	switch proto {
	case ProtocolTCP:
		fallthrough
	case ProtocolUDP:
		err = runIperfCommandOnVMs(t, data, srcVM, dstVM, connected, proto == ProtocolUDP, ruleAction)
	case ProtocolICMP:
		err = runPingCommandOnVM(t, data, dstVM, connected)
	}
	return err
}

func runPingCommandOnVM(t *testing.T, data *TestData, dstVM vmInfo, connected bool) error {
	dstIP := net.ParseIP(dstVM.ip)
	cmd := getPingCommand(pingCount, 0, strings.ToLower(linuxOS), &dstIP)
	cmdStr := strings.Join(cmd, " ")
	expCount := pingCount
	if !connected {
		expCount = 0
	}
	expOutput := fmt.Sprintf("%d packets transmitted, %d received", pingCount, expCount)
	// Use master Node to run ping command.
	pingClient := nodeName(0)
	err := wait.PollImmediate(time.Second*5, time.Second*20, func() (done bool, err error) {
		if err := runCommandAndCheckResult(t, data, pingClient, cmdStr, expOutput, ""); err != nil {
			t.Logf("Failed to run ping command on VM %s: %v", pingClient, err)
			return false, nil
		}
		return true, nil
	})
	return err
}

func runIperfCommandOnVMs(t *testing.T, data *TestData, srcVM vmInfo, dstVM vmInfo, connected bool, isUDP bool, ruleAction crdv1alpha1.RuleAction) error {
	svrIP := net.ParseIP(dstVM.ip)
	err := wait.PollImmediate(time.Second*5, time.Second*20, func() (done bool, err error) {
		if err := runIperfClient(t, data, srcVM, svrIP, iperfPort, isUDP, false, connected, ruleAction); err != nil {
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
		t.Errorf("Failed to run iperf3 command on VM %s, err %v", vm.nodeName, err)
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
		t.Errorf("Failed to stop iperf3 command on VM %s, err %v", vm.nodeName, err)
		return err
	}
	t.Logf("Stoped iperf3 on VM %s", vm.nodeName)
	return nil
}

func runIperfClient(t *testing.T, data *TestData, targetVM vmInfo, svrIP net.IP, dstPort int32, isUDP bool, isServer bool, connected bool, ruleAction crdv1alpha1.RuleAction) error {
	cmd := getIperf3Command(targetVM.osType, svrIP, dstPort, isUDP, isServer)
	cmdStr := strings.Join(cmd, " ")
	if targetVM.osType == windowsOS {
		cmdStr = fmt.Sprintf(`cmd.exe /c "%s"`, cmdStr)
	}
	expectedOutput := "iperf Done"
	if !connected {
		switch ruleAction {
		case crdv1alpha1.RuleActionDrop:
			expectedOutput = "Connection timed out"
		case crdv1alpha1.RuleActionReject:
			if isUDP {
				expectedOutput = "No route to host"
			} else {
				expectedOutput = "Connection refused"
			}
		}
	}

	errCh := make(chan error, 0)
	go func() {
		err := runCommandAndCheckResult(t, data, targetVM.nodeName, cmdStr, expectedOutput, "")
		if err != nil {
			t.Logf("Failed to run iperf3 client command on VM %s: %v", targetVM.nodeName, err)
		}
		errCh <- err
	}()

	select {
	// Complete the iperf3 command in 10s forcibly if it does not return. The stuck in iperf3 command possibly happens
	// when it is running as a client on Windows, if the port opened on iperf server is blocking by ANP rule. To avoid
	// the test is blocking, we forcibly stop the client. As the iperf client is configured with parameter "-t 2" meaning
	// the utility is expected to send packets in 2s. The force quit should not break the testing workloads.
	case <-time.After(time.Second * 10):
		t.Logf("Iperf3 command %s does not return in 10s, stop it forcibly", cmdStr)
		err := stopIperfCommand(t, data, targetVM)
		assert.Nil(t, err, fmt.Sprintf("Failed to stop iperf3 command after 10s: %v", err))
		if !connected {
			return nil
		}
		return fmt.Errorf("failed to complete iperf3 command %s in 10s", cmdStr)
	case err := <-errCh:
		return err
	}
}

func runCurlCommandOnVM(t *testing.T, data *TestData, targetVM vmInfo, url string, action crdv1alpha1.RuleAction) error {
	cmd := getCurlCommand(targetVM.osType, url)
	cmdStr := strings.Join(cmd, " ")

	var expectedErr, expectedOutput string
	switch action {
	case crdv1alpha1.RuleActionAllow:
		expectedOutput = "HTTP/1.1"
	case crdv1alpha1.RuleActionDrop:
		expectedErr = "Connection timed out"
	case crdv1alpha1.RuleActionReject:
		expectedErr = "Connection refused"
	}
	err := wait.PollImmediate(time.Second*5, time.Second*20, func() (done bool, err error) {
		if err := runCommandAndCheckResult(t, data, targetVM.nodeName, cmdStr, expectedOutput, expectedErr); err != nil {
			t.Errorf("Failed to run curl command %s on VM %s: %v", cmdStr, targetVM.nodeName, err)
			return false, nil
		}
		return true, nil
	})
	return err
}

func runCommandAndCheckResult(t *testing.T, data *TestData, targetVM string, cmd string, expectedOutput string, expectError string) error {
	_, out, stderr, err := data.provider.RunCommandOnNode(targetVM, cmd)
	require.Nil(t, err, fmt.Sprintf("Failed to run check command %s on VM %s, err %v", cmd, targetVM, err))
	if strings.Contains(out, expectedOutput) || strings.Contains(stderr, expectError) {
		return nil
	}
	return fmt.Errorf("command output not contains expect string, out: %s, stderr: %s, expectOut: %s, expectErr: %s", out, stderr, expectedOutput, expectError)
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
	cmd := []string{}
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
