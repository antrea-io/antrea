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
	interfaceNameLength = 5
	nameSpace           = "vm-ns"
	serviceAccount      = "vm-agent"
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
			if vm.osType == "Linux" {
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
		if vm.osType == "Windows" {
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
	vm.osType = "Linux"
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
	vm.osType = "Windows"
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
	if vm.osType == "Windows" {
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
	if vm.osType == "Windows" {
		cmd = "nssm stop antrea-agent"
	} else {
		cmd = "sudo systemctl stop antrea-agent"
	}
	_, _, _, err := data.RunCommandOnNode(vm.nodeName, cmd)
	require.Nil(t, err, "Failed to run command %s on VM %s, err %v", cmd, vm.nodeName, err)
}

func verifyInterfaceIsInOVS(t *testing.T, data *TestData, vm vmInfo) (found bool, err error) {
	var cmd string
	if vm.osType == "Windows" {
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
