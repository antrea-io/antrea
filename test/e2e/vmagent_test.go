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
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	. "antrea.io/antrea/test/e2e/utils"
)

type VmInfo struct {
	Nodename string
	OS       string
	IfName   string
	IP       string
	IfIndex  string // Used only for windows
}

// TestBasic is the top-level test which contains some subtests for
// basic test cases so they can share setup, teardown.
func TestVMAgent(t *testing.T) {
	skipIfHasWindowsNodes(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testExternalEntityCommon", func(t *testing.T) { testExternalEntityCommon(t, data, "test-ns") })
}

func testExternalEntityCommon(t *testing.T, data *TestData, namespace string) {
	t.Logf("List of Windows VMs: '%s'", testOptions.winVMs)
	t.Logf("List of Linux VMs: '%s'", testOptions.linVMs)
	nsReturned, _ := data.clientset.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
	saReturned, _ := data.clientset.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), "vm-agent", metav1.GetOptions{})
	t.Logf("Using service account %s", saReturned.Name)
	t.Logf("Using name space %s", nsReturned.Name)
	var VmList []VmInfo
	if testOptions.linVMs != "" {
		vms := strings.Split(testOptions.linVMs, ",")
		for _, vm := range vms {
			t.Logf("Get info for linux VM: %s", vm)
			vmInfo := GetVmInfo(t, data, vm)
			VmList = append(VmList, vmInfo)
		}
	}

	if testOptions.winVMs != "" {
		vms := strings.Split(testOptions.winVMs, ",")
		for _, vm := range vms {
			t.Logf("Get info for windows VM, %s", vm)
			vmInfo := GetWindowsVmInfo(t, data, vm)
			VmList = append(VmList, vmInfo)
		}
	}

	t.Log("=== TestSetup ===")
	for _, vm := range VmList {
		// Stop antrea-agent service
		StopAntreaAgent(t, data, vm)
		t.Logf("Creating ExternalEntity for %+v", vm)
		_, err := CreateExternalEntityCrd(data, nsReturned.Name, vm.Nodename, vm.IfName, vm.IP)
		if err != nil {
			t.Fatalf("ERROR! Failed to create ExternalEntity, %+v", err)
		}

		t.Logf("Creating ExternalNode for %+v", vm)
		_, err = CreateExternalNodeCrd(data, nsReturned.Name, vm.Nodename, vm.IfName, vm.IP)
		if err != nil {
			t.Fatalf("ERROR! Failed to create ExternalNode, %+v", err)
		}

		StartAntreaAgent(t, data, vm)
	}

	t.Logf("Wait 120s for antrea-agent to startup and sync externalentities")
	time.Sleep(120 * time.Second)
	t.Logf("=== TestVerification ===")
	for _, vm := range VmList {
		t.Logf("Verify host interface configuration, VmInfo %+v", vm)
		exists, err := VerifyInterfaceIsInOVS(t, data, vm)
		if err != nil {
			t.Errorf("ERROR! Failed to verify Host interface, VmInfo %+v", vm)
		}
		if exists {
			t.Logf("Verified: Host interface %s is added in OVS", vm.IfName)
		}

		var info VmInfo
		if vm.OS == "windows" {
			info = GetWindowsVmInfo(t, data, vm.Nodename)
		} else {
			info = GetVmInfo(t, data, vm.Nodename)
		}
		if info.IP != vm.IP {
			t.Errorf("ERROR! Failed to verify Host IP address, Expected %+v, Got %+v", vm, info)
		} else {
			t.Logf("Verified: Host interface %s has uplink's ip address %s", info.IfName, info.IP)
		}
	}

	t.Logf("=== TestCleanUp ===")
	for _, vm := range VmList {
		if vm.OS == "windows" {
			t.Logf("Skip Deleting ExternalEntity %s", vm.Nodename)
			continue
		}
		t.Logf("Deleting ExternalEntity: %+v", vm.Nodename)
		err := data.crdClient.CrdV1alpha2().ExternalEntities(nsReturned.Name).Delete(context.TODO(), vm.Nodename, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("ERROR! Failed to delete ExternalEntity, %+v", err)
		}

		t.Logf("Deleting ExternalNode: %+v", vm.Nodename)
		err = data.crdClient.CrdV1alpha1().ExternalNodes(nsReturned.Name).Delete(context.TODO(), vm.Nodename, metav1.DeleteOptions{})
		if err != nil {
			t.Fatalf("ERROR! Failed to delete ExternalNode, %+v", err)
		}
	}

	t.Logf("Wait 30s for antrea-agent to sync externalentities")
	time.Sleep(30 * time.Second)
	t.Logf("=== Verification after TestCleanUp ===")
	for _, vm := range VmList {
		var currVm VmInfo
		if vm.OS == "linux" {
			currVm = GetVmInfo(t, data, vm.Nodename)
		} else {
			// Not required on windows, since externalEntity deletion
			// will be a no-op for single interface use-case
			//currVm = GetWindowsVmInfo(t, data, vm.Nodename)
			continue
		}

		// Verify Uplink Interface Name
		if currVm.IfName != vm.IfName {
			t.Errorf("ERROR! Failed to verify uplink interface, Expected %+v, Got %+v", vm, currVm)
		} else {
			t.Logf("Verified: uplink interface is renamed to %s", vm.IfName)
		}

		// Verify  Uplink Interface IP
		if currVm.IP != vm.IP {
			t.Errorf("ERROR! Failed to verify uplink IP address, Expected %+v, Got %+v", vm, currVm)
		} else {
			t.Logf("Verified: uplink interface %s has IP address %s ", vm.IfName, vm.IP)
		}

	}
	t.Log("Exiting the test")
}

func GetVmInfo(t *testing.T, data *TestData, nodeName string) (vm VmInfo) {
	var err error
	vm.Nodename = nodeName
	var cmd string
	cmd = "ip -o -4 route show to default | awk '{print $5}'"
	vm.OS = "linux"
	_, vm.IfName, _, err = data.provider.RunCommandOnVM(nodeName, cmd)
	if err != nil {
		t.Fatalf("ERROR! Failed to run command %s on VM %s, err %v", cmd, nodeName, err)
	}
	vm.IfName = strings.TrimSpace(vm.IfName)
	cmd = fmt.Sprintf("ifconfig %s | awk '/inet / {print $2}'| sed 's/addr://'", vm.IfName)
	_, vm.IP, _, err = data.provider.RunCommandOnVM(nodeName, cmd)
	if err != nil {
		t.Fatalf("ERROR! Failed to run command %s on VM %s, err %v", cmd, nodeName, err)
	}
	vm.IP = strings.TrimSpace(vm.IP)
	return vm
}

func GetWindowsVmInfo(t *testing.T, data *TestData, nodeName string) (vm VmInfo) {
	var err error
	vm.Nodename = nodeName
	vm.OS = "windows"
	cmd := fmt.Sprintf("powershell 'Get-WmiObject -Class Win32_IP4RouteTable | Where { $_.destination -eq \"0.0.0.0\" -and $_.mask -eq \"0.0.0.0\"} | Sort-Object metric1 | select interfaceindex | ft -HideTableHeaders'")
	_, ifIndex, _, err := data.provider.RunCommandOnVM(nodeName, cmd)
	if err != nil {
		t.Fatalf("ERROR! Failed to run command %s on VM %s, err %v", cmd, nodeName, err)
	}
	vm.IfIndex = strings.TrimSpace(ifIndex)
	cmd = fmt.Sprintf("powershell 'Get-NetAdapter -IfIndex %s | select name | ft -HideTableHeaders'", vm.IfIndex)
	_, ifName, _, err := data.provider.RunCommandOnVM(nodeName, cmd)
	if err != nil {
		t.Fatalf("ERROR! Failed to run command %s on VM %s, err %v", cmd, nodeName, err)
	}
	vm.IfName = strings.TrimSpace(ifName)
	cmd = fmt.Sprintf("powershell 'Get-NetIPAddress -AddressFamily IPv4 -ifIndex %s| select IPAddress| ft -HideTableHeaders'", vm.IfIndex)
	_, ifIP, _, err := data.provider.RunCommandOnVM(nodeName, cmd)
	if err != nil {
		t.Fatalf("ERROR! Failed to run command %s on VM %s, err %v", cmd, nodeName, err)
	}
	vm.IP = strings.TrimSpace(ifIP)
	return vm

}

func StartAntreaAgent(t *testing.T, data *TestData, vm VmInfo) {
	t.Logf("Starting antrea-agent on VM: %s", vm.Nodename)
	var cmd string
	if vm.OS == "windows" {
		cmd = "nssm start antrea-agent"
	} else {
		cmd = "sudo systemctl start antrea-agent"
	}
	_, _, _, err := data.provider.RunCommandOnVM(vm.Nodename, cmd)
	if err != nil {
		t.Errorf("ERROR! Failed to run command %s on VM %s, err %v", cmd, vm.Nodename, err)
	}
}

func StopAntreaAgent(t *testing.T, data *TestData, vm VmInfo) {
	t.Logf("Stopping antrea-agent on VM: %s", vm.Nodename)
	var cmd string
	if vm.OS == "windows" {
		cmd = "nssm stop antrea-agent"
	} else {
		cmd = "sudo systemctl stop antrea-agent"
	}
	_, _, _, err := data.provider.RunCommandOnVM(vm.Nodename, cmd)
	if err != nil {
		t.Errorf("ERROR! Failed to run command %s on VM %s, err %v", cmd, vm.Nodename, err)
	}

}

func VerifyInterfaceIsInOVS(t *testing.T, data *TestData, vm VmInfo) (found bool, err error) {
	var cmd string
	if vm.OS == "windows" {
		cmd = fmt.Sprintf("ovs-vsctl --column=name list port '%s'", vm.IfName)
	} else {
		cmd = fmt.Sprintf("sudo ovs-vsctl --column=name list port %s", vm.IfName)
	}
	_, out, _, err := data.provider.RunCommandOnVM(vm.Nodename, cmd)
	if err != nil {
		t.Errorf("ERROR! Failed to run command %s on VM %s, err %v", cmd, vm.Nodename, err)
		return false, err
	}

	if strings.Contains(out, "no row") {
		t.Errorf("ERROR! Failed to find ovs port %s on VM %s", vm.IfName, vm.Nodename)
		return false, err
	}

	if strings.Contains(out, vm.IfName) && strings.Contains(out, "name") {
		return true, nil
	}

	return false, nil
}

func CreateExternalEntityCrd(data *TestData, namespace string, nodename string, ifName string, ip string) (ee *crdv1alpha2.ExternalEntity, err error) {
	testee := &ExternalEntitySpecSpecBuilder{}
	testee.SetName(namespace, nodename)
	testee.Spec.ExternalNode = nodename
	testee.Spec.Endpoints = append(testee.Spec.Endpoints, crdv1alpha2.Endpoint{Name: ifName, IP: ip})
	return data.crdClient.CrdV1alpha2().ExternalEntities(namespace).Create(context.TODO(), testee.Get(), metav1.CreateOptions{})
}

func CreateExternalNodeCrd(data *TestData, namespace string, nodename string, ifName string, ip string) (enode *crdv1alpha1.ExternalNode, err error) {
	testen := &ExternalNodeSpecBuilder{}
	testen.SetName(namespace, nodename)
	var ipList []string
	ipList = append(ipList, ip)
	testen.Spec.Interfaces = append(testen.Spec.Interfaces, crdv1alpha1.NetworkInterface{
		Name: ifName,
		IPs:  ipList,
	})
	return data.crdClient.CrdV1alpha1().ExternalNodes(namespace).Create(context.TODO(), testen.Get(), metav1.CreateOptions{})
}
