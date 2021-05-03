// Copyright 2019 Antrea Authors
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

package ovs

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

func PrepareOVSBridge(brName string) error {
	// using the netdev datapath type does not impact test coverage but
	// ensures that the integration tests can be run with Docker Desktop on
	// macOS.
	cmdStr := fmt.Sprintf("ovs-vsctl --may-exist add-br %s -- set Bridge %s protocols='OpenFlow10,OpenFlow13' datapath_type=netdev", brName, brName)
	err := exec.Command("/bin/sh", "-c", cmdStr).Run()
	if err != nil {
		return err
	}
	return nil
}

func DeleteOVSBridge(brName string) error {
	cmdStr := fmt.Sprintf("ovs-vsctl --if-exist del-br %s", brName)
	err := exec.Command("/bin/sh", "-c", cmdStr).Run()
	if err != nil {
		return err
	}

	return nil
}

type ExpectFlow struct {
	MatchStr string
	ActStr   string
}

func CheckFlowExists(t *testing.T, ovsCtlClient ovsctl.OVSCtlClient, tableID uint8, exist bool, flows []*ExpectFlow) []string {
	flowList, _ := OfctlDumpTableFlows(ovsCtlClient, tableID)
	if exist {
		for _, flow := range flows {
			if !OfctlFlowMatch(flowList, tableID, flow) {
				t.Errorf("Failed to install flow:\n%v\nExisting flows:\n%v", flow, flowList)
			}
		}
	} else {
		for _, flow := range flows {
			if OfctlFlowMatch(flowList, tableID, flow) {
				t.Errorf("Failed to uninstall flow:\n%v\nExisting flows:\n%v", flow, flowList)
			}
		}
	}
	return flowList
}

func CheckGroupExists(t *testing.T, ovsCtlClient ovsctl.OVSCtlClient, groupID binding.GroupIDType, groupType string, buckets []string, expectExists bool) {
	// dump groups
	groupList, err := OfCtlDumpGroups(ovsCtlClient)
	if err != nil {
		t.Errorf("Error dumping flows: Err %v", err)
	}
	var bucketStrs []string
	for _, bucket := range buckets {
		bucketStr := fmt.Sprintf("bucket=%s", bucket)
		bucketStrs = append(bucketStrs, bucketStr)
	}
	groupStr := fmt.Sprintf("group_id=%d,type=%s,%s", groupID, groupType, strings.Join(bucketStrs, ","))
	found := false
	for _, groupElems := range groupList {
		groupEntry := fmt.Sprintf("%s,bucket=", groupElems[0])
		groupEntry = fmt.Sprintf("%s%s", groupEntry, strings.Join(groupElems[1:], ",bucket="))
		if strings.Contains(groupEntry, groupStr) {
			found = true
			break
		}
	}
	if found != expectExists {
		t.Errorf("Failed to find group:\n%v\nExisting groups:\n%v", groupStr, groupList)
	}
}

func OfctlFlowMatch(flowList []string, tableID uint8, flow *ExpectFlow) bool {
	mtStr := fmt.Sprintf("table=%d, %s ", tableID, flow.MatchStr)
	aStr := fmt.Sprintf("actions=%s", flow.ActStr)
	for _, flowEntry := range flowList {
		if strings.Contains(flowEntry, mtStr) && strings.Contains(flowEntry, aStr) {
			return true
		}
	}

	return false
}

func formatFlowDump(rawFlows []string) []string {
	flowList := []string{}
	for _, flow := range rawFlows {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append(felem[:1], felem[3:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}
	return flowList
}

func OfctlDumpFlows(ovsCtlClient ovsctl.OVSCtlClient, args ...string) ([]string, error) {
	rawFlows, err := ovsCtlClient.DumpFlows(args...)
	if err != nil {
		return nil, err
	}
	return formatFlowDump(rawFlows), nil
}

func OfctlDumpTableFlows(ovsCtlClient ovsctl.OVSCtlClient, table uint8) ([]string, error) {
	rawFlows, err := ovsCtlClient.DumpTableFlows(table)
	if err != nil {
		return nil, err
	}
	return formatFlowDump(rawFlows), nil
}

func OfctlDeleteFlows(ovsCtlClient ovsctl.OVSCtlClient) error {
	_, err := ovsCtlClient.RunOfctlCmd("del-flows")
	return err
}

func OfCtlDumpGroups(ovsCtlClient ovsctl.OVSCtlClient) ([][]string, error) {
	rawGroupItems, err := ovsCtlClient.DumpGroups()
	if err != nil {
		return nil, err
	}

	var groupList [][]string
	for _, item := range rawGroupItems {
		elems := strings.Split(item, ",bucket=")
		groupList = append(groupList, elems)
	}
	return groupList, nil
}
