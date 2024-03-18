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
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"

	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsctl"
)

const (
	openFlowCheckTimeout  = 500 * time.Millisecond
	openFlowCheckInterval = 100 * time.Millisecond
)

func PrepareOVSBridge(brName string) error {
	// using the netdev datapath type does not impact test coverage but
	// ensures that the integration tests can be run with Docker Desktop on
	// macOS.
	cmdStr := fmt.Sprintf("ovs-vsctl --may-exist add-br %s -- set Bridge %s protocols='OpenFlow10,OpenFlow15' datapath_type=netdev", brName, brName)
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

func (f ExpectFlow) flowStr(name string) string {
	return fmt.Sprintf("table=%s,%s actions=%s", name, f.MatchStr, f.ActStr)
}

func CheckFlowExists(t *testing.T, ovsCtlClient ovsctl.OVSCtlClient, tableName string, tableID uint8, expectFound bool, flows []*ExpectFlow) []string {
	var flowList []string
	var unexpectedFlows []*ExpectFlow
	table := tableName
	if table == "" {
		table = fmt.Sprintf("%d", tableID)
	}
	if err := wait.PollUntilContextTimeout(context.TODO(), openFlowCheckInterval, openFlowCheckTimeout, true, func(ctx context.Context) (done bool, err error) {
		unexpectedFlows = unexpectedFlows[:0]
		if tableName != "" {
			flowList, err = OfctlDumpTableFlows(ovsCtlClient, tableName)
		} else {
			flowList, err = OfctlDumpTableFlowsWithoutName(ovsCtlClient, tableID)
		}
		require.NoError(t, err, "Error dumping flows")

		for _, flow := range flows {
			found := OfctlFlowMatch(flowList, table, flow)
			if found != expectFound {
				unexpectedFlows = append(unexpectedFlows, flow)
			}
		}
		return len(unexpectedFlows) == 0, nil
	}); err != nil {
		for _, flow := range unexpectedFlows {
			if expectFound {
				t.Errorf("Failed to install flow: %s", flow.flowStr(table))
			} else {
				t.Errorf("Failed to uninstall flow: %s", flow.flowStr(table))
			}
		}
		t.Logf("Existing flows:\n%s", strings.Join(flowList, "\n"))
	}
	return flowList
}

func CheckGroupExists(t *testing.T, ovsCtlClient ovsctl.OVSCtlClient, groupID binding.GroupIDType, groupType string, buckets []string, expectFound bool) {
	var bucketStrs []string
	for _, bucket := range buckets {
		bucketStr := fmt.Sprintf("bucket=%s", bucket)
		bucketStrs = append(bucketStrs, bucketStr)
	}
	groupStr := fmt.Sprintf("group_id=%d,type=%s,%s", groupID, groupType, strings.Join(bucketStrs, ","))
	var groupList [][]string
	if err := wait.PollUntilContextTimeout(context.TODO(), openFlowCheckInterval, openFlowCheckTimeout, true,
		func(ctx context.Context) (done bool, err error) {
			groupList, err = OfCtlDumpGroups(ovsCtlClient)
			require.NoError(t, err, "Error dumping groups")
			found := false
			for _, groupElems := range groupList {
				groupEntry := fmt.Sprintf("%s,bucket=", groupElems[0])
				var groupElemStrs []string
				for _, elem := range groupElems[1:] {
					elemStr := strings.Join(strings.Split(elem, ",")[1:], ",")
					groupElemStrs = append(groupElemStrs, elemStr)
				}
				groupEntry = fmt.Sprintf("%s%s", groupEntry, strings.Join(groupElemStrs, ",bucket="))
				if strings.Contains(groupEntry, groupStr) {
					found = true
					break
				}
			}
			return found == expectFound, nil
		}); err != nil {
		if expectFound {
			t.Errorf("Failed to install group: %s", groupStr)
		} else {
			t.Errorf("Failed to uninstall group: %s", groupStr)
		}
		t.Logf("Existing groups:\n%s", groupList)
	}
}

func OfctlFlowMatch(flowList []string, tableName string, flow *ExpectFlow) bool {
	mtStr := fmt.Sprintf("table=%s, %s ", tableName, flow.MatchStr)
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
			felem = append(felem[:1], felem[4:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}
	return flowList
}

func OfctlDumpFlows(ovsCtlClient ovsctl.OVSCtlClient, args ...string) ([]string, error) {
	rawFlows, err := ovsCtlClient.DumpFlowsWithoutTableNames(args...)
	if err != nil {
		return nil, err
	}
	return formatFlowDump(rawFlows), nil
}

func OfctlDumpTableFlows(ovsCtlClient ovsctl.OVSCtlClient, table string) ([]string, error) {
	rawFlows, err := ovsCtlClient.DumpFlows(fmt.Sprintf("table=%s", table))
	if err != nil {
		return nil, err
	}
	return formatFlowDump(rawFlows), nil
}

func OfctlDumpTableFlowsWithoutName(ovsCtlClient ovsctl.OVSCtlClient, table uint8) ([]string, error) {
	rawFlows, err := ovsCtlClient.DumpFlowsWithoutTableNames(fmt.Sprintf("table=%d", table))
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

func OfctlDeleteGroups(ovsCtlClient ovsctl.OVSCtlClient) error {
	_, err := ovsCtlClient.RunOfctlCmd("del-groups")
	return err
}
