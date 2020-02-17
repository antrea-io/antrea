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
)

func PrepareOVSBridge(brName string) error {
	cmdStr := fmt.Sprintf("ovs-vsctl --may-exist add-br %s -- set Bridge %s protocols=OpenFlow10,OpenFlow13", brName, brName)
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

func CheckFlowExists(t *testing.T, br string, tableID uint8, exist bool, flows []*ExpectFlow) []string {
	flowList, _ := OfctlDumpTableFlows(br, tableID)
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

func OfctlDumpFlows(brName string, args ...string) ([]string, error) {
	flowDump, err := runOfctlCmd("dump-flows", brName, args...)
	if err != nil {
		return nil, err
	}

	flowOutStr := string(flowDump)
	flowDb := strings.Split(flowOutStr, "\n")[1:]

	var flowList []string
	for _, flow := range flowDb {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append(felem[:1], felem[2:]...)
			felem = append(felem[:2], felem[4:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}

	return flowList, nil
}

func OfctlDumpTableFlows(brName string, table uint8) ([]string, error) {
	return OfctlDumpFlows(brName, fmt.Sprintf("table=%d", table))
}

func OfctlDeleteFlows(brName string) error {
	_, err := runOfctlCmd("del-flows", brName)
	return err
}

func runOfctlCmd(cmd, brName string, args ...string) ([]byte, error) {
	cmdStr := fmt.Sprintf("ovs-ofctl -O Openflow13 %s %s", cmd, brName)
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		return nil, err
	}

	return out, nil
}
