// Copyright 2020 Antrea Authors
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

package ovsctl

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

func (c *ovsCtlClient) DumpFlows(args ...string) ([]string, error) {
	// Print table and port names.
	flowDump, err := c.RunOfctlCmd("dump-flows", append(args, "--names")...)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(flowDump)))
	scanner.Split(bufio.ScanLines)
	flowList := []string{}
	for scanner.Scan() {
		flowList = append(flowList, trimFlowStr(scanner.Text()))
	}
	return flowList, nil

}

func (c *ovsCtlClient) DumpMatchedFlow(matchStr string) (string, error) {
	flowDump, err := c.RunOfctlCmd("dump-flows", matchStr, "--names")
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(flowDump)))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		flowStr := trimFlowStr(scanner.Text())
		// ovs-ofctl dump-flows can return multiple flows that match matchStr, here we
		// check and return only the one that exactly matches matchStr (no extra match
		// conditions).
		if flowExactMatch(matchStr, flowStr) {
			return flowStr, nil
		}
	}

	// No exactly matched flow found.
	return "", nil
}

func (c *ovsCtlClient) DumpTableFlows(table uint8) ([]string, error) {
	return c.DumpFlows(fmt.Sprintf("table=%d", table))
}

func (c *ovsCtlClient) DumpGroups(args ...string) ([][]string, error) {
	groupsDump, err := c.RunOfctlCmd("dump-groups", args...)
	if err != nil {
		return nil, err
	}
	groupsDumpStr := strings.TrimSpace(string(groupsDump))

	scanner := bufio.NewScanner(strings.NewReader(groupsDumpStr))
	scanner.Split(bufio.ScanLines)
	// Skip the first line.
	scanner.Scan()
	rawGroupItems := []string{}
	for scanner.Scan() {
		rawGroupItems = append(rawGroupItems, scanner.Text())
	}

	var groupList [][]string
	for _, rawGroupItem := range rawGroupItems {
		rawGroupItem = strings.TrimSpace(rawGroupItem)
		elems := strings.Split(rawGroupItem, ",bucket=")
		groupList = append(groupList, elems)
	}
	return groupList, nil
}

func (c *ovsCtlClient) RunOfctlCmd(cmd string, args ...string) ([]byte, error) {
	cmdStr := fmt.Sprintf("ovs-ofctl -O Openflow13 %s %s", cmd, c.bridge)
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// trimFlowStr removes undesirable fields from the flow string.
func trimFlowStr(flowStr string) string {
	return flowStr[strings.Index(flowStr, " table")+1:]
}

func flowExactMatch(matchStr, flowStr string) bool {
	// Get the match string which starts with "priority=".
	flowStr = flowStr[strings.Index(flowStr, " priority")+1 : strings.LastIndexByte(flowStr, ' ')]
	matches := strings.Split(flowStr, ",")
	for i, m := range matches {
		// Skip "priority=".
		if i == 0 {
			continue
		}
		if strings.HasPrefix(m, "in_port=") {
			// in_port can be formatted as port name.
			m = "in_port="
		}
		if !strings.Contains(matchStr, m) {
			// The match condition is not included in matchStr.
			return false
		}
	}
	return true
}
