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
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func (c *ovsCtlClient) DumpTables() ([]string, error) {
	tableDump, err := c.RunOfctlCmd("dump-table-features")
	if err != nil {
		return nil, err
	}
	return c.parseTableEntries(tableDump)
}

func (c *ovsCtlClient) DumpFlows(args ...string) ([]string, error) {
	// Print table and port names.
	flowDump, err := c.RunOfctlCmd("dump-flows", append(args, "--names")...)
	if err != nil {
		return nil, err
	}
	return c.parseFlowEntries(flowDump)
}

func (c *ovsCtlClient) DumpFlowsWithoutTableNames(args ...string) ([]string, error) {
	flowDump, err := c.RunOfctlCmd("dump-flows", append(args, "--no-names")...)
	if err != nil {
		return nil, err
	}
	return c.parseFlowEntries(flowDump)
}

func (c *ovsCtlClient) parseFlowEntries(flowDump []byte) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(flowDump)))
	scanner.Split(bufio.ScanLines)
	flowList := []string{}
	for scanner.Scan() {
		flow := trimFlowStr(scanner.Text())
		// Skip the non-flow line, which is printed when using parameter "--no-names" in tests.
		if strings.Contains(flow, "NXST_FLOW reply") || strings.Contains(flow, "OFPST_FLOW reply") {
			continue
		}
		flowList = append(flowList, flow)
	}
	return flowList, nil
}

func (c *ovsCtlClient) parseTableEntries(tableDump []byte) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(tableDump)))
	scanner.Split(bufio.ScanLines)
	var tableList []string
	re := regexp.MustCompile(`(\d+) \("(\S+)"\)`)
	for scanner.Scan() {
		line := trimFlowStr(scanner.Text())
		if line == "" {
			continue
		}
		match := re.FindString(line)
		if match == "" {
			continue
		}
		match = strings.Replace(match, "(\"", "", -1)
		match = strings.Replace(match, "\")", "", -1)
		tableList = append(tableList, match)
	}
	return tableList, nil
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

func (c *ovsCtlClient) DumpGroup(groupID uint32) (string, error) {
	// Only OpenFlow 1.5 and later support dumping a specific group. Earlier
	// versions of OpenFlow always dump all groups. But when OpenFlow
	// version is not specified, ovs-ofctl defaults to use OpenFlow10 but
	// with the Nicira extensions enabled, which can support dumping a
	// single group too. So here, we do not specify Openflow13 to run the
	// command.
	groupDump, err := c.runOfctlCmd(false, "dump-groups", strconv.FormatUint(uint64(groupID), 10))
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(groupDump)))
	scanner.Split(bufio.ScanLines)
	// Skip the first line.
	scanner.Scan()
	if !scanner.Scan() {
		// No group found.
		return "", nil
	}
	// Should have at most one line (group) returned.
	return strings.TrimSpace(scanner.Text()), nil
}

func (c *ovsCtlClient) DumpGroups() ([]string, error) {
	groupsDump, err := c.RunOfctlCmd("dump-groups")
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(groupsDump)))
	scanner.Split(bufio.ScanLines)
	// Skip the first line.
	scanner.Scan()
	groupList := []string{}
	for scanner.Scan() {
		groupList = append(groupList, strings.TrimSpace(scanner.Text()))
	}
	return groupList, nil
}

func (c *ovsCtlClient) DumpPortsDesc() ([][]string, error) {
	portsDescDump, err := c.RunOfctlCmd("dump-ports-desc")
	if err != nil {
		return nil, err
	}
	portsDescStr := strings.TrimSpace(string(portsDescDump))
	scanner := bufio.NewScanner(strings.NewReader(portsDescStr))
	scanner.Split(bufio.ScanLines)
	// Skip the first line.
	scanner.Scan()

	rawPortDescItems := make([][]string, 0)
	var portItem []string
	for scanner.Scan() {
		str := scanner.Text()
		// If the line starts with a port number, it should be the first line of an OF port. There should be some
		// subsequent lines to describe the status of the current port, which start with multiple while-spaces.
		if len(str) > 2 && string(str[1]) != " " {
			if len(portItem) > 0 {
				rawPortDescItems = append(rawPortDescItems, portItem)
			}
			portItem = nil
		}
		portItem = append(portItem, scanner.Text())
	}
	if len(portItem) > 0 {
		rawPortDescItems = append(rawPortDescItems, portItem)
	}
	return rawPortDescItems, nil
}

func (c *ovsCtlClient) SetPortNoFlood(ofport int) error {
	cmdStr := fmt.Sprintf("ovs-ofctl mod-port %s %d no-flood", c.bridge, ofport)
	cmd := getOVSCommand(cmdStr)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("fail to set no-food config for port %d on bridge %s: %v, stderr: %s", ofport, c.bridge, err, string(stderr.Bytes()))
	}
	return nil
}

func (c *ovsCtlClient) runOfctlCmd(openflow13 bool, cmd string, args ...string) ([]byte, error) {
	cmdStr := fmt.Sprintf("ovs-ofctl %s %s", cmd, c.bridge)
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	if openflow13 {
		cmdStr += " -O Openflow13"
	}
	out, err := getOVSCommand(cmdStr).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ovsCtlClient) RunOfctlCmd(cmd string, args ...string) ([]byte, error) {
	// Default to use Openflow13.
	return c.runOfctlCmd(true, cmd, args...)
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
		if i := strings.Index(m, "="); i != -1 {
			m = m[:i]
		}
		if !strings.Contains(matchStr, m) {
			// The match condition is not included in matchStr.
			return false
		}
	}
	return true
}
