// Copyright 2023 Antrea Authors
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
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// Shell exits with 127 if the command to execute is not found.
const exitCodeCommandNotFound = 127

var (
	IPAndNWProtos = []string{"ip", "icmp", "tcp", "udp", "sctp", "ipv6", "icmp6", "tcp6", "udp6", "sctp6"}
	// Some typical non-IP packet types.
	// "dl_type=0x0800" can be used to indicate an IP packet too, but as it is not
	// a common way, here we simply assume "dl_type=" is used for non-IP types
	// only.
	nonIPDLTypes = []string{"arp", "rarp", "dl_type="}
)

type DPFeature string

const (
	CTStateFeature    DPFeature = "CT state"
	CTZoneFeature     DPFeature = "CT zone"
	CTMarkFeature     DPFeature = "CT mark"
	CTLabelFeature    DPFeature = "CT label"
	CTStateNATFeature DPFeature = "CT state NAT"
)

var knownFeatures = map[DPFeature]struct{}{
	CTStateFeature:    {},
	CTZoneFeature:     {},
	CTMarkFeature:     {},
	CTLabelFeature:    {},
	CTStateNATFeature: {},
}

// TracingRequest defines tracing request parameters.
type TracingRequest struct {
	InPort string // Input port.
	SrcIP  net.IP
	DstIP  net.IP
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
	Flow   string
	// Whether in_port field in Flow can override InPort.
	AllowOverrideInPort bool
}

type ovsCtlClient struct {
	bridge          string
	ovsOfctlRunner  OVSOfctlRunner
	ovsAppctlRunner OVSAppctlRunner
}

func NewClient(bridge string) *ovsCtlClient {
	ovsOfctlRunner := &ovsOfctlRunner{
		bridge: bridge,
	}
	ovsAppctlRunner := &ovsAppctlRunner{
		bridge: bridge,
	}
	return &ovsCtlClient{
		bridge:          bridge,
		ovsOfctlRunner:  ovsOfctlRunner,
		ovsAppctlRunner: ovsAppctlRunner,
	}
}

func (c *ovsCtlClient) Trace(req *TracingRequest) (string, error) {
	var inPort, nwSrc, nwDst, dlSrc, dlDst, ipKey, nwTTL string

	if strings.Contains(req.Flow, "in_port=") {
		if !req.AllowOverrideInPort {
			return "", newBadRequestError("duplicated 'in_port' in flow")
		}
	} else {
		inPort = fmt.Sprintf("in_port=%s,", req.InPort)
	}

	nonIP := false
	for _, s := range nonIPDLTypes {
		if strings.Contains(req.Flow, s) {
			nonIP = true
			break
		}
	}
	if nonIP && (req.SrcIP != nil || req.DstIP != nil) {
		return "", newBadRequestError("source and destination must not be specified for non-IP packet")
	}

	if req.SrcIP != nil {
		var nwSrcKey string
		ipKey, nwSrcKey = getNwSrcKey(req.SrcIP)
		if strings.Contains(req.Flow, fmt.Sprintf("%s=", nwSrcKey)) {
			return "", newBadRequestError(fmt.Sprintf("duplicated '%s' in flow", nwSrcKey))
		}
		nwSrc = fmt.Sprintf("%s=%s,", nwSrcKey, req.SrcIP.String())
	}
	if req.DstIP != nil {
		var nwDstKey string
		ipKey, nwDstKey = getNwDstKey(req.DstIP)
		// Do not allow overriding destination IP.
		if strings.Contains(req.Flow, fmt.Sprintf("%s=", nwDstKey)) {
			return "", newBadRequestError(fmt.Sprintf("duplicated '%s' in flow", nwDstKey))
		}
		nwDst = fmt.Sprintf("%s=%s,", nwDstKey, req.DstIP.String())
	}

	// Always allow overriding source and destination MACs.
	if req.SrcMAC != nil && !strings.Contains(req.Flow, "dl_src=") {
		dlSrc = fmt.Sprintf("dl_src=%s,", req.SrcMAC.String())
	}
	if req.DstMAC != nil && !strings.Contains(req.Flow, "dl_dst=") {
		dlDst = fmt.Sprintf("dl_dst=%s,", req.DstMAC.String())
	}
	if !nonIP && (nwSrc != "" || nwDst != "") {
		for _, s := range IPAndNWProtos {
			if strings.Contains(req.Flow, s) {
				// IP or IP protocol is already specified in flow. No need to add "ip"/"ipv6" in
				// flow.
				ipKey = ""
				break
			}
		}
		if !strings.Contains(req.Flow, "nw_ttl=") {
			// Add default IP TTL.
			nwTTL = "nw_ttl=64,"
		}
	}

	// "ip" or IP protocol must be set before "nw_ttl", "nw_src", "nw_dst", and
	// "tp_port". For IPv6 packet, "ipv6" is required as a precondition.
	flow := inPort + dlSrc + dlDst + ipKey + req.Flow + "," + nwTTL + nwSrc + nwDst
	return c.runTracing(flow)
}

// getNwSrcKey returns keys of IP address family and IP source which are supported in ovs-appctl command according
// to the given IP.
func getNwSrcKey(ip net.IP) (string, string) {
	if ip.To4() != nil {
		return "ip", "nw_src"
	}
	return "ipv6", "ipv6_src"
}

func getNwDstKey(ip net.IP) (string, string) {
	if ip.To4() != nil {
		return "ip", "nw_dst"
	}
	return "ipv6", "ipv6_dst"
}

func (c *ovsCtlClient) runTracing(flow string) (string, error) {
	out, execErr := c.ovsAppctlRunner.RunAppctlCmd("ofproto/trace", true, flow)
	if execErr != nil {
		return "", execErr
	}
	// Remove "\r" to avoid format issue on Windows.
	out = bytes.ReplaceAll(out, []byte("\r"), []byte(""))
	return string(out), nil
}

func (c *ovsCtlClient) RunAppctlCmd(cmd string, needsBridge bool, args ...string) ([]byte, error) {
	return c.ovsAppctlRunner.RunAppctlCmd(cmd, needsBridge, args...)
}

func (c *ovsCtlClient) GetDPFeatures() (map[DPFeature]bool, error) {
	cmd := "dpif/show-dp-features"
	out, err := c.ovsAppctlRunner.RunAppctlCmd(cmd, true)
	if err != nil {
		return nil, fmt.Errorf("error listing DP features: %v", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Split(bufio.ScanLines)
	features := map[DPFeature]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) != 2 {
			klog.InfoS("Unexpected output from dpif/show-dp-features", "line", line)
			continue
		}
		feature := DPFeature(strings.TrimSpace(fields[0]))
		_, known := knownFeatures[feature]
		if !known {
			continue
		}
		value := strings.TrimSpace(fields[1])
		var supported bool
		if value == "Yes" {
			supported = true
		} else if value == "No" {
			supported = false
		} else {
			klog.InfoS("Unexpected non boolean value", "feature", feature, "value", value)
			continue
		}
		features[feature] = supported
	}
	return features, nil
}

// DeleteDPInterface deletes OVS datapath interface, and it returns with no error if the interface does not exist.
func (c *ovsCtlClient) DeleteDPInterface(name string) error {
	cmd := "dpctl/show ovs-system"
	out, execErr := c.ovsAppctlRunner.RunAppctlCmd(cmd, false)
	if execErr != nil {
		return execErr
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ": ")
		if len(fields) < 2 {
			continue
		}
		nameStr := fields[1]
		ifName := strings.Split(nameStr, " (internal)")[0]
		if ifName == name {
			portStr := strings.Split(fields[0], " ")[1]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return fmt.Errorf("failed to parse portNum from portStr %s, line %s", portStr, line)
			}
			cmd = fmt.Sprintf("dpctl/del-if ovs-system %d", port)
			_, execErr = c.ovsAppctlRunner.RunAppctlCmd(cmd, false)
			if execErr == nil || strings.Contains(execErr.Error(), "No such device") {
				return nil
			} else {
				return execErr
			}
		}
	}
	return nil
}

func newBadRequestError(msg string) BadRequestError {
	return BadRequestError(msg)
}

func NewExecError(err error, errorOutput string) *ExecError {
	e := &ExecError{error: err}
	if e.CommandExecuted() {
		e.errorOutput = errorOutput
	}
	return e
}

func (c *ovsCtlClient) DumpFlows(args ...string) ([]string, error) {
	// Print table and port names.
	flowDump, err := c.ovsOfctlRunner.RunOfctlCmd("dump-flows", append(args, "--names")...)
	if err != nil {
		return nil, err
	}
	return c.parseFlowEntries(flowDump)
}

func (c *ovsCtlClient) DumpFlowsWithoutTableNames(args ...string) ([]string, error) {
	flowDump, err := c.ovsOfctlRunner.RunOfctlCmd("dump-flows", append(args, "--no-names")...)
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

func (c *ovsCtlClient) DumpMatchedFlow(matchStr string) (string, error) {
	flowDump, err := c.ovsOfctlRunner.RunOfctlCmd("dump-flows", matchStr, "--names")
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
	// single group too. So here, we do not specify Openflow15 to run the
	// command.
	groupDump, err := c.ovsOfctlRunner.RunOfctlCmd("dump-groups", strconv.FormatUint(uint64(groupID), 10))
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
	groupsDump, err := c.ovsOfctlRunner.RunOfctlCmd("dump-groups")
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
	portsDescDump, err := c.ovsOfctlRunner.RunOfctlCmd("dump-ports-desc")
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
	// This command does not have standard output, and only has standard err when running with error.
	// NOTE THAT, THIS CONFIGURATION MUST WORK WITH OpenFlow10.
	_, err := runOfctlCmd(context.TODO(), false, "mod-port", c.bridge, strconv.FormatUint(uint64(ofport), 10), "no-flood")
	if err != nil {
		return fmt.Errorf("fail to set no-food config for port %d on bridge %s: %v", ofport, c.bridge, err)
	}
	return nil
}

func (c *ovsCtlClient) RunOfctlCmd(cmd string, args ...string) ([]byte, error) {
	return c.ovsOfctlRunner.RunOfctlCmd(cmd, args...)
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
