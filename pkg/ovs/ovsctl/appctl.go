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
	"net"
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

type ovsCtlClient struct {
	bridge string
	// To allow injection for testing.
	runAppCtl func(cmd string, needsBridge bool, args ...string) ([]byte, *ExecError)
}

func NewClient(bridge string) *ovsCtlClient {
	client := &ovsCtlClient{bridge: bridge}
	client.runAppCtl = client.RunAppctlCmd
	return client
}

func newBadRequestError(msg string) BadRequestError {
	return BadRequestError(msg)
}

func newExecError(err error, errorOutput string) *ExecError {
	e := &ExecError{error: err}
	if e.CommandExecuted() {
		e.errorOutput = errorOutput
	}
	return e
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
	out, execErr := c.runAppCtl("ofproto/trace", true, flow)
	if execErr != nil {
		return "", execErr
	}
	// Remove "\r" to avoid format issue on Windows.
	out = bytes.ReplaceAll(out, []byte("\r"), []byte(""))
	return string(out), nil
}

func (c *ovsCtlClient) RunAppctlCmd(cmd string, needsBridge bool, args ...string) ([]byte, *ExecError) {
	// Use the control UNIX domain socket to connect to ovs-vswitchd, as Agent can
	// run in a different PID namespace from ovs-vswitchd. Relying on ovs-appctl to
	// determine the control socket based on the pidfile will then give a "stale
	// pidfile" error, as it tries to validate that the PID read from the pidfile
	// corresponds to a valid process in the current PID namespace.
	var cmdStr string
	if needsBridge {
		cmdStr = fmt.Sprintf("ovs-appctl -t %s %s %s", ovsVSwitchdUDS(), cmd, c.bridge)
	} else {
		cmdStr = fmt.Sprintf("ovs-appctl -t %s %s", ovsVSwitchdUDS(), cmd)
	}
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	out, err := getOVSCommand(cmdStr).CombinedOutput()
	if err != nil {
		return nil, newExecError(err, string(out))
	}
	return out, nil
}

func (c *ovsCtlClient) GetDPFeatures() (map[DPFeature]bool, error) {
	cmd := "dpif/show-dp-features"
	out, err := c.runAppCtl(cmd, true)
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
