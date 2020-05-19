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
	"fmt"
	"os/exec"
	"strings"
)

// File path of the ovs-vswitchd control UNIX domain socket.
const ovsVSwitchdUDS = "/var/run/openvswitch/ovs-vswitchd.*.ctl"

// Shell exits with 127 if the command to execute is not found.
const exitCodeCommandNotFound = 127

var (
	ipAndNWProtos = []string{"ip", "icmp", "tcp", "udp", "sctp"}
	// Some typical non-IP packet types.
	// "dl_type=0x0800" can be used to indicate an IP packet too, but as it is not
	// a common way, here we simply assume "dl_type=" is used for non-IP types
	// only.
	nonIPDLTypes = []string{"arp", "rarp", "ip6", "dl_type="}
)

type ovsCtlClient struct {
	bridge string
}

func NewClient(bridge string) *ovsCtlClient {
	return &ovsCtlClient{bridge}
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
	var inPort, nwSrc, nwDst, dlSrc, dlDst, ip, nwTTL string

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
		if strings.Contains(req.Flow, "nw_src=") {
			return "", newBadRequestError("duplicated 'nw_src' in flow")
		} else {
			nwSrc = fmt.Sprintf("nw_src=%s,", req.SrcIP.String())
		}
	}
	if req.DstIP != nil {
		// Do not allow overriding destination IP.
		if strings.Contains(req.Flow, "nw_dst=") {
			return "", newBadRequestError("duplicated 'nw_dst' in flow")
		} else {
			nwDst = fmt.Sprintf("nw_dst=%s,", req.DstIP.String())
		}
	}

	// Always allow overriding source and destination MACs.
	if req.SrcMAC != nil && !strings.Contains(req.Flow, "dl_src=") {
		dlSrc = fmt.Sprintf("dl_src=%s,", req.SrcMAC.String())
	}
	if req.DstMAC != nil && !strings.Contains(req.Flow, "dl_dst=") {
		dlDst = fmt.Sprintf("dl_dst=%s,", req.DstMAC.String())
	}
	if !nonIP && (nwSrc != "" || nwDst != "") {
		// Set DL type to IPv4.
		ip = "ip,"
		for _, s := range ipAndNWProtos {
			if strings.Contains(req.Flow, s) {
				// IP or IP protocol is already specified in flow. No need to add "ip" in
				// flow.
				ip = ""
				break
			}
		}
		if !strings.Contains(req.Flow, "nw_ttl=") {
			// Add default IP TTL.
			nwTTL = "nw_ttl=64,"
		}
	}

	// "ip" or IP protocol must be set before "nw_ttl", "nw_src", "nw_dst", and
	// "tp_port".
	flow := inPort + dlSrc + dlDst + ip + req.Flow + "," + nwTTL + nwSrc + nwDst
	return c.runTracing(flow)
}

func (c *ovsCtlClient) runTracing(flow string) (string, error) {
	out, execErr := c.runAppctlCmd("ofproto/trace", flow)
	if execErr != nil {
		return "", execErr
	}
	return string(out), nil
}

func (c *ovsCtlClient) runAppctlCmd(cmd string, args ...string) ([]byte, *ExecError) {
	// Use the control UNIX domain socket to connect to ovs-vswitchd, as Agent can
	// run in a different PID namespace from ovs-vswitchd, and so might not be able
	// to reach ovs-vswitchd using the PID.
	cmdStr := fmt.Sprintf("ovs-appctl -t %s %s %s", ovsVSwitchdUDS, cmd, c.bridge)
	cmdStr = cmdStr + " " + strings.Join(args, " ")
	out, err := exec.Command("/bin/sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		return nil, newExecError(err, string(out))
	}
	return out, nil
}
