// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connections

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/ovs/ovsctl"
)

// Following map is for converting protocol name (string) to protocol identifier
var (
	// Mapping is defined at https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/netfilter/nf_conntrack_common.h#L42
	conntrackStatusMap = map[string]uint32{
		"EXPECTED":      uint32(1),
		"SEEN_REPLY":    uint32(1 << 1),
		"ASSURED":       uint32(1 << 2),
		"CONFIRMED":     uint32(1 << 3),
		"SRC_NAT":       uint32(1 << 4),
		"DST_NAT":       uint32(1 << 5),
		"NAT_MASK":      uint32(1<<5 | 1<<4),
		"SEQ_ADJUST":    uint32(1 << 6),
		"SRC_NAT_DONE":  uint32(1 << 7),
		"DST_NAT_DONE":  uint32(1 << 8),
		"NAT_DONE_MASK": uint32(1<<8 | 1<<7),
		"DYING":         uint32(1 << 9),
		"FIXED_TIMEOUT": uint32(1 << 10),
		"TEMPLATE":      uint32(1 << 11),
		"UNTRACKED":     uint32(1 << 12),
		"HELPER":        uint32(1 << 13),
		"OFFLOAD":       uint32(1 << 14),
	}
)

// connTrackOvsCtl implements ConnTrackDumper. This supports OVS userspace datapath scenarios.
var _ ConnTrackDumper = new(connTrackOvsCtl)

type connTrackOvsCtl struct {
	nodeConfig           *config.NodeConfig
	serviceCIDRv4        netip.Prefix
	serviceCIDRv6        netip.Prefix
	ovsctlClient         ovsctl.OVSCtlClient
	isAntreaProxyEnabled bool
}

func NewConnTrackOvsAppCtl(nodeConfig *config.NodeConfig, serviceCIDRv4 netip.Prefix, serviceCIDRv6 netip.Prefix, isAntreaProxyEnabled bool) *connTrackOvsCtl {
	return &connTrackOvsCtl{
		nodeConfig,
		serviceCIDRv4,
		serviceCIDRv6,
		ovsctl.NewClient(nodeConfig.OVSBridge),
		isAntreaProxyEnabled,
	}
}

// DumpFlows uses "ovs-appctl dpctl/dump-conntrack" to dump conntrack flows in the Antrea ZoneID.
func (ct *connTrackOvsCtl) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, int, error) {
	svcCIDR := ct.serviceCIDRv4
	if zoneFilter == openflow.CtZoneV6 {
		svcCIDR = ct.serviceCIDRv6
	}
	conns, totalConns, err := ct.ovsAppctlDumpConnections(zoneFilter)
	if err != nil {
		return nil, 0, fmt.Errorf("error when dumping flows from conntrack: %v", err)
	}

	filteredConns := filterAntreaConns(conns, ct.nodeConfig, svcCIDR, zoneFilter, ct.isAntreaProxyEnabled)
	klog.V(2).Infof("FlowExporter considered flows: %d", len(filteredConns))

	return filteredConns, totalConns, nil
}

func (ct *connTrackOvsCtl) ovsAppctlDumpConnections(zoneFilter uint16) ([]*flowexporter.Connection, int, error) {
	// Dump conntrack using ovs-appctl dpctl/dump-conntrack
	cmdOutput, execErr := ct.ovsctlClient.RunAppctlCmd("dpctl/dump-conntrack", false, "-m", "-s")
	if execErr != nil {
		return nil, 0, fmt.Errorf("error when executing dump-conntrack command: %v", execErr)
	}

	// Parse the output to get the flow strings and convert them to Antrea connections.
	antreaConns := make([]*flowexporter.Connection, 0)
	outputFlow := strings.Split(string(cmdOutput), "\n")
	for _, flow := range outputFlow {
		conn, err := flowStringToAntreaConnection(flow, zoneFilter)
		if err != nil {
			klog.V(4).Infof("Ignoring the flow from conntrack dump due to parsing error: %v", err)
			continue
		}
		if conn != nil {
			antreaConns = append(antreaConns, conn)
		}
	}

	klog.V(2).Infof("FlowExporter considered flows in conntrack: %d", len(antreaConns))
	return antreaConns, len(outputFlow), nil
}

// flowStringToAntreaConnection parses the flow string and converts to Antrea connection.
// Example of flow string:
// "tcp,orig=(src=127.0.0.1,dst=127.0.0.1,sport=45218,dport=2379,packets=320108,bytes=24615344),reply=(src=127.0.0.1,dst=127.0.0.1,sport=2379,dport=45218,packets=239595,bytes=24347883),start=2020-07-24T05:07:03.998,id=3750535678,status=SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT_DONE|DST_NAT_DONE,timeout=86399,labels=0x200000001,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)"
func flowStringToAntreaConnection(flow string, zoneFilter uint16) (*flowexporter.Connection, error) {
	conn := flowexporter.Connection{}
	flowSlice := strings.Split(flow, ",")
	isReply := false
	inZone := false
	for _, fs := range flowSlice {
		// Indicator to populate reply or reverse fields
		if strings.Contains(fs, "reply") {
			isReply = true
		}
		switch {
		case hasAnyProto(fs):
			// Proto identifier
			proto, err := flowexporter.LookupProtocolMap(fs)
			if err != nil {
				return nil, err
			}
			conn.FlowKey.Protocol = proto
		case strings.Contains(fs, "src"):
			fields := strings.Split(fs, "=")
			if !isReply {
				srcAddr, err := netip.ParseAddr(fields[len(fields)-1])
				if err != nil {
					return nil, fmt.Errorf("parsing source address failed: %w", err)
				}
				conn.FlowKey.SourceAddress = srcAddr
			} else {
				dstAddr, err := netip.ParseAddr(fields[len(fields)-1])
				if err != nil {
					return nil, fmt.Errorf("parsing destination address failed: %w", err)
				}
				conn.FlowKey.DestinationAddress = dstAddr
			}
		case strings.Contains(fs, "dst"):
			fields := strings.Split(fs, "=")
			if !isReply {
				svcAddr, err := netip.ParseAddr(fields[len(fields)-1])
				if err != nil {
					return nil, fmt.Errorf("parsing original destination address failed: %w", err)
				}
				conn.OriginalDestinationAddress = svcAddr
			}
		case strings.Contains(fs, "sport"):
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conversion of sport %s to int failed: %v", fields[len(fields)-1], err)
			}
			if !isReply {
				conn.FlowKey.SourcePort = uint16(val)
			} else {
				conn.FlowKey.DestinationPort = uint16(val)
			}
		case strings.Contains(fs, "dport"):
			// dport field could be the last tuple field in ovs-dpctl output format.
			fs = strings.TrimSuffix(fs, ")")
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conversion of dport %s to int failed: %v", fields[len(fields)-1], err)
			}
			if !isReply {
				conn.OriginalDestinationPort = uint16(val)
			}
		case strings.Contains(fs, "packets"):
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("conversion of packets %s to int failed: %v", fields[len(fields)-1], err)
			}
			if !isReply {
				conn.OriginalPackets = uint64(val)
			} else {
				conn.ReversePackets = uint64(val)
			}
		case strings.Contains(fs, "bytes"):
			fs = strings.TrimSuffix(fs, ")")
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("conversion of bytes %s to int failed: %v", fields[len(fields)-1], err)
			}
			if !isReply {
				conn.OriginalBytes = uint64(val)
			} else {
				conn.ReverseBytes = uint64(val)
			}
		case strings.Contains(fs, "start"):
			fs = strings.TrimSuffix(fs, ")")
			fields := strings.Split(fs, "=")
			// Append "Z" to meet RFC3339 standard because flow string doesn't have timezone information
			timeString := fields[len(fields)-1] + "Z"
			val, err := time.Parse(time.RFC3339, timeString)
			if err != nil {
				return nil, fmt.Errorf("parsing start time %s failed: %v", timeString, err)
			}
			conn.StartTime = val
		// TODO: We didn't find stoptime related field in flow string right now, need to investigate how stoptime is recorded and dumped.
		case strings.Contains(fs, "status"):
			fields := strings.Split(fs, "=")
			conn.StatusFlag = statusStringToStateFlag(fields[len(fields)-1])
		case strings.Contains(fs, "zone"):
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conversion of zone %s to int failed: %v", fields[len(fields)-1], err)
			}
			if zoneFilter != uint16(val) {
				break
			}
			inZone = true
			conn.Zone = uint16(val)
		case strings.Contains(fs, "mark"):
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("conversion of mark '%s' to int failed: %v", fields[len(fields)-1], err)
			}
			conn.Mark = uint32(val)
		case strings.Contains(fs, "timeout"):
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("conversion of timeout %s to int failed: %v", fields[len(fields)-1], err)
			}
			conn.Timeout = uint32(val)
		case strings.Contains(fs, "labels"):
			fields := strings.Split(fs, "=")
			labelStr := strings.Replace(fields[len(fields)-1], "0x", "", -1)
			// Add leading zeros since DecodeString() expects the input string has even length
			if len(labelStr) < 16 {
				labelStr = strings.Repeat("0", 16-len(labelStr)) + labelStr
			}
			hexval, err := hex.DecodeString(labelStr)
			if err != nil {
				return nil, fmt.Errorf("conversion of label string %s to []byte failed: %v", labelStr, err)
			}
			// Reverse the []byte slice to align with kernel side's result which is little endian
			for i := 0; i < len(hexval)/2; i++ {
				hexval[i], hexval[len(hexval)-i-1] = hexval[len(hexval)-i-1], hexval[i]
			}
			conn.Labels = hexval
		case strings.Contains(fs, "id"):
			fields := strings.Split(fs, "=")
			val, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("conversion of id %s to int failed: %v", fields[len(fields)-1], err)
			}
			conn.ID = uint32(val)
		case strings.Contains(fs, "protoinfo"):
			fields := strings.Split(fs, "(")
			// retrieve tcpState from state or state_orig
			if strings.Contains(fields[1], "state") {
				items := strings.Split(fields[1], "=")
				conn.TCPState = items[1]
			}
		}
	}
	if !inZone {
		return nil, nil
	}

	// Add current time as stop time.
	conn.StopTime = time.Now()
	conn.IsPresent = true

	klog.V(5).Infof("Converted flow string: %v into connection: %+v", flow, conn)

	return &conn, nil
}

func hasAnyProto(text string) bool {
	for proto := range flowexporter.Protocols {
		if strings.Contains(strings.ToLower(text), proto) {
			return true
		}
	}
	return false
}

func (ct *connTrackOvsCtl) GetMaxConnections() (int, error) {
	cmdOutput, execErr := ct.ovsctlClient.RunAppctlCmd("dpctl/ct-get-maxconns", false)
	if execErr != nil {
		return 0, fmt.Errorf("error when executing dpctl/ct-get-maxconns command: %v", execErr)
	}
	maxConns, err := strconv.Atoi(strings.TrimSpace(string(cmdOutput)))
	if err != nil {
		return 0, fmt.Errorf("error when converting dpctl/ct-get-maxconns output '%s' to int", cmdOutput)
	}
	return maxConns, nil
}

func statusStringToStateFlag(status string) uint32 {
	statusFlag := uint32(0)
	statusSlice := strings.Split(status, "|")
	for _, subStatus := range statusSlice {
		statusFlag = statusFlag | conntrackStatusMap[subStatus]
	}
	return statusFlag
}
