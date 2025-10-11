// Copyright 2025 Antrea Authors.
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

package testing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/vmware/go-ipfix/pkg/registry"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/openflow"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"

	v1 "k8s.io/api/core/v1"
	clocktesting "k8s.io/utils/clock/testing"
)

var DefaultCmpOptions cmp.Options = cmp.Options{
	cmpopts.EquateComparable(netip.Addr{}),
	cmpopts.EquateEmpty(),
}

type connOpt func(*connection.Connection)

func WithPodInfo(srcNamespace, srcPod, dstNamespace, dstPod string) connOpt {
	return func(c *connection.Connection) {
		c.SourcePodNamespace = srcNamespace
		c.SourcePodName = srcPod

		c.DestinationPodNamespace = dstNamespace
		c.DestinationPodName = dstPod
	}
}

func WithPodInfoFromPod(src, dst *v1.Pod) connOpt {
	return func(c *connection.Connection) {
		if src != nil {
			c.SourcePodNamespace = src.Namespace
			c.SourcePodName = src.Name
		}

		if dst != nil {
			c.DestinationPodNamespace = dst.Namespace
			c.DestinationPodName = dst.Name
		}
	}
}

func ServiceInfoOpt(namespace, name, port string) connOpt {
	return func(c *connection.Connection) {
		c.DestinationServicePortName = fmt.Sprintf("%s/%s:%s", namespace, name, port)
	}
}

func IngressNPMetadataOpt(namespace, name, uid, ruleName string, policyType v1beta2.NetworkPolicyType) connOpt {
	return func(c *connection.Connection) {
		c.IngressNetworkPolicyNamespace = namespace
		c.IngressNetworkPolicyName = name
		c.IngressNetworkPolicyUID = uid
		c.IngressNetworkPolicyRuleName = ruleName
		c.IngressNetworkPolicyType = utils.PolicyTypeToUint8(policyType)
		c.IngressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
	}
}

func EgressNPMetadataOpt(namespace, name, uid, ruleName string, policyType v1beta2.NetworkPolicyType) connOpt {
	return func(c *connection.Connection) {
		c.EgressNetworkPolicyNamespace = namespace
		c.EgressNetworkPolicyName = name
		c.EgressNetworkPolicyUID = uid
		c.EgressNetworkPolicyRuleName = ruleName
		c.EgressNetworkPolicyType = utils.PolicyTypeToUint8(policyType)
		c.EgressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
	}
}

func WithStats(stats connection.Stats) connOpt {
	return func(c *connection.Connection) {
		c.OriginalStats = stats
	}
}

func IncrementStats(c *connection.Connection) {
	c.OriginalStats.Packets += 10
	c.OriginalStats.Bytes += 100
	c.OriginalStats.ReversePackets += 20
	c.OriginalStats.ReverseBytes += 200
}

func WithPreviousStats(stats connection.Stats) connOpt {
	return func(c *connection.Connection) {
		c.PreviousStats = stats
	}
}

func WithTimeWaitState() connOpt {
	return WithTCPState("TIME_WAIT")
}

func WithCloseState() connOpt {
	return WithTCPState("CLOSE")
}

func WithSYNSentState() connOpt {
	return WithTCPState("SYN_SENT")
}

func WithTCPState(state string) connOpt {
	return func(c *connection.Connection) {
		c.TCPState = state
	}
}

func WithFlowType(ft uint8) connOpt {
	return func(c *connection.Connection) {
		c.FlowType = ft
	}
}

func MarkCTConn(c *connection.Connection) {
	c.IsPresent = true
}

func MarkDenyConn(c *connection.Connection) {
	c.IsDenyFlow = true
	c.IsPresent = false
	c.StopTime = c.StartTime
}

func UpdatedAfter(t time.Duration) connOpt {
	return func(c *connection.Connection) {
		c.LastUpdateTime = c.StartTime.Add(t)
	}
}

func StoppedAfter(t time.Duration) connOpt {
	return func(c *connection.Connection) {
		c.StopTime = c.StartTime.Add(t)
	}
}

func AsUDPConnection(c *connection.Connection) {
	c.TCPState = ""
	c.FlowKey.Protocol = 17
}

func WithRandomOriginalDestinationV4() connOpt {
	return WithOriginalDestination(RandIPv4(), 12345)
}

func WithOriginalDestination(addr netip.Addr, port uint16) connOpt {
	return func(c *connection.Connection) {
		c.OriginalDestinationAddress = addr
		c.OriginalDestinationPort = port
	}
}

func WithServiceMark(c *connection.Connection) {
	c.Mark = openflow.ServiceCTMark.GetValue()
}

func WithServicePortName(namespace, name, port string) connOpt {
	return func(c *connection.Connection) {
		c.DestinationServicePortName = fmt.Sprintf("%s/%s:%s", namespace, name, port)
	}
}

func WithIngressOpenflowID(id uint32) connOpt {
	return func(c *connection.Connection) {
		binary.BigEndian.PutUint32(c.Labels[12:16], id)
	}
}

func WithEgressOpenflowID(id uint32) connOpt {
	return func(c *connection.Connection) {
		binary.BigEndian.PutUint32(c.Labels[8:12], id)
	}
}

func WithEgress(e agenttypes.EgressConfig) connOpt {
	return func(c *connection.Connection) {
		c.EgressName = e.Name
		c.EgressUID = string(e.UID)
		c.EgressIP = e.EgressIP
		c.EgressNodeName = e.EgressNode
	}
}

type ConnFunc func(opts ...connOpt) *connection.Connection

func (fn ConnFunc) ConnectionKey(opts ...connOpt) connection.ConnectionKey {
	return connection.NewConnectionKey(fn(opts...))
}

func (fn ConnFunc) OriginalStats() connection.Stats {
	return fn().OriginalStats
}

func (fn ConnFunc) TCPState() string {
	return fn().TCPState
}

func (fn ConnFunc) OriginalDestinationAddress() netip.Addr {
	return fn().OriginalDestinationAddress
}

func (fn ConnFunc) OriginalDestinationPort() uint16 {
	return fn().OriginalDestinationPort
}

func GenerateConnectionFnWithClock(clock *clocktesting.FakeClock, opts ...connOpt) ConnFunc {
	return generateConnectionFn(clock, false, opts...)
}

func GenerateConnectionFn(opts ...connOpt) ConnFunc {
	clock := clocktesting.NewFakeClock(time.Now())
	return generateConnectionFn(clock, false, opts...)
}

func GenerateIPV6ConnectionFn(opts ...connOpt) ConnFunc {
	clock := clocktesting.NewFakeClock(time.Now())
	return generateConnectionFn(clock, true, opts...)
}

func generateConnectionFn(clock *clocktesting.FakeClock, isIPV6 bool, opts ...connOpt) ConnFunc {
	now := clock.Now()
	key := GenerateConnectionKey(isIPV6)
	return func(subOpts ...connOpt) *connection.Connection {
		conn := &connection.Connection{
			StartTime: now,
			TCPState:  "SYN_SENT",
			FlowKey:   key,
			Labels:    make([]byte, 16),
		}
		WithOriginalDestination(key.DestinationAddress, key.DestinationPort)(conn)

		for _, opt := range opts {
			opt(conn)
		}

		for _, opt := range subOpts {
			opt(conn)
		}

		return conn
	}
}

func GenerateConnectionKey(isIPV6 bool) connection.ConnectionKey {
	var srcAddr netip.Addr
	var dstAddr netip.Addr

	if isIPV6 {
		srcAddr = RandIPv6()
		dstAddr = RandIPv6()
	} else {
		srcAddr = RandIPv4()
		dstAddr = RandIPv6()
	}

	key := connection.Tuple{
		SourceAddress:      srcAddr,
		DestinationAddress: dstAddr,
		Protocol:           6,
		SourcePort:         50000,
		DestinationPort:    80,
	}
	return key
}
