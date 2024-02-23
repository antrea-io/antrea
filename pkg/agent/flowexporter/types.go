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

package flowexporter

import (
	"net/netip"
	"time"
)

// We use a type alias here, as a way to minimize code changes: ConnectionKey used to be its own
// type, and ConnectionKey values were generated from Tuple values. Because of changes to the Tuple
// type (net.IP -> netip.Addr), Tuple is now comparable and can be used as a map key directly.
type ConnectionKey = Tuple

type ConnectionMapCallBack func(key ConnectionKey, conn *Connection) error

type Tuple struct {
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

type Connection struct {
	// Fields from conntrack flows
	ID        uint32
	Timeout   uint32
	StartTime time.Time
	// For invalid and closed connections or deny connections: StopTime is the time when connection
	// was updated last.
	// For established connections: StopTime is latest time when it was polled.
	StopTime time.Time
	// LastExportTime is used to decide whether a connection is stale.
	LastExportTime time.Time
	IsActive       bool
	// IsPresent flag helps in cleaning up connections when they are not in conntrack table anymore.
	IsPresent bool
	// ReadyToDelete marks whether we can safely delete the connection from the connection map.
	ReadyToDelete      bool
	Zone               uint16
	Mark               uint32
	StatusFlag         uint32
	Labels, LabelsMask []byte
	// TODO: Have a separate field for protocol. No need to keep it in Tuple.
	FlowKey                        Tuple
	OriginalPackets, OriginalBytes uint64
	// Fields specific to Antrea
	SourcePodNamespace             string
	SourcePodName                  string
	DestinationPodNamespace        string
	DestinationPodName             string
	DestinationServicePortName     string
	OriginalDestinationAddress     netip.Addr
	OriginalDestinationPort        uint16
	IngressNetworkPolicyName       string
	IngressNetworkPolicyNamespace  string
	IngressNetworkPolicyType       uint8
	IngressNetworkPolicyRuleName   string
	IngressNetworkPolicyRuleAction uint8
	EgressNetworkPolicyName        string
	EgressNetworkPolicyNamespace   string
	EgressNetworkPolicyType        uint8
	EgressNetworkPolicyRuleName    string
	EgressNetworkPolicyRuleAction  uint8
	PrevPackets, PrevBytes         uint64
	// Fields specific to conntrack connections
	ReversePackets, ReverseBytes         uint64
	PrevReversePackets, PrevReverseBytes uint64
	TCPState                             string
	PrevTCPState                         string
	FlowType                             uint8
	EgressName                           string
	EgressIP                             string
	AppProtocolName                      string
	HttpVals                             string
	EgressNodeName                       string
}

type ItemToExpire struct {
	Conn             *Connection
	ActiveExpireTime time.Time
	IdleExpireTime   time.Time
	// Index in the priority queue (heap)
	Index int
}

type FlowExporterOptions struct {
	FlowCollectorAddr      string
	FlowCollectorProto     string
	ActiveFlowTimeout      time.Duration
	IdleFlowTimeout        time.Duration
	StaleConnectionTimeout time.Duration
	PollInterval           time.Duration
	ConnectUplinkToBridge  bool
}
