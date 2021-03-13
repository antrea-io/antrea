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
	"net"
	"time"
)

type ConnectionKey [5]string

type ConnectionMapCallBack func(key ConnectionKey, conn Connection) error
type FlowRecordCallBack func(key ConnectionKey, record FlowRecord) error

type Tuple struct {
	SourceAddress      net.IP
	DestinationAddress net.IP
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

type Connection struct {
	// Fields from conntrack flows
	ID        uint32
	Timeout   uint32
	StartTime time.Time
	// For invalid and closed connections: StopTime is the time when connection was updated last.
	// For established connections: StopTime is latest time when it was polled.
	StopTime time.Time
	// IsPresent flag helps in cleaning up connections when they are not in conntrack table anymore.
	IsPresent          bool
	Zone               uint16
	Mark               uint32
	StatusFlag         uint32
	Labels, LabelsMask []byte
	// TODO: Have a separate field for protocol. No need to keep it in Tuple.
	TupleOrig, TupleReply          Tuple
	OriginalPackets, OriginalBytes uint64
	ReversePackets, ReverseBytes   uint64
	// Fields specific to Antrea
	SourcePodNamespace            string
	SourcePodName                 string
	DestinationPodNamespace       string
	DestinationPodName            string
	DestinationServicePortName    string
	IngressNetworkPolicyName      string
	IngressNetworkPolicyNamespace string
	EgressNetworkPolicyName       string
	EgressNetworkPolicyNamespace  string
}

type FlowRecord struct {
	Conn               Connection
	PrevPackets        uint64
	PrevBytes          uint64
	PrevReversePackets uint64
	PrevReverseBytes   uint64
	IsIPv6             bool
	LastExportTime     time.Time
	IsActive           bool
}
