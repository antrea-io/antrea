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
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/ipfix"
	"net"
	"time"
)

type ConnectionKey [5]string

type FlowRecordUpdate func(key ConnectionKey, cxn Connection) error
type FlowRecordSend func(dataRecord ipfix.IPFIXRecord, record FlowRecord) error

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
	StopTime                       time.Time
	Zone                           uint16
	StatusFlag                     uint32
	// TODO: Have a separate field for protocol. No need to keep it in Tuple.
	TupleOrig, TupleReply          Tuple
	OriginalPackets, OriginalBytes uint64
	ReversePackets, ReverseBytes   uint64
	// Fields specific to Antrea
	SourcePodNamespace      string
	SourcePodName           string
	DestinationPodNamespace string
	DestinationPodName      string
}

type FlowRecord struct {
	Conn               *Connection
	PrevPackets        uint64
	PrevBytes          uint64
	PrevReversePackets uint64
	PrevReverseBytes   uint64
}
