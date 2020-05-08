package flowexporter

import (
	"net"
	"time"
)

const (
	PollInterval = 5 * time.Second
)

type ConnectionKey [5]string

type Tuple struct {
	SourceAddress      net.IP
	DestinationAddress net.IP
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

type Connection struct {
	// Fields from conntrack flows
	ID                             uint32
	Timeout                        uint32
	StartTime                      time.Time
	StopTime                       time.Time
	Zone                           uint16
	StatusFlag                     uint32
	TupleOrig, TupleReply          Tuple
	OriginalPackets, OriginalBytes uint64
	ReversePackets, ReverseBytes   uint64
	// Fields specific to Antrea
	SourcePodNamespace      string
	SourcePodName           string
	DestinationPodNamespace string
	DestinationPodName      string
}
