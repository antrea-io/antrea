package connections

import (
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/broadcaster"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	"k8s.io/klog/v2"
)

type L7EventMapGetter interface {
	ConsumeL7EventMap() map[connection.ConnectionKey]connection.L7ProtocolFields
}

type PollerConfig struct {
	PollInterval          time.Duration
	V4Enabled             bool
	V6Enabled             bool
	ConnectUplinkToBridge bool
}

func ZonesFromConfig(c PollerConfig) []uint16 {
	var zones []uint16
	if c.V4Enabled {
		if c.ConnectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPCtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZone)
		}
	}
	if c.V6Enabled {
		if c.ConnectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPv6CtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZoneV6)
		}
	}

	return zones
}

type Poller struct {
	connTrackDumper  ConnTrackDumper
	config           PollerConfig
	l7EventMapGetter L7EventMapGetter

	publisher broadcaster.Publisher

	zones []uint16
}

func NewPoller(ctDumper ConnTrackDumper, publisher broadcaster.Publisher, l7EventMapGetter L7EventMapGetter, config PollerConfig) *Poller {
	return &Poller{
		connTrackDumper:  ctDumper,
		l7EventMapGetter: l7EventMapGetter,
		config:           config,
		zones:            ZonesFromConfig(config),
		publisher:        publisher,
	}
}

func (p *Poller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Started conntrack poller", "interval", p.config.PollInterval)

	pollTicker := time.NewTicker(p.config.PollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-pollTicker.C:
			conns, l7Events, _, err := p.Poll()
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.ErrorS(err, "Error during conntrack poll cycle")
			}

			p.publisher.Publish(conns, l7Events)
		}
	}
}

// Poll calls into conntrackDumper interface to dump conntrack flows. It returns the connections
// filtered by zones, the l7Events, and number of connections for each address family, as a slice.
// In dual-stack clusters, the slice will contain 2 values (number of IPv4 connections first, then
// number of IPv6 connections).
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (p *Poller) Poll() ([]*connection.Connection, map[connection.ConnectionKey]connection.L7ProtocolFields, []int, error) {
	klog.V(2).Info("Polling conntrack and updating connection store")
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		metrics.ConntrackPollCycleDuration.Observe(duration.Seconds())
		klog.V(2).InfoS("Polled conntrack and updated connection store", "duration", duration)
	}()

	// DeepCopy the L7EventMap before polling the conntrack table to match corresponding L4 connection with L7 events
	// and avoid missing the L7 events for corresponding L4 connection
	var l7EventMap map[connection.ConnectionKey]connection.L7ProtocolFields
	if p.l7EventMapGetter != nil {
		l7EventMap = p.l7EventMapGetter.ConsumeL7EventMap()
	}

	var connsLens []int
	var totalConns int
	var filteredConnsList []*connection.Connection
	for _, zone := range p.zones {
		filteredConnsListPerZone, totalConnsPerZone, err := p.connTrackDumper.DumpFlows(zone)
		if err != nil {
			return nil, nil, nil, err
		}
		totalConns += totalConnsPerZone
		filteredConnsList = append(filteredConnsList, filteredConnsListPerZone...)
		connsLens = append(connsLens, len(filteredConnsList))
	}

	metrics.TotalConnectionsInConnTrackTable.Set(float64(totalConns))
	maxConns, err := p.connTrackDumper.GetMaxConnections()
	if err != nil {
		return nil, nil, nil, err
	}
	metrics.MaxConnectionsInConnTrackTable.Set(float64(maxConns))
	klog.V(2).Infof("Conntrack polling successful")
	return filteredConnsList, l7EventMap, connsLens, nil
}
