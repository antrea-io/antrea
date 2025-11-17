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

package connections

import (
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/broadcaster"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
)

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
	connTrackDumper ConnTrackDumper
	config          PollerConfig

	publisher broadcaster.Publisher

	zones []uint16
}

func NewPoller(ctDumper ConnTrackDumper, publisher broadcaster.Publisher, config PollerConfig) *Poller {
	return &Poller{
		connTrackDumper: ctDumper,
		config:          config,
		zones:           ZonesFromConfig(config),
		publisher:       publisher,
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
			conns, _, err := p.Poll()
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.ErrorS(err, "Error during conntrack poll cycle")
			}

			p.publisher.Publish(conns)
		}
	}
}

// Poll calls into conntrackDumper interface to dump conntrack flows. It returns the connections
// filtered by zones, the l7Events, and number of connections for each address family, as a slice.
// In dual-stack clusters, the slice will contain 2 values (number of IPv4 connections first, then
// number of IPv6 connections).
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (p *Poller) Poll() ([]*connection.Connection, []int, error) {
	klog.V(2).Info("Polling conntrack and updating connection store")
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		metrics.ConntrackPollCycleDuration.Observe(duration.Seconds())
		klog.V(2).InfoS("Polled conntrack and updated connection store", "duration", duration)
	}()

	var connsLens []int
	var totalConns int
	var filteredConnsList []*connection.Connection
	for _, zone := range p.zones {
		filteredConnsListPerZone, totalConnsPerZone, err := p.connTrackDumper.DumpFlows(zone)
		if err != nil {
			return nil, nil, err
		}
		totalConns += totalConnsPerZone
		filteredConnsList = append(filteredConnsList, filteredConnsListPerZone...)
		connsLens = append(connsLens, len(filteredConnsList))
	}

	metrics.TotalConnectionsInConnTrackTable.Set(float64(totalConns))
	maxConns, err := p.connTrackDumper.GetMaxConnections()
	if err != nil {
		return nil, nil, err
	}
	metrics.MaxConnectionsInConnTrackTable.Set(float64(maxConns))
	klog.V(2).Infof("Conntrack polling successful")
	return filteredConnsList, connsLens, nil
}
