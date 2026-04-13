// Copyright 2026 Antrea Authors.
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

	"antrea.io/antrea/v2/pkg/agent/metrics"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	"antrea.io/antrea/v2/pkg/util/channel"
)

type Poller struct {
	connTrackDumper ConnTrackDumper

	pollInterval          time.Duration
	v4Enabled             bool
	v6Enabled             bool
	connectUplinkToBridge bool

	notifier channel.Notifier

	zones []uint16
}

func NewPoller(ctDumper ConnTrackDumper, notifier channel.Notifier, pollInterval time.Duration, v4Enabled, v6Enabled, connectUplinkToBridge bool) *Poller {
	// Zone 0 is polled first so that zone-zero connections (before Antrea
	// DNAT/SNAT) are available in the FromExternalCorrelator before the
	// corresponding Antrea-zone connections are processed.
	zones := []uint16{0}
	if v4Enabled {
		if connectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPCtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZone)
		}
	}
	if v6Enabled {
		if connectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPv6CtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZoneV6)
		}
	}

	return &Poller{
		connTrackDumper:       ctDumper,
		zones:                 zones,
		notifier:              notifier,
		pollInterval:          pollInterval,
		v4Enabled:             v4Enabled,
		v6Enabled:             v6Enabled,
		connectUplinkToBridge: connectUplinkToBridge,
	}
}

func (p *Poller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Started conntrack poller", "interval", p.pollInterval)

	pollTicker := time.NewTicker(p.pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-pollTicker.C:
			batch, _, err := p.Poll()
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.ErrorS(err, "Error during conntrack poll cycle")
				continue
			}

			if p.notifier != nil {
				p.notifier.Notify(batch)
			}
		}
	}
}

// Poll calls into conntrackDumper interface to dump conntrack flows per zone. It returns a
// ConntrackPollBatch (zone 0 vs Antrea zones splitted) and per-zone filtered connection
// counts. In dual-stack clusters, connsLens has one entry per polled zone (zone 0 first, then
// IPv4 Antrea zone, then IPv6 Antrea zone when enabled).
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (p *Poller) Poll() (*ConntrackPollBatch, []int, error) {
	klog.V(2).InfoS("Polling conntrack")
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		metrics.ConntrackPollCycleDuration.Observe(duration.Seconds())
		klog.V(2).InfoS("Polled conntrack", "duration", duration)
	}()

	batch := &ConntrackPollBatch{}
	var connsLens []int
	var totalConns int
	for _, zone := range p.zones {
		filteredConnsListPerZone, totalConnsPerZone, err := p.connTrackDumper.DumpFlows(zone)
		if err != nil {
			return nil, nil, err
		}
		totalConns += totalConnsPerZone
		if zone == 0 {
			batch.ZoneZero = append(batch.ZoneZero, filteredConnsListPerZone...)
		} else {
			batch.AntreaZone = append(batch.AntreaZone, filteredConnsListPerZone...)
		}
		connsLens = append(connsLens, len(filteredConnsListPerZone))
	}

	metrics.TotalConnectionsInConnTrackTable.Set(float64(totalConns))
	maxConns, err := p.connTrackDumper.GetMaxConnections()
	if err != nil {
		return nil, nil, err
	}
	metrics.MaxConnectionsInConnTrackTable.Set(float64(maxConns))
	return batch, connsLens, nil
}
