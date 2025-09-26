package connections

import (
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"k8s.io/klog/v2"
)

type CTResult struct {
	conns    []*connection.Connection
	l7Events map[connection.ConnectionKey]L7ProtocolFields
}

type ConntrackFetcher struct {
	connDumper       ConnTrackDumper
	pollInterval     time.Duration
	l7EventMapGetter L7EventMapGetter

	zones []uint16

	outCh chan CTResult
}

func NewConntrackFetcher(
	connTrackDumper ConnTrackDumper,
	v4Enabled bool,
	v6Enabled bool,
	l7EventMapGetterFunc L7EventMapGetter,
	o *options.FlowExporterOptions) *ConntrackFetcher {

	return &ConntrackFetcher{
		zones: ZoneGetter{
			v4Enabled:             v4Enabled,
			v6Enabled:             v6Enabled,
			connectUplinkToBridge: o.ConnectUplinkToBridge,
		}.Get(),
		pollInterval: o.PollInterval,

		connDumper:       connTrackDumper,
		l7EventMapGetter: l7EventMapGetterFunc,
	}
}

func (f *ConntrackFetcher) Start(stopCh <-chan struct{}) <-chan CTResult {
	if f.outCh == nil {
		f.outCh = make(chan CTResult, 10)
		go f.run(stopCh)
	}
	return f.outCh
}

func (f *ConntrackFetcher) run(stopCh <-chan struct{}) {
	pollTicker := time.NewTicker(f.pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-pollTicker.C:
			err := f.poll()
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.Errorf("Error during conntrack poll cycle: %v", err)
			}
		}
	}
}

func (f *ConntrackFetcher) poll() error {
	var l7EventMap map[connection.ConnectionKey]L7ProtocolFields
	if f.l7EventMapGetter != nil {
		l7EventMap = f.l7EventMapGetter.ConsumeL7EventMap()
	}

	var filteredConnsList []*connection.Connection
	for _, zone := range f.zones {
		filteredConnsListPerZone, _, err := f.connDumper.DumpFlows(zone)
		if err != nil {
			return err
		}
		filteredConnsList = append(filteredConnsList, filteredConnsListPerZone...)
	}

	f.send(filteredConnsList, l7EventMap)
	return nil
}

func (f *ConntrackFetcher) send(conns []*connection.Connection, l7EventMap map[connection.ConnectionKey]L7ProtocolFields) {
	if f.outCh != nil {
		f.outCh <- CTResult{
			conns:    conns,
			l7Events: l7EventMap,
		}
	}
}
