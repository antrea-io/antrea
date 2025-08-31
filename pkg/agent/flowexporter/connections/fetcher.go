package connections

import (
	"time"

	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/objectstore"
	"k8s.io/klog/v2"
)

type ConntrackFetcher struct {
	connDumper       ConnTrackDumper
	pollInterval     time.Duration
	l7EventMapGetter L7EventMapGetter

	zones ZoneGetter

	podInfoAug       Augmenter
	serviceInfoAug   Augmenter
	networkPolicyAug Augmenter
	egressInfoAug    Augmenter
}

func NewConntrackFetcher(
	connTrackDumper ConnTrackDumper,
	v4Enabled bool,
	v6Enabled bool,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	podStore objectstore.PodStore,
	proxier proxy.Proxier,
	l7EventMapGetterFunc L7EventMapGetter,
	egressQuerier querier.EgressQuerier,
	nodeRouteController *noderoute.Controller,
	isNetworkPolicyOnly bool,
	o *options.FlowExporterOptions) *ConntrackFetcher {

	podInfoAug := &podInfoAugmenter{
		podStore: podStore,
	}
	serviceInfoAug := &serviceInfoAugmenter{
		antreaProxier: proxier,
	}
	networkPolicyAug := &networkPolicyMetadataAugmenter{
		networkPolicyQuerier: npQuerier,
	}
	egressInfoAug := &egressInfoAugmenter{
		nodeRouteController: nodeRouteController,
		egressQuerier:       egressQuerier,
		isNetworkPolicyOnly: isNetworkPolicyOnly,
	}

	return &ConntrackFetcher{
		zones: ZoneGetter{
			v4Enabled:             v4Enabled,
			v6Enabled:             v6Enabled,
			connectUplinkToBridge: o.ConnectUplinkToBridge,
		},
		pollInterval: o.PollInterval,

		connDumper:       connTrackDumper,
		l7EventMapGetter: l7EventMapGetterFunc,

		podInfoAug:       podInfoAug,
		serviceInfoAug:   serviceInfoAug,
		networkPolicyAug: networkPolicyAug,
		egressInfoAug:    egressInfoAug,
	}
}

func (f *ConntrackFetcher) Run(stopCh <-chan struct{}, store CTStore) {
	pollTicker := time.NewTicker(f.pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-pollTicker.C:
			err := f.PollAndStore(store)
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.Errorf("Error during conntrack poll cycle: %v", err)
			}
		}
	}
}

func (f *ConntrackFetcher) PollAndStore(store CTStore) error {
	// var l7EventMap map[connection.ConnectionKey]L7ProtocolFields
	// if f.l7EventMapGetter != nil {
	// 	l7EventMap = f.l7EventMapGetter.ConsumeL7EventMap()
	// }

	var filteredConnsList []*connection.Connection
	for _, zone := range f.zones.Get() {
		filteredConnsListPerZone, _, err := f.connDumper.DumpFlows(zone)
		if err != nil {
			return err
		}
		filteredConnsList = append(filteredConnsList, filteredConnsListPerZone...)
	}

	// Augment the connections
	batch := make([]connection.Connection, 0, len(filteredConnsList))
	for _, conn := range filteredConnsList {
		f.podInfoAug.Augment(conn)

		if conn.SourcePodName == "" && conn.DestinationPodName == "" {
			// We don't add connections to connection map if we can't find the pod information for both srcPod and dstPod
			klog.V(5).InfoS("Skip this connection as we cannot map any of the connection IPs to a local Pod", "srcIP", conn.FlowKey.SourceAddress.String(), "dstIP", conn.FlowKey.DestinationAddress.String())
			return nil
		}

		f.serviceInfoAug.Augment(conn)
		f.networkPolicyAug.Augment(conn)
		f.egressInfoAug.Augment(conn) // Double check this. The previous implementation only update this on export.

		batch = append(batch, *conn)
	}

	store.SubmitConnections(batch)
	return nil
}
