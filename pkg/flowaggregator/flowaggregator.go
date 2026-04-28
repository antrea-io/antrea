// Copyright 2020 Antrea Authors
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

package flowaggregator

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/certificate"
	"antrea.io/antrea/v2/pkg/flowaggregator/collector"
	"antrea.io/antrea/v2/pkg/flowaggregator/exporter"
	"antrea.io/antrea/v2/pkg/flowaggregator/intermediate"
	"antrea.io/antrea/v2/pkg/flowaggregator/options"
	"antrea.io/antrea/v2/pkg/flowaggregator/querier"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
	"antrea.io/antrea/v2/pkg/ipfix"
	"antrea.io/antrea/v2/pkg/util/objectstore"
)

const aggregationWorkerNum = 2

// these are used for unit testing
var (
	newIPFIXExporter = func(clusterUUID uuid.UUID, clusterID string, opt *options.Options, registry ipfix.IPFIXRegistry) exporter.Runner {
		return exporter.NewIPFIXExporter(clusterUUID, clusterID, opt, registry)
	}
	newClickHouseExporter = func(clusterUUID uuid.UUID, opt *options.Options) (exporter.Runner, error) {
		return exporter.NewClickHouseExporter(clusterUUID, opt)
	}
	newS3Exporter = func(clusterUUID uuid.UUID, opt *options.Options) (exporter.Runner, error) {
		return exporter.NewS3Exporter(clusterUUID, opt)
	}
	newLogExporter = func(opt *options.Options) (exporter.Runner, error) {
		return exporter.NewLogExporter(opt)
	}

	newCertificateProvider = func(k8sClient kubernetes.Interface, addr string) *certificate.Provider {
		return certificate.NewProvider(k8sClient, addr)
	}
)

// exporterHandle tracks the lifecycle of a running exporter goroutine.
type exporterHandle struct {
	exporter exporter.Runner
	// cancel cancels the context passed to the exporter's Run method,
	// signalling it to stop.
	cancel context.CancelFunc
	// doneCh is closed when the exporter's Run goroutine has returned.
	doneCh chan struct{}
}

// stop cancels the exporter's context and waits for its goroutine to exit.
func (h *exporterHandle) stop() {
	h.cancel()
	<-h.doneCh
}

type flowAggregator struct {
	aggregatorMode              flowaggregatorconfig.AggregatorMode
	clusterUUID                 uuid.UUID
	clusterID                   string
	aggregatorTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol
	collectorMutex              sync.Mutex
	certificateUpdateCh         chan struct{}
	ipfixCollector              collector.Interface
	grpcCollector               collector.Interface
	aggregationProcess          intermediate.AggregationProcess
	activeFlowRecordTimeout     time.Duration
	inactiveFlowRecordTimeout   time.Duration
	registry                    ipfix.IPFIXRegistry
	flowAggregatorAddress       string
	includePodLabels            bool
	includeK8sUIDs              bool
	k8sClient                   kubernetes.Interface
	podStore                    objectstore.PodStore
	nodeStore                   objectstore.NodeStore
	serviceStore                objectstore.ServiceStore
	numRecordsExported          atomic.Int64
	// numRecordsDropped is always 0 with the current ring-buffer design: records
	// are produced to the buffer (which may discard them when full, counted
	// separately by the buffer itself) and proxyRecord no longer returns an error.
	// Kept for API/metrics compatibility.
	numRecordsDropped atomic.Int64
	updateCh          chan *options.Options
	configFile        string
	configWatcher     *fsnotify.Watcher
	configData        []byte
	APIServer         flowaggregatorconfig.APIServerConfig
	logTickerDuration time.Duration
	recordCh          chan *flowpb.Flow

	recordBuffer        ringbuffer.BroadcastBuffer[*flowpb.Flow]
	ipfixHandle         *exporterHandle
	clickHouseHandle    *exporterHandle
	s3Handle            *exporterHandle
	logHandle           *exporterHandle
	exportersMutex      sync.Mutex
	certificateProvider *certificate.Provider
	nodeIndexer         cache.Indexer
}

func NewFlowAggregator(
	k8sClient kubernetes.Interface,
	clusterUUID uuid.UUID,
	podStore objectstore.PodStore,
	nodeStore objectstore.NodeStore,
	serviceStore objectstore.ServiceStore,
	configFile string,
	nodeInformer coreinformers.NodeInformer,
) (*flowAggregator, error) {
	if len(configFile) == 0 {
		return nil, fmt.Errorf("configFile is empty string")
	}
	registry := ipfix.NewIPFIXRegistry()
	registry.LoadRegistry()

	var err error
	configWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("error when creating file watcher for configuration file: %v", err)
	}
	// When watching the configuration file directly, we have to add the file back to our watcher whenever the configuration
	// file is modified (The watcher cannot track the config file  when the config file is replaced).
	// Watching the directory can prevent us from above situation.
	if err = configWatcher.Add(filepath.Dir(configFile)); err != nil {
		return nil, fmt.Errorf("error when starting file watch on configuration dir: %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read FlowAggregator configuration file: %v", err)
	}
	opt, err := options.LoadConfig(data)
	if err != nil {
		return nil, err
	}

	clusterID := opt.Config.ClusterID
	if clusterID == "" {
		clusterID = clusterUUID.String()
	}

	if nodeInformer == nil {
		return nil, fmt.Errorf("nodeInformer is nil")
	}
	informer := nodeInformer.Informer()
	err = informer.AddIndexers(intermediate.NodeIndexers)
	if err != nil {
		return nil, fmt.Errorf("failed to add nodeIndexer: %v", err)
	}

	fa := &flowAggregator{
		aggregatorMode:              opt.AggregatorMode,
		clusterUUID:                 clusterUUID,
		clusterID:                   clusterID,
		aggregatorTransportProtocol: opt.AggregatorTransportProtocol,
		activeFlowRecordTimeout:     opt.ActiveFlowRecordTimeout,
		inactiveFlowRecordTimeout:   opt.InactiveFlowRecordTimeout,
		registry:                    registry,
		flowAggregatorAddress:       opt.Config.FlowAggregatorAddress,
		includePodLabels:            opt.Config.RecordContents.PodLabels,
		includeK8sUIDs:              opt.Config.FlowCollector.Enable && (*opt.Config.FlowCollector.IncludeK8sUIDs),
		k8sClient:                   k8sClient,
		podStore:                    podStore,
		nodeStore:                   nodeStore,
		serviceStore:                serviceStore,
		updateCh:                    make(chan *options.Options),
		configFile:                  configFile,
		configWatcher:               configWatcher,
		configData:                  data,
		APIServer:                   opt.Config.APIServer,
		logTickerDuration:           time.Minute,
		recordCh:                    make(chan *flowpb.Flow, 128),
		recordBuffer:                ringbuffer.NewBroadcastBuffer[*flowpb.Flow](int(opt.Config.RecordBufferSize)),
		nodeIndexer:                 informer.GetIndexer(),
		certificateProvider:         newCertificateProvider(k8sClient, opt.Config.FlowAggregatorAddress),
		certificateUpdateCh:         make(chan struct{}, 1),
	}
	if opt.AggregatorMode == flowaggregatorconfig.AggregatorModeAggregate {
		if err := fa.InitAggregationProcess(); err != nil {
			return nil, fmt.Errorf("error when creating aggregation process: %w", err)
		}
	}

	klog.InfoS("FlowAggregator initialized", "mode", opt.AggregatorMode, "clusterID", fa.clusterID, "recordBufferSize", opt.Config.RecordBufferSize)
	return fa, nil
}

// launchExporter creates a new consumer from the ring buffer, starts the
// exporter's Run method in a goroutine, and returns a handle for lifecycle
// management.
func (fa *flowAggregator) launchExporter(exp exporter.Runner) *exporterHandle {
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		exp.Run(ctx, fa.recordBuffer)
	}()
	return &exporterHandle{
		exporter: exp,
		cancel:   cancel,
		doneCh:   doneCh,
	}
}

func (fa *flowAggregator) initCollectors() error {
	fa.collectorMutex.Lock()
	defer fa.collectorMutex.Unlock()

	caCert, serverCert, serverKey := fa.certificateProvider.GetTLSConfig()
	grpcCollector, err := collector.NewGRPCCollector(fa.recordCh, caCert, serverKey, serverCert)
	if err != nil {
		return fmt.Errorf("failed to create gRPC collector: %w", err)
	}
	fa.grpcCollector = grpcCollector
	if fa.aggregatorTransportProtocol != flowaggregatorconfig.AggregatorTransportProtocolNone {
		ipfixCollector, err := collector.NewIPFIXCollector(
			fa.recordCh,
			fa.aggregatorTransportProtocol,
			caCert,
			serverKey,
			serverCert,
		)
		if err != nil {
			return fmt.Errorf("failed to create IPFIX collector: %w", err)
		}
		fa.ipfixCollector = ipfixCollector
	}
	return nil
}

func (fa *flowAggregator) InitAggregationProcess() error {
	var err error
	apInput := intermediate.AggregationInput{
		RecordChan:            fa.recordCh,
		WorkerNum:             aggregationWorkerNum,
		ActiveExpiryTimeout:   fa.activeFlowRecordTimeout,
		InactiveExpiryTimeout: fa.inactiveFlowRecordTimeout,
	}
	fa.aggregationProcess, err = intermediate.InitAggregationProcess(apInput, fa.nodeIndexer)
	return err
}

func (fa *flowAggregator) CertificateUpdated() {
	select {
	case fa.certificateUpdateCh <- struct{}{}:
	default:
	}
}

func (fa *flowAggregator) runCollectors(stopCh <-chan struct{}) {
	var collectorWg sync.WaitGroup
	collectorStopCh := make(chan struct{})
	for {
		select {
		case <-stopCh:
			close(collectorStopCh)
			collectorWg.Wait()
			return
		case <-fa.certificateUpdateCh:
			close(collectorStopCh)
			collectorWg.Wait()
		}
		collectorStopCh = make(chan struct{})

		if err := fa.initCollectors(); err != nil {
			klog.ErrorS(err, "failed to initialize collectors")
			return
		}

		collectorWg.Go(func() {
			fa.grpcCollector.Run(collectorStopCh)
		})

		if fa.ipfixCollector != nil {
			collectorWg.Go(func() {
				fa.ipfixCollector.Run(collectorStopCh)
			})
		}
	}
}

func (fa *flowAggregator) Run(stopCh <-chan struct{}) {
	var wg sync.WaitGroup

	// We first wait for the object stores to sync to avoid lookup failures when processing records.
	const objectStoreSyncTimeout = 30 * time.Second
	func() {
		ctx, cancel := context.WithTimeout(wait.ContextForChannel(stopCh), objectStoreSyncTimeout)
		defer cancel()
		klog.InfoS("Waiting for object stores to sync", "timeout", objectStoreSyncTimeout)
		if err := objectstore.WaitForStoreSyncs(ctx, fa.podStore.HasSynced, fa.nodeStore.HasSynced, fa.serviceStore.HasSynced); err != nil {
			// Stores not synced within a reasonable time. We continue with the rest of the
			// function but there may be error logs when processing records.
			klog.ErrorS(err, "Object stores not synced", "timeout", objectStoreSyncTimeout)
			return
		}
		klog.InfoS("Object stores synced")
	}()

	if fa.certificateProvider != nil {
		fa.certificateProvider.AddListener(fa)

		wg.Add(1)
		go func() {
			defer wg.Done()
			fa.certificateProvider.Run(stopCh)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		fa.runCollectors(stopCh)
	}()

	if fa.aggregationProcess != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// blocking function, will return when fa.aggregationProcess.Stop() is called
			fa.aggregationProcess.Start()
		}()
	}

	fa.initExporters()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fa.flowExportLoop(stopCh)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		fa.watchConfiguration(stopCh)
		fa.configWatcher.Close()
	}()
	<-stopCh
	if fa.aggregationProcess != nil {
		fa.aggregationProcess.Stop()
	}
	fa.recordBuffer.Shutdown()
	fa.stopAllExporters()
	if fa.certificateUpdateCh != nil {
		close(fa.certificateUpdateCh)
	}
	wg.Wait()
}

// initExporters reads the initial configuration and launches exporter
// goroutines for all enabled exporters.
func (fa *flowAggregator) initExporters() {
	fa.exportersMutex.Lock()
	defer fa.exportersMutex.Unlock()
	opt, err := options.LoadConfig(fa.configData)
	if err != nil {
		klog.ErrorS(err, "Error loading config during exporter init")
		return
	}
	if opt.Config.FlowCollector.Enable {
		exp := newIPFIXExporter(fa.clusterUUID, fa.clusterID, opt, fa.registry)
		fa.ipfixHandle = fa.launchExporter(exp)
		klog.InfoS("Started IPFIX exporter")
	}
	if opt.Config.ClickHouse.Enable {
		exp, err := newClickHouseExporter(fa.clusterUUID, opt)
		if err != nil {
			klog.ErrorS(err, "Error when creating ClickHouse export process")
		} else {
			fa.clickHouseHandle = fa.launchExporter(exp)
			klog.InfoS("Started ClickHouse exporter")
		}
	}
	if opt.Config.S3Uploader.Enable {
		exp, err := newS3Exporter(fa.clusterUUID, opt)
		if err != nil {
			klog.ErrorS(err, "Error when creating S3 export process")
		} else {
			fa.s3Handle = fa.launchExporter(exp)
			klog.InfoS("Started S3 exporter")
		}
	}
	if opt.Config.FlowLogger.Enable {
		exp, err := newLogExporter(opt)
		if err != nil {
			klog.ErrorS(err, "Error when creating log export process")
		} else {
			fa.logHandle = fa.launchExporter(exp)
			klog.InfoS("Started log exporter")
		}
	}
}

// stopAllExporters stops all running exporter goroutines.
func (fa *flowAggregator) stopAllExporters() {
	fa.exportersMutex.Lock()
	defer fa.exportersMutex.Unlock()
	if fa.ipfixHandle != nil {
		fa.ipfixHandle.stop()
		fa.ipfixHandle = nil
	}
	if fa.clickHouseHandle != nil {
		fa.clickHouseHandle.stop()
		fa.clickHouseHandle = nil
	}
	if fa.s3Handle != nil {
		fa.s3Handle.stop()
		fa.s3Handle = nil
	}
	if fa.logHandle != nil {
		fa.logHandle.stop()
		fa.logHandle = nil
	}
}

// flowExportLoop reads records from recordCh, enriches them, and produces them
// into the ring buffer. Each exporter independently consumes from the buffer.
func (fa *flowAggregator) flowExportLoop(stopCh <-chan struct{}) {
	switch fa.aggregatorMode {
	case flowaggregatorconfig.AggregatorModeAggregate:
		fa.flowExportLoopAggregate(stopCh)
	case flowaggregatorconfig.AggregatorModeProxy:
		fa.flowExportLoopProxy(stopCh)
	}
}

func (fa *flowAggregator) proxyRecord(record *flowpb.Flow) {
	sourceAddress := net.IP(record.Ip.Source).String()
	destinationAddress := net.IP(record.Ip.Destination).String()
	startTime := record.StartTs.AsTime()
	flowType := record.K8S.FlowType
	withSource := record.K8S.SourcePodName != ""
	withDestination := record.K8S.DestinationPodName != ""
	switch {
	// !withDestination should be redundant here
	case flowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE && withSource && !withDestination:
		// egress
		record.FlowDirection = flowpb.FlowDirection_FLOW_DIRECTION_EGRESS
	// !withSource should be redundant here
	case flowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE && !withSource && withDestination:
		// ingress
		record.FlowDirection = flowpb.FlowDirection_FLOW_DIRECTION_INGRESS
	case flowType == flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL && withSource:
		// egress
		record.FlowDirection = flowpb.FlowDirection_FLOW_DIRECTION_EGRESS
	case flowType == flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL && withDestination:
		// ingress
		record.FlowDirection = flowpb.FlowDirection_FLOW_DIRECTION_INGRESS
	default:
		// this covers the IntraNode case
		record.FlowDirection = flowpb.FlowDirection_FLOW_DIRECTION_UNKNOWN
	}
	if flowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE {
		// This is the only case where K8s metadata could be missing
		fa.fillK8sMetadata(sourceAddress, destinationAddress, record, startTime)
	}
	if fa.includeK8sUIDs {
		fa.fillServiceUID(record, startTime)
		fa.fillEgressNodeUID(record, startTime)
	}
	fa.fillPodLabels(sourceAddress, destinationAddress, record, startTime)
	fa.produceRecord(record)
}

func (fa *flowAggregator) flowExportLoopProxy(stopCh <-chan struct{}) {
	logTicker := time.NewTicker(fa.logTickerDuration)
	defer logTicker.Stop()
	recordCh := fa.recordCh

	updateCh := fa.updateCh
	for {
		select {
		case <-stopCh:
			return
		case record, ok := <-recordCh:
			if !ok {
				recordCh = nil
				break
			}
			fa.proxyRecord(record)
		case <-logTicker.C:
			klog.V(4).InfoS("Total number of records received", "count", fa.getNumRecordsReceived())
			klog.V(4).InfoS("Total number of records exported by each active exporter", "count", fa.numRecordsExported.Load())
			klog.V(4).InfoS("Total number of records dropped", "count", fa.numRecordsDropped.Load())
			klog.V(4).InfoS("Number of exporters connected with Flow Aggregator", "count", fa.getNumConnsToCollector())
		case opt, ok := <-updateCh:
			if !ok {
				// set the channel to nil and essentially disable this select case.
				// we could also just return straightaway as this should only happen
				// when stopCh is closed, but maybe it's better to keep stopCh as
				// the only signal for stopping the event loop.
				updateCh = nil
				break
			}
			fa.updateFlowAggregator(opt)
		}
	}
}

func (fa *flowAggregator) flowExportLoopAggregate(stopCh <-chan struct{}) {
	// Every 1s, we check for expired records and we export all of them. 1s is small enough to have good accuracy,
	// and long enough that we don't call the function too often. In the future, we can support handling batches of
	// expired records, which we can add to the ring buffer in a single API call.
	// Note that ActiveFlowRecordTimeout / InactiveFlowRecordTimeout values under 1s are not reasonable and not supported.
	expiredFlowRecordsTicker := time.NewTicker(1 * time.Second)
	defer expiredFlowRecordsTicker.Stop()
	logTicker := time.NewTicker(fa.logTickerDuration)
	defer logTicker.Stop()

	updateCh := fa.updateCh
	for {
		select {
		case <-stopCh:
			return
		case <-expiredFlowRecordsTicker.C:
			if err := fa.aggregationProcess.ForAllExpiredFlowRecordsDo(fa.sendAggregatedRecord); err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
			}
		case <-logTicker.C:
			klog.V(4).InfoS("Total number of records received", "count", fa.getNumRecordsReceived())
			klog.V(4).InfoS("Total number of records exported by each active exporter", "count", fa.numRecordsExported.Load())
			klog.V(4).InfoS("Total number of flows stored in Flow Aggregator", "count", fa.aggregationProcess.GetNumFlows())
			klog.V(4).InfoS("Number of exporters connected with Flow Aggregator", "count", fa.getNumConnsToCollector())
		case opt, ok := <-updateCh:
			if !ok {
				// set the channel to nil and essentially disable this select case.
				// we could also just return straightaway as this should only happen
				// when stopCh is closed, but maybe it's better to keep stopCh as
				// the only signal for stopping the event loop.
				updateCh = nil
				break
			}
			fa.updateFlowAggregator(opt)
		}
	}
}

// produceRecord publishes a flow record into the ring buffer for all active
// exporter consumers to pick up independently.
func (fa *flowAggregator) produceRecord(record *flowpb.Flow) {
	fa.recordBuffer.Produce(record)
	fa.numRecordsExported.Add(1)
}

func (fa *flowAggregator) sendAggregatedRecord(key intermediate.FlowKey, record *intermediate.AggregationFlowRecord) error {
	startTime := record.Record.StartTs.AsTime()
	if !fa.aggregationProcess.AreCorrelatedFieldsFilled(*record) {
		fa.fillK8sMetadata(key.SourceAddress, key.DestinationAddress, record.Record, startTime)
		fa.aggregationProcess.SetCorrelatedFieldsFilled(record, true)
	}
	// Even if fa.includePodLabels is false, we still need to add an empty IE to match the template.
	if !fa.aggregationProcess.AreExternalFieldsFilled(*record) {
		fa.fillPodLabels(key.SourceAddress, key.DestinationAddress, record.Record, startTime)
		if fa.includeK8sUIDs {
			fa.fillServiceUID(record.Record, startTime)
			fa.fillEgressNodeUID(record.Record, startTime)
		}
		fa.aggregationProcess.SetExternalFieldsFilled(record, true)
	}
	// In Aggregate mode, we need to clone the record before placing it in the ring buffer, as
	// it is "owned" by the aggregation process and will be updated as new records are received
	// from the FlowExporters.
	fa.produceRecord(proto.CloneOf(record.Record))
	if err := fa.aggregationProcess.ResetStatAndThroughputElementsInRecord(record.Record); err != nil {
		return err
	}
	return nil
}

func (fa *flowAggregator) getNodeUID(nodeName string, startTime time.Time) string {
	node, exist := fa.nodeStore.GetNodeByNameAndTime(nodeName, startTime)
	if !exist {
		klog.ErrorS(nil, "Cannot find Node information", "name", nodeName, "flowStartTime", startTime)
		return ""
	}
	return string(node.UID)
}

// fillK8sMetadata fills Pod name, Pod namespace, Pod UID, Node name and Node UID for inter-Node flows.
// This function is used in Proxy mode, as well as in Aggregate mode when correlation cannot be
// performed because of network policies.
func (fa *flowAggregator) fillK8sMetadata(sourceAddress, destinationAddress string, record *flowpb.Flow, startTime time.Time) {
	// fill source Pod info when sourcePodName is empty
	if record.K8S.SourcePodName == "" {
		pod, exist := fa.podStore.GetPodByIPAndTime(sourceAddress, startTime)
		if exist {
			record.K8S.SourcePodName = pod.Name
			record.K8S.SourcePodNamespace = pod.Namespace
			record.K8S.SourceNodeName = pod.Spec.NodeName
			if fa.includeK8sUIDs {
				record.K8S.SourcePodUid = string(pod.UID)
				record.K8S.SourceNodeUid = fa.getNodeUID(pod.Spec.NodeName, startTime)
			}
		} else {
			klog.ErrorS(nil, "Cannot find Pod information", "sourceAddress", sourceAddress, "flowStartTime", startTime)
		}
	}
	// fill destination Pod info when destinationPodName is empty
	if record.K8S.DestinationPodName == "" {
		pod, exist := fa.podStore.GetPodByIPAndTime(destinationAddress, startTime)
		if exist {
			record.K8S.DestinationPodName = pod.Name
			record.K8S.DestinationPodNamespace = pod.Namespace
			record.K8S.DestinationNodeName = pod.Spec.NodeName
			if fa.includeK8sUIDs {
				record.K8S.DestinationPodUid = string(pod.UID)
				record.K8S.DestinationNodeUid = fa.getNodeUID(pod.Spec.NodeName, startTime)
			}
		} else {
			klog.ErrorS(nil, "Cannot find Pod information", "destinationAddress", destinationAddress, "flowStartTime", startTime)
		}
	}
}

func (fa *flowAggregator) fetchPodLabels(ip string, startTime time.Time) *flowpb.Labels {
	pod, exist := fa.podStore.GetPodByIPAndTime(ip, startTime)
	if !exist {
		klog.ErrorS(nil, "Error when getting Pod information from podInformer", "ip", ip, "startTime", startTime)
		return nil
	}
	return &flowpb.Labels{
		// Labels field is of type map[string]string.
		// Note that Protobuf treats nil and empty maps the same when it comes to
		// serialization, and they should be treated the same in our Go code as well.
		Labels: pod.GetLabels(),
	}
}

func (fa *flowAggregator) fillPodLabels(sourceAddress, destinationAddress string, record *flowpb.Flow, startTime time.Time) {
	// If fa.includePodLabels is false, we always use nil.
	// If fa.includePodLabels is true, we use nil in case of error or if the endpoint is not a Pod.
	if !fa.includePodLabels {
		record.K8S.SourcePodLabels = nil
		record.K8S.DestinationPodLabels = nil
		return
	}
	if record.K8S.SourcePodName != "" && record.K8S.SourcePodNamespace != "" {
		record.K8S.SourcePodLabels = fa.fetchPodLabels(sourceAddress, startTime)
	} else {
		record.K8S.SourcePodLabels = nil
	}
	if record.K8S.DestinationPodName != "" && record.K8S.DestinationPodNamespace != "" {
		record.K8S.DestinationPodLabels = fa.fetchPodLabels(destinationAddress, startTime)
	} else {
		record.K8S.DestinationPodLabels = nil
	}
}

func (fa *flowAggregator) fillServiceUID(record *flowpb.Flow, startTime time.Time) {
	if record.K8S.DestinationServicePortName == "" {
		return
	}
	namespacedName, _, _ := strings.Cut(record.K8S.DestinationServicePortName, ":")
	service, exist := fa.serviceStore.GetServiceByNamespacedNameAndTime(namespacedName, startTime)
	if !exist {
		klog.ErrorS(nil, "Cannot find Service information", "name", namespacedName, "flowStartTime", startTime)
		return
	}
	record.K8S.DestinationServiceUid = string(service.UID)
}

func (fa *flowAggregator) fillEgressNodeUID(record *flowpb.Flow, startTime time.Time) {
	if record.K8S.EgressNodeName == "" {
		return
	}
	record.K8S.EgressNodeUid = fa.getNodeUID(record.K8S.EgressNodeName, startTime)
}

func (fa *flowAggregator) GetFlowRecords(flowKey *intermediate.FlowKey) []map[string]interface{} {
	if fa.aggregationProcess != nil {
		return fa.aggregationProcess.GetRecords(flowKey)
	}
	return nil
}

func (fa *flowAggregator) getNumFlows() int64 {
	if fa.aggregationProcess != nil {
		return fa.aggregationProcess.GetNumFlows()
	}
	return 0
}

func (fa *flowAggregator) getNumRecordsReceived() int64 {
	fa.collectorMutex.Lock()
	defer fa.collectorMutex.Unlock()
	var num int64
	if fa.grpcCollector != nil {
		num += fa.grpcCollector.GetNumRecordsReceived()
	}
	if fa.ipfixCollector != nil {
		num += fa.ipfixCollector.GetNumRecordsReceived()
	}
	return num
}

func (fa *flowAggregator) getNumConnsToCollector() int64 {
	fa.collectorMutex.Lock()
	defer fa.collectorMutex.Unlock()
	var num int64
	if fa.grpcCollector != nil {
		num += fa.grpcCollector.GetNumConnsToCollector()
	}
	if fa.ipfixCollector != nil {
		num += fa.ipfixCollector.GetNumConnsToCollector()
	}
	return num
}

func (fa *flowAggregator) GetRecordMetrics() querier.Metrics {
	metrics := querier.Metrics{
		NumRecordsExported: fa.numRecordsExported.Load(),
		NumRecordsReceived: fa.getNumRecordsReceived(),
		NumRecordsDropped:  fa.numRecordsDropped.Load(),
		NumFlows:           fa.getNumFlows(),
		NumConnToCollector: fa.getNumConnsToCollector(),
	}
	fa.exportersMutex.Lock()
	defer fa.exportersMutex.Unlock()
	metrics.WithClickHouseExporter = fa.clickHouseHandle != nil
	metrics.WithS3Exporter = fa.s3Handle != nil
	metrics.WithLogExporter = fa.logHandle != nil
	metrics.WithIPFIXExporter = fa.ipfixHandle != nil
	return metrics
}

func (fa *flowAggregator) watchConfiguration(stopCh <-chan struct{}) {
	klog.InfoS("Watching for FlowAggregator configuration file")
	for {
		select {
		case <-stopCh:
			close(fa.updateCh)
			return
		case event, ok := <-fa.configWatcher.Events:
			klog.InfoS("Event happened", "event", event.String())
			if !ok {
				// If configWatcher event channel is closed, we kill the flow-aggregator Pod to restore
				// the channel.
				klog.Fatal("ConfigWatcher event channel closed")
			}
			if err := fa.handleWatcherEvent(); err != nil {
				// If the watcher cannot add mounted configuration file or the configuration file is not readable,
				// we kill the flow-aggregator Pod (serious error)
				klog.Fatalf("Cannot watch or read configMap: %v", err)
			}
		case err := <-fa.configWatcher.Errors:
			if err != nil {
				// If the error happens to watcher, we kill the flow-aggregator Pod.
				// watcher might be shut-down or broken in this situation.
				klog.Fatalf("configWatcher err: %v", err)
			}
		}
	}
}

func (fa *flowAggregator) handleWatcherEvent() error {
	data, err := os.ReadFile(fa.configFile)
	if err != nil {
		return fmt.Errorf("cannot read FlowAggregator configuration file: %v", err)
	}
	opt, err := options.LoadConfig(data)
	if err != nil {
		klog.ErrorS(err, "Error when loading configuration from config file")
		return nil
	}
	if bytes.Equal(data, fa.configData) {
		klog.InfoS("Flow-aggregator configuration didn't change")
		return nil
	}
	fa.configData = data
	klog.InfoS("Updating Flow Aggregator")
	// all updates must be performed within flowExportLoop
	fa.updateCh <- opt
	return nil
}

func (fa *flowAggregator) updateFlowAggregator(opt *options.Options) {
	// This function potentially modifies the exporter handle fields (e.g.,
	// fa.ipfixHandle). We protect these writes by locking fa.exportersMutex, so
	// that GetRecordMetrics() can safely read the fields (by also locking the mutex).
	fa.exportersMutex.Lock()
	defer fa.exportersMutex.Unlock()

	// If user tries to change the mode dynamically, it makes sense to error out
	// immediately and ignore other updates, as this is such a major configuration
	// parameter. Unsupported "minor" updates are handled at the end of this function.
	if opt.AggregatorMode != fa.aggregatorMode {
		klog.ErrorS(nil, "FlowAggregator mode cannot be changed without restarting")
		return
	}

	// IPFIX exporter: stop-and-replace
	if opt.Config.FlowCollector.Enable {
		if fa.ipfixHandle != nil {
			klog.InfoS("Replacing Flow-Collector exporter")
			fa.ipfixHandle.stop()
			fa.ipfixHandle = nil
		} else {
			klog.InfoS("Enabling Flow-Collector")
		}
		exp := newIPFIXExporter(fa.clusterUUID, fa.clusterID, opt, fa.registry)
		fa.ipfixHandle = fa.launchExporter(exp)
		klog.InfoS("Started Flow-Collector exporter")
	} else if fa.ipfixHandle != nil {
		klog.InfoS("Disabling Flow-Collector")
		fa.ipfixHandle.stop()
		fa.ipfixHandle = nil
		klog.InfoS("Disabled Flow-Collector")
	}

	// ClickHouse exporter: stop-and-replace
	if opt.Config.ClickHouse.Enable {
		if fa.clickHouseHandle != nil {
			klog.InfoS("Replacing ClickHouse exporter")
			fa.clickHouseHandle.stop()
			fa.clickHouseHandle = nil
		} else {
			klog.InfoS("Enabling ClickHouse")
		}
		exp, err := newClickHouseExporter(fa.clusterUUID, opt)
		if err != nil {
			klog.ErrorS(err, "Error when creating ClickHouse export process")
		} else {
			fa.clickHouseHandle = fa.launchExporter(exp)
			klog.InfoS("Started ClickHouse exporter")
		}
	} else if fa.clickHouseHandle != nil {
		klog.InfoS("Disabling ClickHouse")
		fa.clickHouseHandle.stop()
		fa.clickHouseHandle = nil
		klog.InfoS("Disabled ClickHouse")
	}

	// S3 exporter: stop-and-replace
	if opt.Config.S3Uploader.Enable {
		if fa.s3Handle != nil {
			klog.InfoS("Replacing S3 exporter")
			fa.s3Handle.stop()
			fa.s3Handle = nil
		} else {
			klog.InfoS("Enabling S3Uploader")
		}
		exp, err := newS3Exporter(fa.clusterUUID, opt)
		if err != nil {
			klog.ErrorS(err, "Error when creating S3 export process")
		} else {
			fa.s3Handle = fa.launchExporter(exp)
			klog.InfoS("Started S3 exporter")
		}
	} else if fa.s3Handle != nil {
		klog.InfoS("Disabling S3Uploader")
		fa.s3Handle.stop()
		fa.s3Handle = nil
		klog.InfoS("Disabled S3Uploader")
	}

	// Log exporter: stop-and-replace
	if opt.Config.FlowLogger.Enable {
		if fa.logHandle != nil {
			klog.InfoS("Replacing FlowLogger exporter")
			fa.logHandle.stop()
			fa.logHandle = nil
		} else {
			klog.InfoS("Enabling FlowLogger")
		}
		exp, err := newLogExporter(opt)
		if err != nil {
			klog.ErrorS(err, "Error when creating log export process")
		} else {
			fa.logHandle = fa.launchExporter(exp)
			klog.InfoS("Started FlowLogger exporter")
		}
	} else if fa.logHandle != nil {
		klog.InfoS("Disabling FlowLogger")
		fa.logHandle.stop()
		fa.logHandle = nil
		klog.InfoS("Disabled FlowLogger")
	}

	if opt.Config.RecordContents.PodLabels != fa.includePodLabels {
		fa.includePodLabels = opt.Config.RecordContents.PodLabels
		klog.InfoS("Updated recordContents.podLabels configuration", "value", fa.includePodLabels)
	}
	includeK8sUIDs := opt.Config.FlowCollector.Enable && (*opt.Config.FlowCollector.IncludeK8sUIDs)
	if includeK8sUIDs != fa.includeK8sUIDs {
		fa.includeK8sUIDs = includeK8sUIDs
		klog.InfoS("Updated includeK8sUIDs configuration", "value", includeK8sUIDs)
	}
	var unsupportedUpdates []string
	if opt.Config.APIServer != fa.APIServer {
		unsupportedUpdates = append(unsupportedUpdates, "apiServer")
	}
	if opt.ActiveFlowRecordTimeout != fa.activeFlowRecordTimeout {
		unsupportedUpdates = append(unsupportedUpdates, "activeFlowRecordTimeout")
	}
	if opt.InactiveFlowRecordTimeout != fa.inactiveFlowRecordTimeout {
		unsupportedUpdates = append(unsupportedUpdates, "inactiveFlowRecordTimeout")
	}
	if opt.AggregatorTransportProtocol != fa.aggregatorTransportProtocol {
		unsupportedUpdates = append(unsupportedUpdates, "aggregatorTransportProtocol")
	}
	if opt.Config.FlowAggregatorAddress != fa.flowAggregatorAddress {
		unsupportedUpdates = append(unsupportedUpdates, "flowAggregatorAddress")
	}
	if len(unsupportedUpdates) > 0 {
		klog.ErrorS(nil, "Ignoring unsupported configuration updates, please restart FlowAggregator", "keys", unsupportedUpdates)
	}
}
