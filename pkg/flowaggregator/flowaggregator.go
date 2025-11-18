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
	"errors"
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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/certificate"
	"antrea.io/antrea/pkg/flowaggregator/collector"
	"antrea.io/antrea/pkg/flowaggregator/exporter"
	"antrea.io/antrea/pkg/flowaggregator/intermediate"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
	"antrea.io/antrea/pkg/util/objectstore"
)

const aggregationWorkerNum = 2

// these are used for unit testing
var (
	newIPFIXExporter = func(clusterUUID uuid.UUID, clusterID string, opt *options.Options, registry ipfix.IPFIXRegistry) exporter.Interface {
		return exporter.NewIPFIXExporter(clusterUUID, clusterID, opt, registry)
	}
	newClickHouseExporter = func(clusterUUID uuid.UUID, opt *options.Options) (exporter.Interface, error) {
		return exporter.NewClickHouseExporter(clusterUUID, opt)
	}
	newS3Exporter = func(clusterUUID uuid.UUID, opt *options.Options) (exporter.Interface, error) {
		return exporter.NewS3Exporter(clusterUUID, opt)
	}
	newLogExporter = func(opt *options.Options) (exporter.Interface, error) {
		return exporter.NewLogExporter(opt)
	}

	newCertificateProvider = func(k8sClient kubernetes.Interface, addr string) certificate.Provider {
		return certificate.NewProvider(k8sClient, addr)
	}
)

type flowAggregator struct {
	aggregatorMode              flowaggregatorconfig.AggregatorMode
	clusterUUID                 uuid.UUID
	clusterID                   string
	aggregatorTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol
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
	numRecordsDropped           atomic.Int64
	updateCh                    chan *options.Options
	configFile                  string
	configWatcher               *fsnotify.Watcher
	configData                  []byte
	APIServer                   flowaggregatorconfig.APIServerConfig
	ipfixExporter               exporter.Interface
	clickHouseExporter          exporter.Interface
	s3Exporter                  exporter.Interface
	logExporter                 exporter.Interface
	logTickerDuration           time.Duration
	recordCh                    chan *flowpb.Flow
	exportersMutex              sync.Mutex

	certificateProvider certificate.Provider
}

func NewFlowAggregator(
	k8sClient kubernetes.Interface,
	clusterUUID uuid.UUID,
	podStore objectstore.PodStore,
	nodeStore objectstore.NodeStore,
	serviceStore objectstore.ServiceStore,
	configFile string,
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
		// We support buffering a small amount of flow records.
		recordCh:            make(chan *flowpb.Flow, 128),
		certificateProvider: newCertificateProvider(k8sClient, opt.Config.FlowAggregatorAddress),
	}

	if err := fa.InitCollectors(); err != nil {
		return nil, fmt.Errorf("error when creating collectors: %w", err)
	}

	if opt.AggregatorMode == flowaggregatorconfig.AggregatorModeAggregate {
		if err := fa.InitAggregationProcess(); err != nil {
			return nil, fmt.Errorf("error when creating aggregation process: %w", err)
		}
	}
	if opt.Config.ClickHouse.Enable {
		var err error
		fa.clickHouseExporter, err = newClickHouseExporter(clusterUUID, opt)
		if err != nil {
			return nil, fmt.Errorf("error when creating ClickHouse export process: %v", err)
		}
	}
	if opt.Config.S3Uploader.Enable {
		var err error
		fa.s3Exporter, err = newS3Exporter(clusterUUID, opt)
		if err != nil {
			return nil, fmt.Errorf("error when creating S3 export process: %v", err)
		}
	}
	if opt.Config.FlowLogger.Enable {
		var err error
		fa.logExporter, err = newLogExporter(opt)
		if err != nil {
			return nil, fmt.Errorf("error when creating log export process: %v", err)
		}
	}
	if opt.Config.FlowCollector.Enable {
		fa.ipfixExporter = newIPFIXExporter(clusterUUID, clusterID, opt, registry)
	}

	klog.InfoS("FlowAggregator initialized", "mode", opt.AggregatorMode, "clusterID", fa.clusterID)
	return fa, nil
}

func (fa *flowAggregator) InitCollectors() error {
	grpcCollector, err := collector.NewGRPCCollector(fa.recordCh, fa.certificateProvider)
	if err != nil {
		return fmt.Errorf("failed to create gRPC collector: %w", err)
	}
	fa.grpcCollector = grpcCollector
	if fa.aggregatorTransportProtocol != flowaggregatorconfig.AggregatorTransportProtocolNone {
		ipfixCollector, err := collector.NewIPFIXCollector(
			fa.recordCh,
			fa.aggregatorTransportProtocol,
			fa.certificateProvider,
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
	fa.aggregationProcess, err = intermediate.InitAggregationProcess(apInput)
	return err
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		fa.certificateProvider.Run(stopCh)
	}()

	if !cache.WaitForCacheSync(stopCh, fa.certificateProvider.HasSynced) {
		return
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Waiting for this function to return on stop makes it easier to set expectations
		// when testing. Without this, there is no guarantee that
		// fa.grpcCollector.Run() was called by the time Run() returns.
		fa.grpcCollector.Run(stopCh)
	}()
	if fa.ipfixCollector != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fa.ipfixCollector.Run(stopCh)
		}()
	}
	if fa.aggregationProcess != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// blocking function, will return when fa.aggregationProcess.Stop() is called
			fa.aggregationProcess.Start()
		}()
	}

	if fa.ipfixExporter != nil {
		fa.ipfixExporter.Start()
	}
	if fa.clickHouseExporter != nil {
		fa.clickHouseExporter.Start()
	}
	if fa.s3Exporter != nil {
		fa.s3Exporter.Start()
	}
	if fa.logExporter != nil {
		fa.logExporter.Start()
	}

	wg.Add(1)
	go func() {
		// We want to make sure that flowExportLoop returns before
		// returning from this function. This is because flowExportLoop
		// is in charge of cleanly stopping the exporters.
		defer wg.Done()
		fa.flowExportLoop(stopCh)
	}()
	wg.Add(1)
	go func() {
		// there is no strong reason to wait for this function to return
		// on stop, but it does seem like the best thing to do.
		defer wg.Done()
		fa.watchConfiguration(stopCh)
		// the watcher should not be closed until watchConfiguration returns.
		// note that it is safe to close an fsnotify watcher multiple times,
		// for example:
		// https://github.com/fsnotify/fsnotify/blob/v1.6.0/backend_inotify.go#L184
		// in practice, this should only happen during unit tests.
		fa.configWatcher.Close()
	}()
	<-stopCh
	if fa.aggregationProcess != nil {
		fa.aggregationProcess.Stop()
	}
	wg.Wait()
}

// flowExportLoop is the main loop for the FlowAggregator. It runs in a single
// goroutine. All calls to exporter.Interface methods happen within this
// function, hence preventing any concurrency issue as the exporter.Interface
// implementations are not safe for concurrent access.
func (fa *flowAggregator) flowExportLoop(stopCh <-chan struct{}) {
	defer func() {
		// We stop the exporters from flowExportLoop and not from Run,
		// to avoid any possible race condition.
		if fa.ipfixExporter != nil {
			fa.ipfixExporter.Stop()
		}
		if fa.clickHouseExporter != nil {
			fa.clickHouseExporter.Stop()
		}
		if fa.s3Exporter != nil {
			fa.s3Exporter.Stop()
		}
		if fa.logExporter != nil {
			fa.logExporter.Stop()
		}
	}()
	switch fa.aggregatorMode {
	case flowaggregatorconfig.AggregatorModeAggregate:
		fa.flowExportLoopAggregate(stopCh)
	case flowaggregatorconfig.AggregatorModeProxy:
		fa.flowExportLoopProxy(stopCh)
	}
}

func (fa *flowAggregator) proxyRecord(record *flowpb.Flow) error {
	sourceAddress := net.IP(record.Ip.Source).String()
	destinationAddress := net.IP(record.Ip.Destination).String()
	isIPv6 := record.Ip.Version == flowpb.IPVersion_IP_VERSION_6
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
	return fa.sendRecord(record, isIPv6)
}

func (fa *flowAggregator) flowExportLoopProxy(stopCh <-chan struct{}) {
	logTicker := time.NewTicker(fa.logTickerDuration)
	defer logTicker.Stop()
	const flushTickerDuration = 1 * time.Second
	flushTicker := time.NewTicker(flushTickerDuration)
	defer flushTicker.Stop()
	recordCh := fa.recordCh

	proxyRecord := func(record *flowpb.Flow) {
		if err := fa.proxyRecord(record); err != nil {
			fa.numRecordsDropped.Add(1)
			if errors.Is(err, exporter.ErrIPFIXExporterBackoff) {
				return
			}
			klog.ErrorS(err, "Failed to proxy record")
		}
	}

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
			proxyRecord(record)
		case <-flushTicker.C:
			if err := fa.flushExporters(); err != nil {
				klog.ErrorS(err, "Error when flushing exporters")
			}
		case <-logTicker.C:
			// Add visibility of processing stats of Flow Aggregator
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
	expireTimer := time.NewTimer(fa.activeFlowRecordTimeout)
	defer expireTimer.Stop()
	logTicker := time.NewTicker(fa.logTickerDuration)
	defer logTicker.Stop()

	updateCh := fa.updateCh
	for {
		select {
		case <-stopCh:
			return
		case <-expireTimer.C:
			// Pop the flow record item from expire priority queue in the Aggregation
			// Process and send the flow records.
			if err := fa.aggregationProcess.ForAllExpiredFlowRecordsDo(fa.sendAggregatedRecord); err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				expireTimer.Reset(fa.activeFlowRecordTimeout)
				continue
			}
			// Get the new expiry and reset the timer.
			expireTimer.Reset(fa.aggregationProcess.GetExpiryFromExpirePriorityQueue())
			if err := fa.flushExporters(); err != nil {
				klog.ErrorS(err, "Error when flushing exporters")
			}
		case <-logTicker.C:
			// Add visibility of processing stats of Flow Aggregator
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

func (fa *flowAggregator) sendRecord(record *flowpb.Flow, isRecordIPv6 bool) error {
	if fa.ipfixExporter != nil {
		if err := fa.ipfixExporter.AddRecord(record, isRecordIPv6); err != nil {
			return err
		}
	}
	if fa.clickHouseExporter != nil {
		if err := fa.clickHouseExporter.AddRecord(record, isRecordIPv6); err != nil {
			return err
		}
	}
	if fa.s3Exporter != nil {
		if err := fa.s3Exporter.AddRecord(record, isRecordIPv6); err != nil {
			return err
		}
	}
	if fa.logExporter != nil {
		if err := fa.logExporter.AddRecord(record, isRecordIPv6); err != nil {
			return err
		}
	}
	fa.numRecordsExported.Add(1)
	return nil
}

func (fa *flowAggregator) flushExporters() error {
	if fa.ipfixExporter != nil {
		if err := fa.ipfixExporter.Flush(); err != nil {
			return err
		}
	}
	// Other exporters don't leverage Flush for now, so we skip them.
	return nil
}

func (fa *flowAggregator) sendAggregatedRecord(key intermediate.FlowKey, record *intermediate.AggregationFlowRecord) error {
	isRecordIPv4 := fa.aggregationProcess.IsAggregatedRecordIPv4(*record)
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
	if err := fa.sendRecord(record.Record, !isRecordIPv4); err != nil {
		return err
	}
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
	namespacedName, _, found := strings.Cut(record.K8S.DestinationServicePortName, ":")
	if !found {
		klog.ErrorS(nil, "Expected format for ServicePortName", "servicePortName", record.K8S.DestinationServicePortName)
		return
	}
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
	num := fa.grpcCollector.GetNumRecordsReceived()
	if fa.ipfixCollector != nil {
		num += fa.ipfixCollector.GetNumRecordsReceived()
	}
	return num
}

func (fa *flowAggregator) getNumConnsToCollector() int64 {
	num := fa.grpcCollector.GetNumConnsToCollector()
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
	metrics.WithClickHouseExporter = fa.clickHouseExporter != nil
	metrics.WithS3Exporter = fa.s3Exporter != nil
	metrics.WithLogExporter = fa.logExporter != nil
	metrics.WithIPFIXExporter = fa.ipfixExporter != nil
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
	// This function potentially modifies the exporter pointer fields (e.g.,
	// fa.ipfixExporter). We protect these writes by locking fa.exportersMutex, so that
	// GetRecordMetrics() can safely read the fields (by also locking the mutex).
	fa.exportersMutex.Lock()
	defer fa.exportersMutex.Unlock()
	// If user tries to change the mode dynamically, it makes sense to error out immediately and
	// ignore other updates, as this is such a major configuration parameter.
	// Unsupported "minor" updates are handled at the end of this function.
	if opt.AggregatorMode != fa.aggregatorMode {
		klog.ErrorS(nil, "FlowAggregator mode cannot be changed without restarting")
		return
	}
	if opt.Config.FlowCollector.Enable {
		if fa.ipfixExporter == nil {
			klog.InfoS("Enabling Flow-Collector")
			fa.ipfixExporter = newIPFIXExporter(fa.clusterUUID, fa.clusterID, opt, fa.registry)
			fa.ipfixExporter.Start()
			klog.InfoS("Enabled Flow-Collector")
		} else {
			fa.ipfixExporter.UpdateOptions(opt)
		}
	} else {
		if fa.ipfixExporter != nil {
			klog.InfoS("Disabling Flow-Collector")
			fa.ipfixExporter.Stop()
			fa.ipfixExporter = nil
			klog.InfoS("Disabled Flow-Collector")
		}
	}
	if opt.Config.ClickHouse.Enable {
		if fa.clickHouseExporter == nil {
			klog.InfoS("Enabling ClickHouse")
			var err error
			fa.clickHouseExporter, err = newClickHouseExporter(fa.clusterUUID, opt)
			if err != nil {
				klog.ErrorS(err, "Error when creating ClickHouse export process")
				return
			}
			fa.clickHouseExporter.Start()
			klog.InfoS("Enabled ClickHouse")
		} else {
			fa.clickHouseExporter.UpdateOptions(opt)
		}
	} else {
		if fa.clickHouseExporter != nil {
			klog.InfoS("Disabling ClickHouse")
			fa.clickHouseExporter.Stop()
			fa.clickHouseExporter = nil
			klog.InfoS("Disabled ClickHouse")
		}
	}
	if opt.Config.S3Uploader.Enable {
		if fa.s3Exporter == nil {
			klog.InfoS("Enabling S3Uploader")
			var err error
			fa.s3Exporter, err = newS3Exporter(fa.clusterUUID, opt)
			if err != nil {
				klog.ErrorS(err, "Error when creating S3 export process")
				return
			}
			fa.s3Exporter.Start()
			klog.InfoS("Enabled S3Uploader")
		} else {
			fa.s3Exporter.UpdateOptions(opt)
		}
	} else {
		if fa.s3Exporter != nil {
			klog.InfoS("Disabling S3Uploader")
			fa.s3Exporter.Stop()
			fa.s3Exporter = nil
			klog.InfoS("Disabled S3Uploader")
		}
	}
	if opt.Config.FlowLogger.Enable {
		if fa.logExporter == nil {
			klog.InfoS("Enabling FlowLogger")
			var err error
			fa.logExporter, err = newLogExporter(opt)
			if err != nil {
				klog.ErrorS(err, "Error when creating log export process")
				return
			}
			fa.logExporter.Start()
			klog.InfoS("Enabled FlowLogger")
		} else {
			fa.logExporter.UpdateOptions(opt)
		}
	} else {
		if fa.logExporter != nil {
			klog.InfoS("Disabling FlowLogger")
			fa.logExporter.Stop()
			fa.logExporter = nil
			klog.InfoS("Disabled FlowLogger")
		}
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
