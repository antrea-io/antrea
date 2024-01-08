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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/vmware/go-ipfix/pkg/collector"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/exporter"
	"antrea.io/antrea/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
	"antrea.io/antrea/pkg/util/podstore"
)

var (
	aggregationElements = &ipfixintermediate.AggregationElements{
		NonStatsElements:                   infoelements.NonStatsElementList,
		StatsElements:                      infoelements.StatsElementList,
		AggregatedSourceStatsElements:      infoelements.AntreaSourceStatsElementList,
		AggregatedDestinationStatsElements: infoelements.AntreaDestinationStatsElementList,
		AntreaFlowEndSecondsElements:       infoelements.AntreaFlowEndSecondsElementList,
		ThroughputElements:                 infoelements.AntreaThroughputElementList,
		SourceThroughputElements:           infoelements.AntreaSourceThroughputElementList,
		DestinationThroughputElements:      infoelements.AntreaDestinationThroughputElementList,
	}

	correlateFields = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationClusterIPv4",
		"destinationClusterIPv6",
		"destinationServicePort",
		"destinationServicePortName",
		"ingressNetworkPolicyName",
		"ingressNetworkPolicyNamespace",
		"ingressNetworkPolicyRuleAction",
		"ingressNetworkPolicyType",
		"ingressNetworkPolicyRuleName",
		"egressNetworkPolicyName",
		"egressNetworkPolicyNamespace",
		"egressNetworkPolicyRuleAction",
		"egressNetworkPolicyType",
		"egressNetworkPolicyRuleName",
	}
)

const (
	aggregationWorkerNum = 2
	udpTransport         = "udp"
	tcpTransport         = "tcp"
	collectorAddress     = "0.0.0.0:4739"
)

// these are used for unit testing
var (
	newIPFIXExporter = func(k8sClient kubernetes.Interface, opt *options.Options, registry ipfix.IPFIXRegistry) exporter.Interface {
		return exporter.NewIPFIXExporter(k8sClient, opt, registry)
	}
	newClickHouseExporter = func(k8sClient kubernetes.Interface, opt *options.Options) (exporter.Interface, error) {
		return exporter.NewClickHouseExporter(k8sClient, opt)
	}
	newS3Exporter = func(k8sClient kubernetes.Interface, opt *options.Options) (exporter.Interface, error) {
		return exporter.NewS3Exporter(k8sClient, opt)
	}
	newLogExporter = func(opt *options.Options) (exporter.Interface, error) {
		return exporter.NewLogExporter(opt)
	}
)

type flowAggregator struct {
	aggregatorTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol
	collectingProcess           ipfix.IPFIXCollectingProcess
	aggregationProcess          ipfix.IPFIXAggregationProcess
	activeFlowRecordTimeout     time.Duration
	inactiveFlowRecordTimeout   time.Duration
	registry                    ipfix.IPFIXRegistry
	flowAggregatorAddress       string
	includePodLabels            bool
	k8sClient                   kubernetes.Interface
	podStore                    podstore.Interface
	numRecordsExported          int64
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
}

func NewFlowAggregator(
	k8sClient kubernetes.Interface,
	podStore podstore.Interface,
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

	fa := &flowAggregator{
		aggregatorTransportProtocol: opt.AggregatorTransportProtocol,
		activeFlowRecordTimeout:     opt.ActiveFlowRecordTimeout,
		inactiveFlowRecordTimeout:   opt.InactiveFlowRecordTimeout,
		registry:                    registry,
		flowAggregatorAddress:       opt.Config.FlowAggregatorAddress,
		includePodLabels:            opt.Config.RecordContents.PodLabels,
		k8sClient:                   k8sClient,
		podStore:                    podStore,
		updateCh:                    make(chan *options.Options),
		configFile:                  configFile,
		configWatcher:               configWatcher,
		configData:                  data,
		APIServer:                   opt.Config.APIServer,
		logTickerDuration:           time.Minute,
	}
	err = fa.InitCollectingProcess()
	if err != nil {
		return nil, fmt.Errorf("error when creating collecting process: %v", err)
	}
	err = fa.InitAggregationProcess()
	if err != nil {
		return nil, fmt.Errorf("error when creating aggregation process: %v", err)
	}
	if opt.Config.ClickHouse.Enable {
		var err error
		fa.clickHouseExporter, err = newClickHouseExporter(k8sClient, opt)
		if err != nil {
			return nil, fmt.Errorf("error when creating ClickHouse export process: %v", err)
		}
	}
	if opt.Config.S3Uploader.Enable {
		var err error
		fa.s3Exporter, err = newS3Exporter(k8sClient, opt)
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
		fa.ipfixExporter = newIPFIXExporter(k8sClient, opt, registry)
	}
	return fa, nil
}

func (fa *flowAggregator) InitCollectingProcess() error {
	var cpInput collector.CollectorInput
	if fa.aggregatorTransportProtocol == flowaggregatorconfig.AggregatorTransportProtocolTLS {
		parentCert, privateKey, caCert, err := generateCACertKey()
		if err != nil {
			return fmt.Errorf("error when generating CA certificate: %v", err)
		}
		serverCert, serverKey, err := generateCertKey(parentCert, privateKey, true, fa.flowAggregatorAddress)
		if err != nil {
			return fmt.Errorf("error when creating server certificate: %v", err)
		}

		clientCert, clientKey, err := generateCertKey(parentCert, privateKey, false, "")
		if err != nil {
			return fmt.Errorf("error when creating client certificate: %v", err)
		}
		err = syncCAAndClientCert(caCert, clientCert, clientKey, fa.k8sClient)
		if err != nil {
			return fmt.Errorf("error when synchronizing client certificate: %v", err)
		}
		cpInput = collector.CollectorInput{
			Address:       collectorAddress,
			Protocol:      tcpTransport,
			MaxBufferSize: 65535,
			TemplateTTL:   0,
			IsEncrypted:   true,
			CACert:        caCert,
			ServerKey:     serverKey,
			ServerCert:    serverCert,
		}
	} else if fa.aggregatorTransportProtocol == flowaggregatorconfig.AggregatorTransportProtocolTCP {
		cpInput = collector.CollectorInput{
			Address:       collectorAddress,
			Protocol:      tcpTransport,
			MaxBufferSize: 65535,
			TemplateTTL:   0,
			IsEncrypted:   false,
		}
	} else {
		cpInput = collector.CollectorInput{
			Address:       collectorAddress,
			Protocol:      udpTransport,
			MaxBufferSize: 1024,
			TemplateTTL:   0,
			IsEncrypted:   false,
		}
	}
	cpInput.NumExtraElements = len(infoelements.AntreaSourceStatsElementList) + len(infoelements.AntreaDestinationStatsElementList) + len(infoelements.AntreaLabelsElementList) +
		len(infoelements.AntreaFlowEndSecondsElementList) + len(infoelements.AntreaThroughputElementList) + len(infoelements.AntreaSourceThroughputElementList) + len(infoelements.AntreaDestinationThroughputElementList)
	var err error
	fa.collectingProcess, err = collector.InitCollectingProcess(cpInput)
	return err
}

func (fa *flowAggregator) InitAggregationProcess() error {
	var err error
	apInput := ipfixintermediate.AggregationInput{
		MessageChan:           fa.collectingProcess.GetMsgChan(),
		WorkerNum:             aggregationWorkerNum,
		CorrelateFields:       correlateFields,
		ActiveExpiryTimeout:   fa.activeFlowRecordTimeout,
		InactiveExpiryTimeout: fa.inactiveFlowRecordTimeout,
		AggregateElements:     aggregationElements,
	}
	fa.aggregationProcess, err = ipfixintermediate.InitAggregationProcess(apInput)
	return err
}

func (fa *flowAggregator) Run(stopCh <-chan struct{}) {
	var wg, ipfixProcessesWg sync.WaitGroup

	ipfixProcessesWg.Add(1)
	go func() {
		// Waiting for this function to return on stop makes it easier to set expectations
		// when testing. Without this, there is no guarantee that
		// fa.collectingProcess.Start() was called by the time Run() returns.
		defer ipfixProcessesWg.Done()
		// blocking function, will return when fa.collectingProcess.Stop() is called
		fa.collectingProcess.Start()
	}()
	ipfixProcessesWg.Add(1)
	go func() {
		// Same comment as above.
		defer ipfixProcessesWg.Done()
		// blocking function, will return when fa.aggregationProcess.Stop() is called
		fa.aggregationProcess.Start()
	}()

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
		// Waiting for this function to return on stop makes it easier to set expectations
		// when testing.
		defer wg.Done()
		fa.podStore.Run(stopCh)
	}()

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
	// Wait for fa.podStore.Run, fa.flowExportLoop and fa.watchConfiguration to return.
	wg.Wait()
	// Stop fa.collectingProcess and fa.aggregationProcess, and wait for their Start function to
	// return. There should be no strict requirement to stop these processes last, but we
	// preserve existing behavior from older code.
	fa.aggregationProcess.Stop()
	fa.collectingProcess.Stop()
	ipfixProcessesWg.Wait()
}

// flowExportLoop is the main loop for the FlowAggregator. It runs in a single
// goroutine. All calls to exporter.Interface methods happen within this
// function, hence preventing any concurrency issue as the exporter.Interface
// implementations are not safe for concurrent access.
func (fa *flowAggregator) flowExportLoop(stopCh <-chan struct{}) {
	expireTimer := time.NewTimer(fa.activeFlowRecordTimeout)
	defer expireTimer.Stop()
	logTicker := time.NewTicker(fa.logTickerDuration)
	defer logTicker.Stop()
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
	updateCh := fa.updateCh
	for {
		select {
		case <-stopCh:
			return
		case <-expireTimer.C:
			// Pop the flow record item from expire priority queue in the Aggregation
			// Process and send the flow records.
			if err := fa.aggregationProcess.ForAllExpiredFlowRecordsDo(fa.sendFlowKeyRecord); err != nil {
				klog.ErrorS(err, "Error when sending expired flow records")
				expireTimer.Reset(fa.activeFlowRecordTimeout)
				continue
			}
			// Get the new expiry and reset the timer.
			expireTimer.Reset(fa.aggregationProcess.GetExpiryFromExpirePriorityQueue())
		case <-logTicker.C:
			// Add visibility of processing stats of Flow Aggregator
			klog.V(4).InfoS("Total number of records received", "count", fa.collectingProcess.GetNumRecordsReceived())
			klog.V(4).InfoS("Total number of records exported by each active exporter", "count", fa.numRecordsExported)
			klog.V(4).InfoS("Total number of flows stored in Flow Aggregator", "count", fa.aggregationProcess.GetNumFlows())
			klog.V(4).InfoS("Number of exporters connected with Flow Aggregator", "count", fa.collectingProcess.GetNumConnToCollector())
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

func (fa *flowAggregator) sendFlowKeyRecord(key ipfixintermediate.FlowKey, record *ipfixintermediate.AggregationFlowRecord) error {
	isRecordIPv4 := fa.aggregationProcess.IsAggregatedRecordIPv4(*record)
	startTime, err := fa.getRecordStartTime(record.Record)
	if err != nil {
		return fmt.Errorf("cannot find record start time: %v", err)
	}
	if !fa.aggregationProcess.AreCorrelatedFieldsFilled(*record) {
		fa.fillK8sMetadata(key, record.Record, *startTime)
		fa.aggregationProcess.SetCorrelatedFieldsFilled(record, true)
	}
	if fa.includePodLabels && !fa.aggregationProcess.AreExternalFieldsFilled(*record) {
		fa.fillPodLabels(key, record.Record, *startTime)
		fa.aggregationProcess.SetExternalFieldsFilled(record, true)
	}
	if fa.ipfixExporter != nil {
		if err := fa.ipfixExporter.AddRecord(record.Record, !isRecordIPv4); err != nil {
			return err
		}
	}
	if fa.clickHouseExporter != nil {
		if err := fa.clickHouseExporter.AddRecord(record.Record, !isRecordIPv4); err != nil {
			return err
		}
	}
	if fa.s3Exporter != nil {
		if err := fa.s3Exporter.AddRecord(record.Record, !isRecordIPv4); err != nil {
			return err
		}
	}
	if fa.logExporter != nil {
		if err := fa.logExporter.AddRecord(record.Record, !isRecordIPv4); err != nil {
			return err
		}
	}
	if err := fa.aggregationProcess.ResetStatAndThroughputElementsInRecord(record.Record); err != nil {
		return err
	}
	fa.numRecordsExported = fa.numRecordsExported + 1
	return nil
}

// fillK8sMetadata fills Pod name, Pod namespace and Node name for inter-Node flows
// that have incomplete info due to deny network policy.
func (fa *flowAggregator) fillK8sMetadata(key ipfixintermediate.FlowKey, record ipfixentities.Record, startTime time.Time) {
	// fill source Pod info when sourcePodName is empty
	if sourcePodName, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		if sourcePodName.GetStringValue() == "" {
			pod, exist := fa.podStore.GetPodByIPAndTime(key.SourceAddress, startTime)
			if exist {
				sourcePodName.SetStringValue(pod.Name)
				if sourcePodNamespace, _, exist := record.GetInfoElementWithValue("sourcePodNamespace"); exist {
					sourcePodNamespace.SetStringValue(pod.Namespace)
				}
				if sourceNodeName, _, exist := record.GetInfoElementWithValue("sourceNodeName"); exist {
					sourceNodeName.SetStringValue(pod.Spec.NodeName)
				}
			} else {
				klog.ErrorS(nil, "Cannot find Pod information", "sourceAddress", key.SourceAddress, "flowStartTime", startTime)
			}
		}
	}
	// fill destination Pod info when destinationPodName is empty
	if destinationPodName, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		if destinationPodName.GetStringValue() == "" {
			pod, exist := fa.podStore.GetPodByIPAndTime(key.DestinationAddress, startTime)
			if exist {
				destinationPodName.SetStringValue(pod.Name)
				if destinationPodNamespace, _, exist := record.GetInfoElementWithValue("destinationPodNamespace"); exist {
					destinationPodNamespace.SetStringValue(pod.Namespace)
				}
				if destinationNodeName, _, exist := record.GetInfoElementWithValue("destinationNodeName"); exist {
					destinationNodeName.SetStringValue(pod.Spec.NodeName)
				}
			} else {
				klog.ErrorS(nil, "Cannot find Pod information", "destinationAddress", key.DestinationAddress, "flowStartTime", startTime)
			}
		}
	}
}

func (fa *flowAggregator) getRecordStartTime(record ipfixentities.Record) (*time.Time, error) {
	flowStartSeconds, _, exist := record.GetInfoElementWithValue("flowStartSeconds")
	if !exist {
		return nil, fmt.Errorf("flowStartSeconds filed is empty")
	}
	startTime := time.Unix(int64(flowStartSeconds.GetUnsigned32Value()), 0)
	return &startTime, nil
}

func (fa *flowAggregator) fetchPodLabels(ip string, startTime time.Time) string {
	pod, exist := fa.podStore.GetPodByIPAndTime(ip, startTime)
	if !exist {
		klog.ErrorS(nil, "Error when getting Pod information from podInformer", "ip", ip, "startTime", startTime)
		return ""
	}
	labelsJSON, err := json.Marshal(pod.GetLabels())
	if err != nil {
		klog.ErrorS(err, "Error when JSON encoding of Pod labels")
		return ""
	}
	return string(labelsJSON)
}

func (fa *flowAggregator) fillPodLabelsForSide(ip string, record ipfixentities.Record, startTime time.Time, podNamespaceIEName, podNameIEName, podLabelsIEName string) error {
	podLabelsString := ""
	if podName, _, ok := record.GetInfoElementWithValue(podNameIEName); ok {
		podNameString := podName.GetStringValue()
		if podNamespace, _, ok := record.GetInfoElementWithValue(podNamespaceIEName); ok {
			podNamespaceString := podNamespace.GetStringValue()
			if podNameString != "" && podNamespaceString != "" {
				podLabelsString = fa.fetchPodLabels(ip, startTime)
			}
		}
	}

	podLabelsElement, err := fa.registry.GetInfoElement(podLabelsIEName, ipfixregistry.AntreaEnterpriseID)
	if err == nil {
		podLabelsIE, err := ipfixentities.DecodeAndCreateInfoElementWithValue(podLabelsElement, bytes.NewBufferString(podLabelsString).Bytes())
		if err != nil {
			return fmt.Errorf("error when creating podLabels InfoElementWithValue: %v", err)
		}
		if err := record.AddInfoElement(podLabelsIE); err != nil {
			return fmt.Errorf("error when adding podLabels InfoElementWithValue: %v", err)
		}
	} else {
		return fmt.Errorf("error when getting podLabels InfoElementWithValue: %v", err)
	}

	return nil
}

func (fa *flowAggregator) fillPodLabels(key ipfixintermediate.FlowKey, record ipfixentities.Record, startTime time.Time) {
	if err := fa.fillPodLabelsForSide(key.SourceAddress, record, startTime, "sourcePodNamespace", "sourcePodName", "sourcePodLabels"); err != nil {
		klog.ErrorS(err, "Error when filling pod labels", "side", "source")
	}
	if err := fa.fillPodLabelsForSide(key.DestinationAddress, record, startTime, "destinationPodNamespace", "destinationPodName", "destinationPodLabels"); err != nil {
		klog.ErrorS(err, "Error when filling pod labels", "side", "destination")
	}
}

func (fa *flowAggregator) GetFlowRecords(flowKey *ipfixintermediate.FlowKey) []map[string]interface{} {
	return fa.aggregationProcess.GetRecords(flowKey)
}

func (fa *flowAggregator) GetRecordMetrics() querier.Metrics {
	return querier.Metrics{
		NumRecordsExported:     fa.numRecordsExported,
		NumRecordsReceived:     fa.collectingProcess.GetNumRecordsReceived(),
		NumFlows:               fa.aggregationProcess.GetNumFlows(),
		NumConnToCollector:     fa.collectingProcess.GetNumConnToCollector(),
		WithClickHouseExporter: fa.clickHouseExporter != nil,
		WithS3Exporter:         fa.s3Exporter != nil,
		WithLogExporter:        fa.logExporter != nil,
		WithIPFIXExporter:      fa.ipfixExporter != nil,
	}
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
	if opt.Config.FlowCollector.Enable {
		if fa.ipfixExporter == nil {
			klog.InfoS("Enabling Flow-Collector")
			fa.ipfixExporter = newIPFIXExporter(fa.k8sClient, opt, fa.registry)
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
			fa.clickHouseExporter, err = newClickHouseExporter(fa.k8sClient, opt)
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
			fa.s3Exporter, err = newS3Exporter(fa.k8sClient, opt)
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
}
