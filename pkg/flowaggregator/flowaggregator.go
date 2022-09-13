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
	corev1 "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/exporter"
	"antrea.io/antrea/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	"antrea.io/antrea/pkg/ipfix"
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

	// PodInfo index name for Pod cache.
	podInfoIndex = "podInfo"
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
	podInformer                 coreinformers.PodInformer
	numRecordsExported          int64
	numRecordsReceived          int64
	updateCh                    chan *options.Options
	configFile                  string
	configWatcher               *fsnotify.Watcher
	configData                  []byte
	APIServer                   flowaggregatorconfig.APIServerConfig
	ipfixExporter               exporter.Interface
	clickHouseExporter          exporter.Interface
	s3Exporter                  exporter.Interface
	logTickerDuration           time.Duration
}

func NewFlowAggregator(
	k8sClient kubernetes.Interface,
	podInformer coreinformers.PodInformer,
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
		podInformer:                 podInformer,
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
	if opt.Config.FlowCollector.Enable {
		fa.ipfixExporter = newIPFIXExporter(k8sClient, opt, registry)
	}
	podInformer.Informer().AddIndexers(cache.Indexers{podInfoIndex: podInfoIndexFunc})
	return fa, nil
}

func podInfoIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("obj is not pod: %+v", obj)
	}
	if len(pod.Status.PodIPs) > 0 && pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
		indexes := make([]string, len(pod.Status.PodIPs))
		for i := range pod.Status.PodIPs {
			indexes[i] = pod.Status.PodIPs[i].IP
		}
		return indexes, nil
	}
	return nil, nil
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
	fa.collectingProcess, err = ipfix.NewIPFIXCollectingProcess(cpInput)
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
	fa.aggregationProcess, err = ipfix.NewIPFIXAggregationProcess(apInput)
	return err
}

func (fa *flowAggregator) Run(stopCh <-chan struct{}) {
	go fa.collectingProcess.Start()
	defer fa.collectingProcess.Stop()
	go fa.aggregationProcess.Start()
	defer fa.aggregationProcess.Stop()
	if fa.ipfixExporter != nil {
		fa.ipfixExporter.Start()
	}
	if fa.clickHouseExporter != nil {
		fa.clickHouseExporter.Start()
	}
	if fa.s3Exporter != nil {
		fa.s3Exporter.Start()
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// We want to make sure that flowExportLoop returns before
		// returning from this function. This is because flowExportLoop
		// is in charge of cleanly stopping the exporters.
		defer wg.Done()
		fa.flowExportLoop(stopCh)
	}()
	go fa.watchConfiguration(stopCh)
	<-stopCh
	wg.Wait()
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
	if !fa.aggregationProcess.AreCorrelatedFieldsFilled(*record) {
		fa.fillK8sMetadata(key, record.Record)
		fa.aggregationProcess.SetCorrelatedFieldsFilled(record)
	}
	if fa.includePodLabels && !fa.aggregationProcess.AreExternalFieldsFilled(*record) {
		fa.fillPodLabels(key, record.Record)
		fa.aggregationProcess.SetExternalFieldsFilled(record)
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
	if err := fa.aggregationProcess.ResetStatAndThroughputElementsInRecord(record.Record); err != nil {
		return err
	}
	fa.numRecordsExported = fa.numRecordsExported + 1
	return nil
}

// fillK8sMetadata fills Pod name, Pod namespace and Node name for inter-Node flows
// that have incomplete info due to deny network policy.
func (fa *flowAggregator) fillK8sMetadata(key ipfixintermediate.FlowKey, record ipfixentities.Record) {
	// fill source Pod info when sourcePodName is empty
	if sourcePodName, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		if sourcePodName.GetStringValue() == "" {
			pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, key.SourceAddress)
			if err == nil && len(pods) > 0 {
				pod, ok := pods[0].(*corev1.Pod)
				if !ok {
					klog.Warningf("Invalid Pod obj in cache")
				}
				sourcePodName.SetStringValue(pod.Name)
				if sourcePodNamespace, _, exist := record.GetInfoElementWithValue("sourcePodNamespace"); exist {
					sourcePodNamespace.SetStringValue(pod.Namespace)
				}
				if sourceNodeName, _, exist := record.GetInfoElementWithValue("sourceNodeName"); exist {
					sourceNodeName.SetStringValue(pod.Spec.NodeName)
				}
			} else {
				klog.Warning(err)
			}
		}
	}
	// fill destination Pod info when destinationPodName is empty
	if destinationPodName, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		if destinationPodName.GetStringValue() == "" {
			pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, key.DestinationAddress)
			if len(pods) > 0 && err == nil {
				pod, ok := pods[0].(*corev1.Pod)
				if !ok {
					klog.Warningf("Invalid Pod obj in cache")
				}
				destinationPodName.SetStringValue(pod.Name)
				if destinationPodNamespace, _, exist := record.GetInfoElementWithValue("destinationPodNamespace"); exist {
					destinationPodNamespace.SetStringValue(pod.Namespace)
				}
				if destinationNodeName, _, exist := record.GetInfoElementWithValue("destinationNodeName"); exist {
					destinationNodeName.SetStringValue(pod.Spec.NodeName)
				}
			} else {
				klog.Warning(err)
			}
		}
	}
}

func (fa *flowAggregator) fetchPodLabels(podAddress string) string {
	pods, err := fa.podInformer.Informer().GetIndexer().ByIndex(podInfoIndex, podAddress)
	if err != nil {
		klog.Warning(err)
		return ""
	} else if len(pods) == 0 {
		klog.InfoS("No Pod objects found for Pod Address", "podAddress", podAddress)
		return ""
	}
	pod, ok := pods[0].(*corev1.Pod)
	if !ok {
		klog.Warningf("Invalid Pod obj in cache")
	}
	labelsJSON, err := json.Marshal(pod.GetLabels())
	if err != nil {
		klog.Warningf("JSON encoding of Pod labels failed: %v", err)
		return ""
	}
	return string(labelsJSON)
}

func (fa *flowAggregator) fillPodLabels(key ipfixintermediate.FlowKey, record ipfixentities.Record) {
	podLabelString := fa.fetchPodLabels(key.SourceAddress)
	sourcePodLabelsElement, err := fa.registry.GetInfoElement("sourcePodLabels", ipfixregistry.AntreaEnterpriseID)
	if err == nil {
		sourcePodLabelsIE, err := ipfixentities.DecodeAndCreateInfoElementWithValue(sourcePodLabelsElement, bytes.NewBufferString(podLabelString).Bytes())
		if err != nil {
			klog.Warningf("Create sourcePodLabels InfoElementWithValue failed: %v", err)
		}
		err = record.AddInfoElement(sourcePodLabelsIE)
		if err != nil {
			klog.Warningf("Add sourcePodLabels InfoElementWithValue failed: %v", err)
		}
	} else {
		klog.Warningf("Get sourcePodLabels InfoElement failed: %v", err)
	}
	podLabelString = fa.fetchPodLabels(key.DestinationAddress)
	destinationPodLabelsElement, err := fa.registry.GetInfoElement("destinationPodLabels", ipfixregistry.AntreaEnterpriseID)
	if err == nil {
		destinationPodLabelsIE, err := ipfixentities.DecodeAndCreateInfoElementWithValue(destinationPodLabelsElement, bytes.NewBufferString(podLabelString).Bytes())
		if err != nil {
			klog.Warningf("Create destinationPodLabelsIE InfoElementWithValue failed: %v", err)
		}
		err = record.AddInfoElement(destinationPodLabelsIE)
		if err != nil {
			klog.Warningf("Add destinationPodLabels InfoElementWithValue failed: %v", err)
		}
	} else {
		klog.Warningf("Get destinationPodLabels InfoElement failed: %v", err)
	}
}

func (fa *flowAggregator) GetFlowRecords(flowKey *ipfixintermediate.FlowKey) []map[string]interface{} {
	return fa.aggregationProcess.GetRecords(flowKey)
}

func (fa *flowAggregator) GetRecordMetrics() querier.Metrics {
	return querier.Metrics{
		NumRecordsExported: fa.numRecordsExported,
		NumRecordsReceived: fa.collectingProcess.GetNumRecordsReceived(),
		NumFlows:           fa.aggregationProcess.GetNumFlows(),
		NumConnToCollector: fa.collectingProcess.GetNumConnToCollector(),
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
		klog.InfoS("Flow-aggregator configuration didn't changed")
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
}
