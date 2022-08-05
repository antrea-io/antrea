// Copyright 2022 Antrea Authors
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

package exporter

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/gammazero/deque"
	"github.com/google/uuid"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/clusteridentity"
	"antrea.io/antrea/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/ipfix"
)

const (
	maxQueueSize = 1 << 16 // 65536. ~50MB assuming 1KB per record
	sendInterval = 1 * time.Second
)

type stopPayload struct {
	flushQueue bool
}

// this is used for unit testing
var (
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		return exporter.initExportingProcess()
	}
)

type IPFIXExporter struct {
	externalFlowCollectorAddr  string
	externalFlowCollectorProto string
	exportingProcess           ipfix.IPFIXExportingProcess
	sendJSONRecord             bool
	includePodLabels           bool
	observationDomainID        uint32
	templateIDv4               uint16
	templateIDv6               uint16
	set                        ipfixentities.Set
	registry                   ipfix.IPFIXRegistry
	exportingProcessRunning    bool
	// mutex protects configuration state from concurrent access
	mutex sync.Mutex
	// deque buffers flows records between batch commits.
	deque *deque.Deque
	// dequeMutex is for concurrency between adding and removing records from deque.
	dequeMutex sync.Mutex
	// queueSize is the max size of deque
	queueSize    int
	sendInterval time.Duration
	// stopCh is the channel to receive stop message
	stopCh chan stopPayload
	// exportWg is to ensure that all messages have been flushed from the queue when we stop
	exportWg sync.WaitGroup
}

type queuedRecord struct {
	record       ipfixentities.Record
	isRecordIPv6 bool
}

// genObservationDomainID generates an IPFIX Observation Domain ID when one is not provided by the
// user through the flow aggregator configuration. It will first try to generate one
// deterministically based on the cluster UUID (if available, with a timeout of 10s). Otherwise, it
// will generate a random one. The cluster UUID should be available if Antrea is deployed to the
// cluster ahead of the flow aggregator, which is the expectation since when deploying flow
// aggregator as a Pod, networking needs to be configured by the CNI plugin.
func genObservationDomainID(k8sClient kubernetes.Interface) uint32 {
	const retryInterval = time.Second
	const timeout = 10 * time.Second
	const defaultAntreaNamespace = "kube-system"

	clusterIdentityProvider := clusteridentity.NewClusterIdentityProvider(
		defaultAntreaNamespace,
		clusteridentity.DefaultClusterIdentityConfigMapName,
		k8sClient,
	)
	var clusterUUID uuid.UUID
	if err := wait.PollImmediate(retryInterval, timeout, func() (bool, error) {
		clusterIdentity, _, err := clusterIdentityProvider.Get()
		if err != nil {
			return false, nil
		}
		clusterUUID = clusterIdentity.UUID
		return true, nil
	}); err != nil {
		klog.InfoS(
			"Unable to retrieve cluster UUID; will generate a random observation domain ID", "timeout", timeout, "ConfigMapNameSpace", defaultAntreaNamespace, "ConfigMapName", clusteridentity.DefaultClusterIdentityConfigMapName,
		)
		clusterUUID = uuid.New()
	}
	h := fnv.New32()
	h.Write(clusterUUID[:])
	observationDomainID := h.Sum32()
	return observationDomainID
}

func NewIPFIXExporter(
	k8sClient kubernetes.Interface,
	opt *options.Options,
	registry ipfix.IPFIXRegistry,
) *IPFIXExporter {
	var sendJSONRecord bool
	if opt.Config.FlowCollector.RecordFormat == "JSON" {
		sendJSONRecord = true
	} else {
		sendJSONRecord = false
	}

	var observationDomainID uint32
	if opt.Config.FlowCollector.ObservationDomainID != nil {
		observationDomainID = *opt.Config.FlowCollector.ObservationDomainID
	} else {
		observationDomainID = genObservationDomainID(k8sClient)
	}
	klog.InfoS("Flow aggregator Observation Domain ID", "Domain ID", observationDomainID)

	exporter := &IPFIXExporter{
		externalFlowCollectorAddr:  opt.ExternalFlowCollectorAddr,
		externalFlowCollectorProto: opt.ExternalFlowCollectorProto,
		sendJSONRecord:             sendJSONRecord,
		includePodLabels:           opt.Config.RecordContents.PodLabels,
		observationDomainID:        observationDomainID,
		registry:                   registry,
		set:                        ipfixentities.NewSet(false),
		deque:                      deque.New(),
		queueSize:                  maxQueueSize,
		sendInterval:               sendInterval,
	}

	return exporter
}

func (e *IPFIXExporter) Start() {
	e.startExportingProcess()
}

func (e *IPFIXExporter) Stop() {
	e.stopExportingProcess(true)
}

func (e *IPFIXExporter) startExportingProcess() {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if e.exportingProcessRunning {
		return
	}
	e.exportingProcessRunning = true
	e.stopCh = make(chan stopPayload, 1)
	e.exportWg.Add(1)
	go func() {
		defer e.exportWg.Done()
		e.runExportingProcess()
	}()
}

func (e *IPFIXExporter) stopExportingProcess(flushQueue bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if !e.exportingProcessRunning {
		return
	}
	e.exportingProcessRunning = false
	e.stopCh <- stopPayload{
		flushQueue: flushQueue,
	}
	e.exportWg.Wait()
}

// sendFirstQueuedRecord returns true if the function is invoked but the queue
// is empty.
func (e *IPFIXExporter) sendFirstQueuedRecord() (bool, error) {
	e.dequeMutex.Lock()
	defer e.dequeMutex.Unlock()
	if e.deque.Len() == 0 {
		return true, nil
	}
	qRecord := e.deque.At(0).(queuedRecord)
	err := e.sendRecord(qRecord.record, qRecord.isRecordIPv6)
	if err != nil {
		return false, err
	}
	e.deque.PopFront()
	// The queue may be empty now if the initial length was 1. However we
	// don't return true. Instead, we just let the caller call
	// sendFirstQueuedRecord again, at which point we will return true.
	return false, nil
}

func (e *IPFIXExporter) sendAllQueuedRecords(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			empty, err := e.sendFirstQueuedRecord()
			if err != nil {
				return err
			}
			if empty {
				return nil
			}
		}
	}
}

func (e *IPFIXExporter) runExportingProcess() {
	ctx := context.Background()
	const initRetryDelay = 10 * time.Second
	const flushTimeout = 5 * time.Second
	sendTimer := time.NewTimer(e.sendInterval)
	defer sendTimer.Stop()
	defer func() {
		if e.exportingProcess != nil {
			e.exportingProcess.CloseConnToCollector()
			e.exportingProcess = nil
		}
	}()
	for {
		select {
		case stop := <-e.stopCh:
			if !stop.flushQueue {
				return
			}
			if e.exportingProcess == nil {
				return
			}
			ctx, cancelFn := context.WithTimeout(ctx, flushTimeout)
			defer cancelFn()
			if err := e.sendAllQueuedRecords(ctx); err != nil {
				klog.ErrorS(err, "Error when flushing queued records, some records may be lost")
			}
			return
		case <-sendTimer.C:
			if e.exportingProcess == nil {
				if err := initIPFIXExportingProcess(e); err != nil {
					klog.ErrorS(err, "Error when initializing exporting process", "wait time for retry", initRetryDelay)
					sendTimer.Reset(initRetryDelay)
					continue
				}
			}
			if err := e.sendAllQueuedRecords(ctx); err != nil {
				// If there is an error when sending flow records because of intermittent connectivity, we reset the connection
				// to IPFIX collector and retry in the next export cycle to reinitialize the connection and send flow records.
				klog.ErrorS(err, "Error when sending queued records")
				e.exportingProcess.CloseConnToCollector()
				e.exportingProcess = nil
			}
			sendTimer.Reset(time.Second)
		}
	}
}

func (e *IPFIXExporter) AddRecord(record ipfixentities.Record, isRecordIPv6 bool) {
	e.dequeMutex.Lock()
	defer e.dequeMutex.Unlock()
	if e.deque.Len() >= e.queueSize {
		klog.V(2).InfoS("Queue for IPFIX exporter is full, dropping records")
	}
	for e.deque.Len() >= e.queueSize {
		e.deque.PopFront()
	}
	e.deque.PushBack(queuedRecord{
		record:       record,
		isRecordIPv6: isRecordIPv6,
	})
}

func (e *IPFIXExporter) updateExternalFlowCollectorAddr(address, protocol string) {
	if address == e.externalFlowCollectorAddr && protocol == e.externalFlowCollectorProto {
		return
	}
	klog.InfoS("Updating flow-collector address")
	e.stopExportingProcess(false)
	e.externalFlowCollectorAddr = address
	e.externalFlowCollectorProto = protocol
	klog.InfoS("Config ExternalFlowCollectorAddr is changed", "address", e.externalFlowCollectorAddr, "protocol", e.externalFlowCollectorProto)
	e.startExportingProcess()
}

func (e *IPFIXExporter) UpdateOptions(opt *options.Options) {
	e.updateExternalFlowCollectorAddr(opt.ExternalFlowCollectorAddr, opt.ExternalFlowCollectorProto)
}

func (e *IPFIXExporter) sendRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	templateID := e.templateIDv4
	if isRecordIPv6 {
		templateID = e.templateIDv6
	}
	// TODO: more records per data set will be supported when go-ipfix supports size check when adding records
	e.set.ResetSet()
	if err := e.set.PrepareSet(ipfixentities.Data, templateID); err != nil {
		return err
	}
	if err := e.set.AddRecord(record.GetOrderedElementList(), templateID); err != nil {
		return err
	}
	if e.exportingProcess != nil {
		sentBytes, err := e.exportingProcess.SendSet(e.set)
		if err != nil {
			return err
		}
		klog.V(4).InfoS("Data set sent successfully", "bytes sent", sentBytes)
	}
	return nil
}

func (e *IPFIXExporter) initExportingProcess() error {
	// TODO: This code can be further simplified by changing the go-ipfix API to accept
	// externalFlowCollectorAddr and externalFlowCollectorProto instead of net.Addr input.
	var expInput exporter.ExporterInput
	if e.externalFlowCollectorProto == "tcp" {
		// TCP transport does not need any tempRefTimeout, so sending 0.
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			TempRefTimeout:      0,
			IsEncrypted:         false,
			SendJSONRecord:      e.sendJSONRecord,
		}
	} else {
		// For UDP transport, hardcoding tempRefTimeout value as 1800s. So we will send out template every 30 minutes.
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			TempRefTimeout:      1800,
			IsEncrypted:         false,
			SendJSONRecord:      e.sendJSONRecord,
		}
	}
	ep, err := ipfix.NewIPFIXExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("got error when initializing IPFIX exporting process: %v", err)
	}
	e.exportingProcess = ep
	// Currently, we send two templates for IPv4 and IPv6 regardless of the IP families supported by cluster
	if err = e.createAndSendTemplate(false); err != nil {
		return err
	}
	if err = e.createAndSendTemplate(true); err != nil {
		return err
	}

	return nil
}

func (e *IPFIXExporter) createAndSendTemplate(isRecordIPv6 bool) error {
	templateID := e.exportingProcess.NewTemplateID()
	recordIPFamily := "IPv4"
	if isRecordIPv6 {
		recordIPFamily = "IPv6"
	}
	if isRecordIPv6 {
		e.templateIDv6 = templateID
	} else {
		e.templateIDv4 = templateID
	}
	bytesSent, err := e.sendTemplateSet(isRecordIPv6)
	if err != nil {
		e.exportingProcess.CloseConnToCollector()
		e.exportingProcess = nil
		e.set.ResetSet()
		return fmt.Errorf("sending %s template set failed, err: %v", recordIPFamily, err)
	}
	klog.V(2).InfoS("Exporting process initialized", "bytesSent", bytesSent, "templateSetIPFamily", recordIPFamily)
	return nil
}

func (e *IPFIXExporter) sendTemplateSet(isIPv6 bool) (int, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)
	ianaInfoElements := infoelements.IANAInfoElementsIPv4
	antreaInfoElements := infoelements.AntreaInfoElementsIPv4
	templateID := e.templateIDv4
	if isIPv6 {
		ianaInfoElements = infoelements.IANAInfoElementsIPv6
		antreaInfoElements = infoelements.AntreaInfoElementsIPv6
		templateID = e.templateIDv6
	}
	for _, ie := range ianaInfoElements {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range infoelements.IANAReverseInfoElements {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range antreaInfoElements {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	// The order of source and destination stats elements needs to match the order specified in
	// addFieldsForStatsAggregation method in go-ipfix aggregation process.
	for i := range infoelements.StatsElementList {
		// Add Antrea source stats fields
		ieName := infoelements.AntreaSourceStatsElementList[i]
		ie, err := e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add Antrea destination stats fields
		ieName = infoelements.AntreaDestinationStatsElementList[i]
		ie, err = e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for _, ie := range infoelements.AntreaFlowEndSecondsElementList {
		ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	for i := range infoelements.AntreaThroughputElementList {
		// Add common throughput fields
		ieName := infoelements.AntreaThroughputElementList[i]
		ie, err := e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add source node specific throughput fields
		ieName = infoelements.AntreaSourceThroughputElementList[i]
		ie, err = e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
		// Add destination node specific throughput fields
		ieName = infoelements.AntreaDestinationThroughputElementList[i]
		ie, err = e.createInfoElementForTemplateSet(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return 0, err
		}
		elements = append(elements, ie)
	}
	if e.includePodLabels {
		for _, ie := range infoelements.AntreaLabelsElementList {
			ie, err := e.createInfoElementForTemplateSet(ie, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return 0, err
			}
			elements = append(elements, ie)
		}
	}
	e.set.ResetSet()
	if err := e.set.PrepareSet(ipfixentities.Template, templateID); err != nil {
		return 0, err
	}
	err := e.set.AddRecord(elements, templateID)
	if err != nil {
		return 0, fmt.Errorf("error when adding record to set, error: %v", err)
	}
	bytesSent, err := e.exportingProcess.SendSet(e.set)
	return bytesSent, err
}

func (e *IPFIXExporter) createInfoElementForTemplateSet(ieName string, enterpriseID uint32) (ipfixentities.InfoElementWithValue, error) {
	element, err := e.registry.GetInfoElement(ieName, enterpriseID)
	if err != nil {
		return nil, fmt.Errorf("%s not present. returned error: %v", ieName, err)
	}
	ie, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	if err != nil {
		return nil, err
	}
	return ie, nil
}
