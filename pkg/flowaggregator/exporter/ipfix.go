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
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/afero"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/infoelements"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/ipfix"
	"antrea.io/antrea/pkg/util/env"
)

var (
	// this is used for unit testing
	initIPFIXExportingProcess = func(exporter *IPFIXExporter) error {
		return exporter.initExportingProcessImpl()
	}

	defaultFS = afero.NewOsFs()
)

const flowCollectorCertDir = "/etc/flow-aggregator/certs/flow-collector"

var ErrIPFIXExporterBackoff = errors.New("backoff needed")

type IPFIXExporter struct {
	config                     flowaggregatorconfig.FlowCollectorConfig
	externalFlowCollectorAddr  string
	externalFlowCollectorProto string
	exportingProcess           ipfix.IPFIXExportingProcess
	bufferedExporter           ipfix.IPFIXBufferedExporter
	sendJSONRecord             bool
	aggregatorMode             flowaggregatorconfig.AggregatorMode
	observationDomainID        uint32
	templateRefreshTimeout     time.Duration
	templateIDv4               uint16
	templateIDv6               uint16
	elementsV4                 []ipfixentities.InfoElementWithValue
	elementsV6                 []ipfixentities.InfoElementWithValue
	registry                   ipfix.IPFIXRegistry
	clusterUUID                uuid.UUID
	clusterID                  string
	maxIPFIXMsgSize            int
	tls                        ipfixExporterTLSConfig
	// initBackoff is used to enforce some minimum delay between initialization attempts.
	initBackoff wait.Backoff
	// initNextAttempt is the time after which the next initialization can be attempted.
	initNextAttempt time.Time
	clock           clock.Clock
}

type ipfixExporterTLSConfig struct {
	enable                          bool
	minVersion                      uint16
	externalFlowCollectorCAPath     string
	externalFlowCollectorServerName string
	exporterCertPath                string
	exporterKeyPath                 string
}

func newIPFIXExporterTLSConfig(config flowaggregatorconfig.FlowCollectorTLSConfig) ipfixExporterTLSConfig {
	var tlsConfig ipfixExporterTLSConfig
	if !config.Enable {
		return tlsConfig
	}
	tlsConfig.enable = true
	// config.MinVersion has already been validated during FA config validation.
	tlsConfig.minVersion = options.TLSVersionOrDie(config.MinVersion)
	if config.CASecretName != "" {
		tlsConfig.externalFlowCollectorCAPath = filepath.Join(flowCollectorCertDir, "ca.crt")
	}
	tlsConfig.externalFlowCollectorServerName = config.ServerName
	if config.ClientSecretName != "" {
		tlsConfig.exporterCertPath = filepath.Join(flowCollectorCertDir, "tls.crt")
		tlsConfig.exporterKeyPath = filepath.Join(flowCollectorCertDir, "tls.key")
	}
	return tlsConfig
}

// genObservationDomainID generates an IPFIX Observation Domain ID when one is not provided by the
// user through the flow aggregator configuration. It is generated as a hash of the cluster UUID.
func genObservationDomainID(clusterUUID uuid.UUID) uint32 {
	h := fnv.New32()
	h.Write(clusterUUID[:])
	observationDomainID := h.Sum32()
	return observationDomainID
}

func newInitBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      30 * time.Second,
	}
}

func NewIPFIXExporter(
	clusterUUID uuid.UUID,
	clusterID string,
	opt *options.Options,
	registry ipfix.IPFIXRegistry,
) *IPFIXExporter {
	return newIPFIXExporterWithClock(clusterUUID, clusterID, opt, registry, clock.RealClock{})
}

func newIPFIXExporterWithClock(
	clusterUUID uuid.UUID,
	clusterID string,
	opt *options.Options,
	registry ipfix.IPFIXRegistry,
	clock clock.Clock,
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
		observationDomainID = genObservationDomainID(clusterUUID)
	}
	klog.InfoS("Flow aggregator Observation Domain ID", "domainID", observationDomainID)

	exporter := &IPFIXExporter{
		config:                     opt.Config.FlowCollector,
		externalFlowCollectorAddr:  opt.ExternalFlowCollectorAddr,
		externalFlowCollectorProto: opt.ExternalFlowCollectorProto,
		sendJSONRecord:             sendJSONRecord,
		aggregatorMode:             opt.AggregatorMode,
		observationDomainID:        observationDomainID,
		templateRefreshTimeout:     opt.TemplateRefreshTimeout,
		registry:                   registry,
		clusterUUID:                clusterUUID,
		clusterID:                  clusterID,
		maxIPFIXMsgSize:            int(opt.Config.FlowCollector.MaxIPFIXMsgSize),
		tls:                        newIPFIXExporterTLSConfig(opt.Config.FlowCollector.TLS),
		initBackoff:                newInitBackoff(),
		initNextAttempt:            clock.Now(),
		clock:                      clock,
	}

	return exporter
}

func (e *IPFIXExporter) reset() {
	e.exportingProcess.CloseConnToCollector()
	e.exportingProcess = nil
}

func (e *IPFIXExporter) Start() {
	// no-op, initExportingProcessWithBackoff will be called whenever AddRecord is
	// called as needed.
}

func (e *IPFIXExporter) Stop() {
	if e.exportingProcess != nil {
		if err := e.bufferedExporter.Flush(); err != nil {
			klog.ErrorS(err, "Error when flushing buffered IPFIX exporter")
		}
		e.reset()
	}
}

// AddRecord will send the record to the destination IPFIX collector.
// If necessary, it will initialize the exporting process (i.e., the connection to the
// connector). An exponential backoff mechanism is used to limit the number of initialization
// attempts. If a delay is required before the next initialization attempt, an error wrapping
// ErrIPFIXExporterBackoff will be returned.
func (e *IPFIXExporter) AddRecord(record *flowpb.Flow, isRecordIPv6 bool) error {
	if err := e.sendRecord(record, isRecordIPv6); err != nil {
		if e.exportingProcess != nil {
			e.reset()
		}
		// in case of error:
		// in Aggregate mode: the FlowAggregator flowExportLoop will retry after activeFlowRecordTimeout
		// in Proxy mode: the FlowAggregator flowExportLoop will retry the next time a record is proxied
		return fmt.Errorf("error when sending IPFIX record: %w", err)
	}
	return nil
}

func (e *IPFIXExporter) UpdateOptions(opt *options.Options) {
	config := opt.Config.FlowCollector
	if reflect.DeepEqual(config, e.config) {
		return
	}

	e.config = config
	e.externalFlowCollectorAddr = opt.ExternalFlowCollectorAddr
	e.externalFlowCollectorProto = opt.ExternalFlowCollectorProto
	e.sendJSONRecord = config.RecordFormat == "JSON"
	if config.ObservationDomainID != nil {
		e.observationDomainID = *config.ObservationDomainID
	} else {
		e.observationDomainID = genObservationDomainID(e.clusterUUID)
	}
	e.templateRefreshTimeout = opt.TemplateRefreshTimeout
	e.maxIPFIXMsgSize = int(config.MaxIPFIXMsgSize)
	e.tls = newIPFIXExporterTLSConfig(config.TLS)
	klog.InfoS("New IPFIXExporter configuration", "collectorAddress", e.externalFlowCollectorAddr, "collectorProtocol", e.externalFlowCollectorProto, "sendJSON", e.sendJSONRecord, "domainID", e.observationDomainID, "templateRefreshTimeout", e.templateRefreshTimeout, "maxIPFIXMsgSize", e.maxIPFIXMsgSize, "tls", e.tls.enable)

	if e.exportingProcess != nil {
		if err := e.bufferedExporter.Flush(); err != nil {
			klog.ErrorS(err, "Error when flushing buffered IPFIX exporter")
		}
		e.reset()
	}
}

func (e *IPFIXExporter) makeIPFIXRecord(flow *flowpb.Flow, isIPv6 bool) ipfixentities.Record {
	var elements []ipfixentities.InfoElementWithValue
	if isIPv6 {
		elements = e.elementsV6
	} else {
		elements = e.elementsV4
	}
	idx := 0
	next := func() ipfixentities.InfoElementWithValue {
		e := elements[idx]
		idx += 1
		return e
	}

	// IANA IEs
	next().SetUnsigned32Value(uint32(flow.StartTs.Seconds))
	next().SetUnsigned32Value(uint32(flow.EndTs.Seconds))
	next().SetUnsigned8Value(uint8(flow.EndReason))
	next().SetUnsigned16Value(uint16(flow.Transport.SourcePort))
	next().SetUnsigned16Value(uint16(flow.Transport.DestinationPort))
	next().SetUnsigned8Value(uint8(flow.Transport.ProtocolNumber))
	next().SetUnsigned64Value(flow.Stats.PacketTotalCount)
	next().SetUnsigned64Value(flow.Stats.OctetTotalCount)
	next().SetUnsigned64Value(flow.Stats.PacketDeltaCount)
	next().SetUnsigned64Value(flow.Stats.OctetDeltaCount)
	next().SetIPAddressValue(flow.Ip.Source)
	next().SetIPAddressValue(flow.Ip.Destination)
	// IANAReverse IEs
	next().SetUnsigned64Value(flow.ReverseStats.PacketTotalCount)
	next().SetUnsigned64Value(flow.ReverseStats.OctetTotalCount)
	next().SetUnsigned64Value(flow.ReverseStats.PacketDeltaCount)
	next().SetUnsigned64Value(flow.ReverseStats.OctetDeltaCount)
	// Antrea IEs
	next().SetStringValue(flow.K8S.SourcePodName)
	next().SetStringValue(flow.K8S.SourcePodNamespace)
	next().SetStringValue(flow.K8S.SourceNodeName)
	next().SetStringValue(flow.K8S.DestinationPodName)
	next().SetStringValue(flow.K8S.DestinationPodNamespace)
	next().SetStringValue(flow.K8S.DestinationNodeName)
	next().SetUnsigned16Value(uint16(flow.K8S.DestinationServicePort))
	next().SetStringValue(flow.K8S.DestinationServicePortName)
	next().SetStringValue(flow.K8S.IngressNetworkPolicyName)
	next().SetStringValue(flow.K8S.IngressNetworkPolicyNamespace)
	next().SetUnsigned8Value(uint8(flow.K8S.IngressNetworkPolicyType))
	next().SetStringValue(flow.K8S.IngressNetworkPolicyRuleName)
	next().SetUnsigned8Value(uint8(flow.K8S.IngressNetworkPolicyRuleAction))
	next().SetStringValue(flow.K8S.EgressNetworkPolicyName)
	next().SetStringValue(flow.K8S.EgressNetworkPolicyNamespace)
	next().SetUnsigned8Value(uint8(flow.K8S.EgressNetworkPolicyType))
	next().SetStringValue(flow.K8S.EgressNetworkPolicyRuleName)
	next().SetUnsigned8Value(uint8(flow.K8S.EgressNetworkPolicyRuleAction))
	next().SetStringValue(flow.Transport.GetTCP().GetStateName()) // Use Getter functions in case transport is not TCP
	next().SetUnsigned8Value(uint8(flow.K8S.FlowType))
	next().SetStringValue(flow.K8S.EgressName)
	next().SetStringValue(net.IP(flow.K8S.EgressIp).String())
	next().SetStringValue(flow.App.ProtocolName)
	next().SetStringValue(string(flow.App.HttpVals))
	next().SetStringValue(flow.K8S.EgressNodeName)
	next().SetIPAddressValue(flow.K8S.DestinationClusterIp)
	if e.aggregatorMode == flowaggregatorconfig.AggregatorModeAggregate {
		// Add Antrea source stats fields
		next().SetUnsigned64Value(flow.Aggregation.StatsFromSource.PacketTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.StatsFromSource.OctetTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.StatsFromSource.PacketDeltaCount)
		next().SetUnsigned64Value(flow.Aggregation.StatsFromSource.OctetDeltaCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromSource.PacketTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromSource.OctetTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromSource.PacketDeltaCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromSource.OctetDeltaCount)
		// Add Antrea destination stats fields
		next().SetUnsigned64Value(flow.Aggregation.StatsFromDestination.PacketTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.StatsFromDestination.OctetTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.StatsFromDestination.PacketDeltaCount)
		next().SetUnsigned64Value(flow.Aggregation.StatsFromDestination.OctetDeltaCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromDestination.PacketTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromDestination.OctetTotalCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromDestination.PacketDeltaCount)
		next().SetUnsigned64Value(flow.Aggregation.ReverseStatsFromDestination.OctetDeltaCount)
		// Add Antrea flow end seconds fields
		next().SetUnsigned32Value(uint32(flow.Aggregation.EndTsFromSource.Seconds))
		next().SetUnsigned32Value(uint32(flow.Aggregation.EndTsFromDestination.Seconds))
		// Add common throughput fields
		next().SetUnsigned64Value(flow.Aggregation.Throughput)
		next().SetUnsigned64Value(flow.Aggregation.ReverseThroughput)
		next().SetUnsigned64Value(flow.Aggregation.ThroughputFromSource)
		next().SetUnsigned64Value(flow.Aggregation.ReverseThroughputFromSource)
		next().SetUnsigned64Value(flow.Aggregation.ThroughputFromDestination)
		next().SetUnsigned64Value(flow.Aggregation.ReverseThroughputFromDestination)
	}

	// Add Pod label fields
	var sourcePodLabels string
	if flow.K8S.SourcePodLabels != nil {
		b, err := json.Marshal(flow.K8S.SourcePodLabels.Labels)
		if err == nil {
			sourcePodLabels = string(b)
		}
	}
	next().SetStringValue(sourcePodLabels)
	var destinationPodLabels string
	if flow.K8S.DestinationPodLabels != nil {
		b, err := json.Marshal(flow.K8S.DestinationPodLabels.Labels)
		if err == nil {
			destinationPodLabels = string(b)
		}
	}
	next().SetStringValue(destinationPodLabels)

	next().SetStringValue(e.clusterID)

	// Proxy-mode specific IEs
	if e.aggregatorMode == flowaggregatorconfig.AggregatorModeProxy {
		next().SetUnsigned32Value(flow.Ipfix.ObservationDomainId)
		exporterIP := net.ParseIP(flow.Ipfix.ExporterIp)
		if ip := exporterIP.To4(); ip != nil {
			next().SetIPAddressValue(ip)
		} else {
			next().SetIPAddressValue(net.IPv4zero)
		}
		if exporterIP.To4() == nil {
			next().SetIPAddressValue(exporterIP)
		} else {
			next().SetIPAddressValue(net.IPv6zero)
		}
		next().SetUnsigned8Value(uint8(flow.FlowDirection))
	}

	templateID := e.templateIDv4
	if isIPv6 {
		templateID = e.templateIDv6
	}
	return ipfixentities.NewDataRecordFromElements(templateID, elements)
}

func (e *IPFIXExporter) sendRecord(flow *flowpb.Flow, isRecordIPv6 bool) error {
	if e.exportingProcess == nil {
		if err := e.initExportingProcessWithBackoff(); err != nil {
			// in case of error:
			// in Aggregate mode: the FlowAggregator flowExportLoop will retry after activeFlowRecordTimeout
			// in Proxy mode: the FlowAggregator flowExportLoop will retry the next time a record is proxied
			return fmt.Errorf("error when initializing IPFIX exporting process: %w", err)
		}
	}
	record := e.makeIPFIXRecord(flow, isRecordIPv6)
	if err := e.bufferedExporter.AddRecord(record); err != nil {
		return err
	}
	klog.V(7).InfoS("Data record added successfully")
	return nil
}

func inPod() bool {
	return env.GetPodNamespace() != ""
}

func getMTU(ifaceName string) (int, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}

func (e *IPFIXExporter) prepareExportingProcessTLSClientConfig() (*exporter.ExporterTLSClientConfig, error) {
	if !e.tls.enable {
		return nil, nil
	}
	exporterConfig := &exporter.ExporterTLSClientConfig{
		ServerName: e.tls.externalFlowCollectorServerName,
		MinVersion: e.tls.minVersion,
	}
	if e.tls.externalFlowCollectorCAPath != "" {
		caBytes, err := afero.ReadFile(defaultFS, e.tls.externalFlowCollectorCAPath)
		if err != nil {
			return nil, fmt.Errorf("error when reading CA cert %q, ensure Secret %q exists in this Namespace and has the 'ca.crt' key: %w", e.tls.externalFlowCollectorCAPath, e.config.TLS.CASecretName, err)
		}
		exporterConfig.CAData = caBytes
	}
	if e.tls.exporterCertPath != "" {
		certBytes, err := afero.ReadFile(defaultFS, e.tls.exporterCertPath)
		if err != nil {
			return nil, fmt.Errorf("error when reading client cert %q, ensure Secret %q exists in this Namespace and has the 'tls.crt' key: %w", e.tls.exporterCertPath, e.config.TLS.ClientSecretName, err)
		}
		exporterConfig.CertData = certBytes
	}
	if e.tls.exporterKeyPath != "" {
		keyBytes, err := afero.ReadFile(defaultFS, e.tls.exporterKeyPath)
		if err != nil {
			return nil, fmt.Errorf("error when reading client key %q, ensure Secret %q exists in this Namespace and has the 'tls.key' key: %w", e.tls.exporterKeyPath, e.config.TLS.ClientSecretName, err)
		}
		exporterConfig.KeyData = keyBytes
	}
	return exporterConfig, nil
}

func (e *IPFIXExporter) initExportingProcess() error {
	return initIPFIXExportingProcess(e)
}

func (e *IPFIXExporter) initExportingProcessWithBackoff() error {
	now := e.clock.Now()
	if e.initNextAttempt.After(now) {
		return ErrIPFIXExporterBackoff
	}
	e.initNextAttempt = now.Add(e.initBackoff.Step())
	if err := e.initExportingProcess(); err != nil {
		return err
	}
	// Reset backoff after a successful initialization.
	e.initBackoff = newInitBackoff()
	e.initNextAttempt = now
	return nil
}

func (e *IPFIXExporter) initExportingProcessImpl() error {
	// We reload the certificate data every time, in case the files have been updated.
	tlsClientConfig, err := e.prepareExportingProcessTLSClientConfig()
	if err != nil {
		return fmt.Errorf("error when preparing TLS config for exporter: %w", err)
	}
	if tlsClientConfig != nil {
		klog.InfoS("TLS is enabled for IPFIXExporter", "protocol", e.externalFlowCollectorProto, "customRoots", tlsClientConfig.CAData != nil, "clientAuth", tlsClientConfig.CertData != nil)
	} else {
		klog.InfoS("TLS is disabled for IPFIXExporter", "protocol", e.externalFlowCollectorProto)
	}
	var expInput exporter.ExporterInput
	if e.externalFlowCollectorProto == "tcp" {
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			// TCP transport does not need any tempRefTimeout, so sending 0.
			TempRefTimeout:  0,
			TLSClientConfig: tlsClientConfig,
			SendJSONRecord:  e.sendJSONRecord,
		}
	} else {
		expInput = exporter.ExporterInput{
			CollectorAddress:    e.externalFlowCollectorAddr,
			CollectorProtocol:   e.externalFlowCollectorProto,
			ObservationDomainID: e.observationDomainID,
			TempRefTimeout:      uint32(e.templateRefreshTimeout.Seconds()),
			TLSClientConfig:     tlsClientConfig,
			SendJSONRecord:      e.sendJSONRecord,
		}
		if inPod() {
			// In a Pod, the primary network interface is always "eth0", and we assume
			// this is the interface used to connect to the IPFIX collector.
			// The FlowAggregator is not meant to be run in the host network.
			mtu, err := getMTU("eth0")
			if err != nil {
				klog.ErrorS(err, "Failed to determine uplink MTU")
			} else {
				// In practice the only guarantee we have is that PMTU <=
				// MTU. However, this is a reasonable approximation for most
				// scenarios. Note that MaxMessageSize is an available override in
				// the config.
				expInput.PathMTU = mtu
			}
		} else {
			klog.InfoS("Not running as Pod, cannot determine interface MTU")
		}
	}
	expInput.MaxMsgSize = e.maxIPFIXMsgSize

	ep, err := exporter.InitExportingProcess(expInput)
	if err != nil {
		return fmt.Errorf("got error when initializing IPFIX exporting process: %w", err)
	}
	e.exportingProcess = ep
	e.bufferedExporter = exporter.NewBufferedIPFIXExporter(ep)
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
	// These elements will be used for data records as well, to avoid extra memory allocations.
	elements, err := e.prepareElements(isRecordIPv6)
	if err != nil {
		return err
	}
	if isRecordIPv6 {
		e.elementsV6 = elements
	} else {
		e.elementsV4 = elements
	}
	if err := e.sendTemplateSet(isRecordIPv6); err != nil {
		// No need to flush first, as no data records should have been sent yet.
		e.reset()
		return fmt.Errorf("sending %s template set failed, err: %w", recordIPFamily, err)
	}
	klog.V(2).InfoS("Exporting process initialized", "templateSetIPFamily", recordIPFamily)
	return nil
}

func (e *IPFIXExporter) prepareElements(isIPv6 bool) ([]ipfixentities.InfoElementWithValue, error) {
	elements := make([]ipfixentities.InfoElementWithValue, 0)
	ianaInfoElements := infoelements.IANAInfoElementsIPv4
	antreaInfoElements := infoelements.AntreaInfoElementsIPv4
	if isIPv6 {
		ianaInfoElements = infoelements.IANAInfoElementsIPv6
		antreaInfoElements = infoelements.AntreaInfoElementsIPv6
	}

	for _, ieName := range ianaInfoElements {
		ie, err := e.createInfoElement(ieName, ipfixregistry.IANAEnterpriseID)
		if err != nil {
			return nil, err
		}
		elements = append(elements, ie)
	}
	for _, ieName := range infoelements.IANAReverseInfoElements {
		ie, err := e.createInfoElement(ieName, ipfixregistry.IANAReversedEnterpriseID)
		if err != nil {
			return nil, err
		}
		elements = append(elements, ie)
	}
	for _, ieName := range antreaInfoElements {
		ie, err := e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return nil, err
		}
		elements = append(elements, ie)
	}
	if e.aggregatorMode == flowaggregatorconfig.AggregatorModeAggregate {
		for i := range infoelements.StatsElementList {
			// Add Antrea source stats fields
			ieName := infoelements.AntreaSourceStatsElementList[i]
			ie, err := e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
			// Add Antrea destination stats fields
			ieName = infoelements.AntreaDestinationStatsElementList[i]
			ie, err = e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
		}
		for _, ieName := range infoelements.AntreaFlowEndSecondsElementList {
			ie, err := e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
		}
		for i := range infoelements.AntreaThroughputElementList {
			// Add common throughput fields
			ieName := infoelements.AntreaThroughputElementList[i]
			ie, err := e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
			// Add source node specific throughput fields
			ieName = infoelements.AntreaSourceThroughputElementList[i]
			ie, err = e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
			// Add destination node specific throughput fields
			ieName = infoelements.AntreaDestinationThroughputElementList[i]
			ie, err = e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
		}
	}
	for _, ieName := range infoelements.AntreaLabelsElementList {
		ie, err := e.createInfoElement(ieName, ipfixregistry.AntreaEnterpriseID)
		if err != nil {
			return nil, err
		}
		elements = append(elements, ie)
	}
	ie, err := e.createInfoElement("clusterId", ipfixregistry.AntreaEnterpriseID)
	if err != nil {
		return nil, err
	}
	elements = append(elements, ie)
	if e.aggregatorMode == flowaggregatorconfig.AggregatorModeProxy {
		for _, ieName := range infoelements.IANAProxyModeElementList {
			ie, err := e.createInfoElement(ieName, ipfixregistry.IANAEnterpriseID)
			if err != nil {
				return nil, err
			}
			elements = append(elements, ie)
		}
	}

	return elements, nil
}

func (e *IPFIXExporter) sendTemplateSet(isIPv6 bool) error {
	elements := e.elementsV4
	templateID := e.templateIDv4
	if isIPv6 {
		elements = e.elementsV6
		templateID = e.templateIDv6
	}
	record := ipfixentities.NewTemplateRecordFromElements(templateID, elements)
	// Ideally we would not have to do it explicitly, it would be taken care of by the go-ipfix library.
	record.PrepareRecord()
	return e.bufferedExporter.AddRecord(record)
}

func (e *IPFIXExporter) createInfoElement(ieName string, enterpriseID uint32) (ipfixentities.InfoElementWithValue, error) {
	element, err := e.registry.GetInfoElement(ieName, enterpriseID)
	if err != nil {
		return nil, fmt.Errorf("%s not present. returned error: %w", ieName, err)
	}
	ie, err := ipfixentities.DecodeAndCreateInfoElementWithValue(element, nil)
	if err != nil {
		return nil, err
	}
	return ie, nil
}

func (e *IPFIXExporter) Flush() error {
	if e.exportingProcess == nil {
		return nil
	}
	if err := e.bufferedExporter.Flush(); err != nil {
		e.reset()
		return err
	}
	return nil
}
