package exporter

import (
	"fmt"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/ipfix"
	"hash/fnv"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	ipfixentities "github.com/srikartati/go-ipfixlib/pkg/entities"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
)

var (
	IANAInfoElements = []string{
		"flowStartSeconds",
		"flowEndSeconds",
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"packetTotalCount",
		"octetTotalCount",
		"packetDeltaCount",
		"octetDeltaCount",
		"reverse_PacketTotalCount",
		"reverse_OctetTotalCount",
		"reverse_PacketDeltaCount",
		"reverse_OctetDeltaCount",
	}
	AntreaInfoElements = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"destinationPodName",
		"destinationPodNamespace",
	}
)

var _ FlowExporter = new(flowExporter)

type FlowExporter interface {
	Run(stopCh <-chan struct{})
}

type flowExporter struct {
	flowRecords  flowrecords.FlowRecords
	process      ipfix.IPFIXExportingProcess
	elementsList []*ipfixentities.InfoElement
	templateID   uint16
}

func getNodeName() (string, error) {
	const nodeNameEnvKey = "NODE_NAME"
	nodeName := os.Getenv(nodeNameEnvKey)
	if nodeName != "" {
		return nodeName, nil
	}
	klog.Infof("Environment variable %s not found, using hostname instead", nodeNameEnvKey)
	var err error
	nodeName, err = os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get local hostname: %v", err)
	}
	return nodeName, nil
}

func genObservationID() (uint32, error) {
	name, err := getNodeName()
	if err != nil {
		return 0, err
	}
	h := fnv.New32()
	h.Write([]byte(name))
	return h.Sum32(), nil
}

func InitFlowExporter(collector net.Addr, records flowrecords.FlowRecords) (*flowExporter, error) {
	// Create IPFIX exporting expProcess and initialize registries and other related entities
	obsID, err := genObservationID()
	if err != nil {
		return nil, fmt.Errorf("cannot generate obsID for IPFIX ipfixexport: %v", err)
	}

	expProcess, err := ipfix.NewIPFIXExportingProcess(collector, obsID)
	if err != nil {
		return nil, fmt.Errorf("error while initializing IPFIX exporting expProcess: %v", err)
	}
	expProcess.LoadRegistries()

	flowExp := &flowExporter{
		records,
		expProcess,
		nil,
		0,
	}

	flowExp.templateID = flowExp.process.AddTemplate()
	templateRec := ipfix.NewIPFIXTemplateRecord(uint16(len(IANAInfoElements)+len(AntreaInfoElements)), flowExp.templateID)

	sentBytes, err := flowExp.sendTemplateRecord(templateRec)
	if err != nil {
		return nil, fmt.Errorf("error while creating and sending template record through IPFIX process: %v", err)
	}
	klog.V(2).Infof("Initialized flow exporter and sent %d bytes size of template record", sentBytes)

	return flowExp, nil
}

func (exp *flowExporter) Run(stopCh <-chan struct{}) {
	klog.Infof("Start exporting IPFIX flow records")
	for {
		select {
		case <-stopCh:
			exp.process.CloseConnToCollector()
			break
		case <-time.After(flowexporter.FlowExportInterval):
			err := exp.flowRecords.BuildFlowRecords()
			if err != nil {
				klog.Errorf("Error when building flow records: %v", err)
				return
			}
			err = exp.sendFlowRecords()
			if err != nil {
				klog.Errorf("Error when sending flow records: %v", err)
				return
			}
		}
	}
}

func (exp *flowExporter) sendFlowRecords() error {
	err := exp.flowRecords.IterateFlowRecordsWithSendCB(exp.sendDataRecord, exp.templateID)
	if err != nil {
		return fmt.Errorf("error in iterating flow records: %v", err)
	}
	return nil
}

func (exp *flowExporter) sendTemplateRecord(templateRec ipfix.IPFIXRecord) (int, error) {
	// Initialize this every time new template is added
	exp.elementsList = make([]*ipfixentities.InfoElement, len(IANAInfoElements)+len(AntreaInfoElements))
	// Add template header
	_, err := templateRec.PrepareRecord()
	if err != nil {
		return 0, fmt.Errorf("error when writing template header: %v", err)
	}

	for i, ie := range IANAInfoElements {
		var element *ipfixentities.InfoElement
		var err error
		if !strings.Contains(ie, "reverse") {
			element, err = exp.process.GetIANARegistryInfoElement(ie, false)
			if err != nil {
				return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
			}
		} else {
			split := strings.Split(ie, "_")
			runeStr := []rune(split[1])
			runeStr[0] = unicode.ToLower(runeStr[0])
			element, err = exp.process.GetIANARegistryInfoElement(string(runeStr), true)
			if err != nil {
				return 0, fmt.Errorf("%s not present. returned error: %v", ie, err)
			}
		}
		_, err = templateRec.AddInfoElement(element, nil)
		if err != nil {
			// Add error interface to IPFIX library in future to avoid overloading of fmt.Errorf.
			return 0, fmt.Errorf("error when adding %s to template: %v", element.Name, err)
		}
		exp.elementsList[i] = element
	}

	for i, ie := range AntreaInfoElements {
		element, err := exp.process.GetAntreaRegistryInfoElement(ie, false)
		if err != nil {
			return 0, fmt.Errorf("information element %s is not present in Antrea registry", ie)
		}
		templateRec.AddInfoElement(element, nil)
		exp.elementsList[i+len(IANAInfoElements)] = element
	}

	sentBytes, err := exp.process.AddRecordAndSendMsg(ipfixentities.Template, templateRec.GetRecord())
	if err != nil {
		return 0, fmt.Errorf("error in IPFIX exporting process when sending template record: %v", err)
	}

	return sentBytes, nil
}

func (exp *flowExporter) sendDataRecord(dataRec ipfix.IPFIXRecord, record flowexporter.FlowRecord) error {
	// Iterate over all infoElements in the list
	for _, ie := range exp.elementsList {
		var err error
		switch ieName := ie.Name; ieName {
		case "flowStartSeconds":
			_, err = dataRec.AddInfoElement(ie, record.Conn.StartTime.Unix())
		case "flowEndSeconds":
			_, err = dataRec.AddInfoElement(ie, record.Conn.StopTime.Unix())
		case "sourceIPv4Address":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.SourceAddress)
		case "destinationIPv4Address":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleReply.SourceAddress)
		case "sourceTransportPort":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.SourcePort)
		case "destinationTransportPort":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleReply.SourcePort)
		case "protocolIdentifier":
			_, err = dataRec.AddInfoElement(ie, record.Conn.TupleOrig.Protocol)
		case "packetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.OriginalPackets)
		case "octetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.OriginalBytes)
		case "packetDeltaCount":
			deltaPkts := int(record.Conn.OriginalPackets) - int(record.PrevPackets)
			if deltaPkts < 0 {
				klog.Warningf("Delta packets is not expected to be negative: %d", deltaPkts)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaPkts))
		case "octetDeltaCount":
			deltaBytes := int(record.Conn.OriginalBytes) - int(record.PrevBytes)
			if deltaBytes < 0 {
				klog.Warningf("Delta bytes is not expected to be negative: %d", deltaBytes)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaBytes))
		case "reverse_PacketTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.ReversePackets)
		case "reverse_OctetTotalCount":
			_, err = dataRec.AddInfoElement(ie, record.Conn.ReverseBytes)
		case "reverse_PacketDeltaCount":
			deltaPkts := int(record.Conn.ReversePackets) - int(record.PrevReversePackets)
			if deltaPkts < 0 {
				klog.Warningf("Delta packets is not expected to be negative: %d", deltaPkts)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaPkts))
		case "reverse_OctetDeltaCount":
			deltaBytes := int(record.Conn.ReverseBytes) - int(record.PrevReverseBytes)
			if deltaBytes < 0 {
				klog.Warningf("Delta bytes is not expected to be negative: %d", deltaBytes)
			}
			_, err = dataRec.AddInfoElement(ie, uint64(deltaBytes))
		case "sourcePodNamespace":
			_, err = dataRec.AddInfoElement(ie, record.Conn.SourcePodNamespace)
		case "sourcePodName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.SourcePodName)
		case "destinationPodNamespace":
			_, err = dataRec.AddInfoElement(ie, record.Conn.DestinationPodNamespace)
		case "destinationPodName":
			_, err = dataRec.AddInfoElement(ie, record.Conn.DestinationPodName)
		}
		if err != nil {
			return fmt.Errorf("error while adding info element: %s to data record: %v", ie.Name, err)
		}
	}
	klog.V(2).Infof("Flow data record created. Number of fields: %d, Bytes added: %d", dataRec.GetFieldCount(), dataRec.GetBuffer().Len())

	sentBytes, err := exp.process.AddRecordAndSendMsg(ipfixentities.Data, dataRec.GetRecord())
	if err != nil {
		return fmt.Errorf("error in IPFIX exporting process when sending data record: %v", err)
	}
	klog.V(2).Infof("Flow record sent successfully. Bytes sent: %d", sentBytes)

	return nil
}
