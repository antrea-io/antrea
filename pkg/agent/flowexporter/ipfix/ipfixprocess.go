package ipfix

import (
	"fmt"
	"net"

	ipfixentities "github.com/srikartati/go-ipfixlib/pkg/entities"
	ipfixexport "github.com/srikartati/go-ipfixlib/pkg/exporter"
	ipfixregistry "github.com/srikartati/go-ipfixlib/pkg/registry"
)

var _ IPFIXExportingProcess = new(ipfixExportingProcess)

type IPFIXExportingProcess interface {
	LoadRegistries()
	GetIANARegistryInfoElement(name string, isReverse bool) (*ipfixentities.InfoElement, error)
	GetAntreaRegistryInfoElement(name string, isReverse bool) (*ipfixentities.InfoElement, error)
	AddTemplate() uint16
	AddRecordAndSendMsg(setType ipfixentities.ContentType, record ipfixentities.Record) (int, error)
	CloseConnToCollector() error
}

type ipfixExportingProcess struct {
	*ipfixexport.ExportingProcess
	ianaReg   ipfixregistry.Registry
	antreaReg ipfixregistry.Registry
}

func NewIPFIXExportingProcess(collector net.Addr, obsID uint32) (*ipfixExportingProcess, error) {
	expProcess, err := ipfixexport.InitExportingProcess(collector, obsID)
	if err != nil {
		return nil, fmt.Errorf("error while initializing IPFIX exporting process: %v", err)
	}

	return &ipfixExportingProcess{
		ExportingProcess: expProcess,
	}, nil
}

func (exp *ipfixExportingProcess) AddRecordAndSendMsg(setType ipfixentities.ContentType, record ipfixentities.Record) (int, error) {
	sentBytes, err := exp.ExportingProcess.AddRecordAndSendMsg(setType, record)
	return sentBytes, err
}

func (exp *ipfixExportingProcess) CloseConnToCollector() error {
	err := exp.ExportingProcess.CloseConnToCollector()
	return err
}

func (exp *ipfixExportingProcess) LoadRegistries() {
	exp.ianaReg = ipfixregistry.NewIanaRegistry()
	exp.ianaReg.LoadRegistry()
	exp.antreaReg = ipfixregistry.NewAntreaRegistry()
	exp.antreaReg.LoadRegistry()
	return
}

func (exp *ipfixExportingProcess) GetIANARegistryInfoElement(name string, isReverse bool) (*ipfixentities.InfoElement, error) {
	var ie *ipfixentities.InfoElement
	var err error
	if !isReverse {
		ie, err = exp.ianaReg.GetInfoElement(name)
	} else {
		ie, err = exp.ianaReg.GetReverseInfoElement(name)
	}
	return ie, err
}

func (exp *ipfixExportingProcess) GetAntreaRegistryInfoElement(name string, isReverse bool) (*ipfixentities.InfoElement, error) {
	var ie *ipfixentities.InfoElement
	var err error
	if !isReverse {
		ie, err = exp.antreaReg.GetInfoElement(name)
	} else {
		ie, err = exp.antreaReg.GetReverseInfoElement(name)
	}
	return ie, err
}

func (exp *ipfixExportingProcess) AddTemplate() uint16 {
	return exp.ExportingProcess.AddTemplate()
}
