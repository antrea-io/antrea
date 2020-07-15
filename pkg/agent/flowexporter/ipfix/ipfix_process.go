// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipfix

import (
	"fmt"
	"net"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixexport "github.com/vmware/go-ipfix/pkg/exporter"
	ipfixregistry "github.com/vmware/go-ipfix/pkg/registry"
)

var _ IPFIXExportingProcess = new(ipfixExportingProcess)

type IPFIXExportingProcess interface {
	LoadRegistries()
	GetIANARegistryInfoElement(name string, isReverse bool) (*ipfixentities.InfoElement, error)
	GetAntreaRegistryInfoElement(name string, isReverse bool) (*ipfixentities.InfoElement, error)
	NewTemplateID() uint16
	AddRecordAndSendMsg(setType ipfixentities.ContentType, record ipfixentities.Record) (int, error)
	CloseConnToCollector()
}

type ipfixExportingProcess struct {
	*ipfixexport.ExportingProcess
	ianaReg   ipfixregistry.Registry
	antreaReg ipfixregistry.Registry
}

func NewIPFIXExportingProcess(collector net.Addr, obsID uint32, tempRefTimeout uint32) (*ipfixExportingProcess, error) {
	expProcess, err := ipfixexport.InitExportingProcess(collector, obsID, tempRefTimeout)
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

func (exp *ipfixExportingProcess) CloseConnToCollector() {
	exp.ExportingProcess.CloseConnToCollector()
	return
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

func (exp *ipfixExportingProcess) NewTemplateID() uint16 {
	return exp.ExportingProcess.NewTemplateID()
}
