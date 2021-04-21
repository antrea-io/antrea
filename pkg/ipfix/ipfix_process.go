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

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixexport "github.com/vmware/go-ipfix/pkg/exporter"
)

var _ IPFIXExportingProcess = new(ipfixExportingProcess)

// IPFIXExportingProcess interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXExportingProcess interface {
	NewTemplateID() uint16
	SendSet(set ipfixentities.Set) (int, error)
	CloseConnToCollector()
}

type ipfixExportingProcess struct {
	*ipfixexport.ExportingProcess
}

func NewIPFIXExportingProcess(input ipfixexport.ExporterInput) (*ipfixExportingProcess, error) {
	expProcess, err := ipfixexport.InitExportingProcess(input)
	if err != nil {
		return nil, fmt.Errorf("error while initializing IPFIX exporting process: %v", err)
	}

	return &ipfixExportingProcess{
		ExportingProcess: expProcess,
	}, nil
}

func (exp *ipfixExportingProcess) SendSet(set ipfixentities.Set) (int, error) {
	sentBytes, err := exp.ExportingProcess.SendSet(set)
	return sentBytes, err
}

func (exp *ipfixExportingProcess) CloseConnToCollector() {
	exp.ExportingProcess.CloseConnToCollector()
	return
}

func (exp *ipfixExportingProcess) NewTemplateID() uint16 {
	return exp.ExportingProcess.NewTemplateID()
}
