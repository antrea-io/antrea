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

	ipfixcollect "github.com/vmware/go-ipfix/pkg/collector"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
)

var _ IPFIXCollectingProcess = new(ipfixCollectingProcess)

// IPFIXCollectingProcess interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXCollectingProcess interface {
	Start()
	Stop()
	GetMsgChan() chan *ipfixentities.Message
	GetCollectingProcess() *ipfixcollect.CollectingProcess
}

type ipfixCollectingProcess struct {
	CollectingProcess *ipfixcollect.CollectingProcess
}

func NewIPFIXCollectingProcess(input ipfixcollect.CollectorInput) (*ipfixCollectingProcess, error) {
	cp, err := ipfixcollect.InitCollectingProcess(input)
	if err != nil {
		return nil, fmt.Errorf("error while initializing IPFIX collecting process: %v", err)
	}

	return &ipfixCollectingProcess{
		CollectingProcess: cp,
	}, nil
}

func (cp *ipfixCollectingProcess) Start() {
	cp.CollectingProcess.Start()
}

func (cp *ipfixCollectingProcess) Stop() {
	cp.CollectingProcess.Stop()
}

func (cp *ipfixCollectingProcess) GetMsgChan() chan *ipfixentities.Message {
	return cp.CollectingProcess.GetMsgChan()
}

func (cp *ipfixCollectingProcess) GetCollectingProcess() *ipfixcollect.CollectingProcess {
	return cp.CollectingProcess
}
