// Copyright 2025 Antrea Authors
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

package collector

import (
	"fmt"
	"sync"

	ipfixcollector "github.com/vmware/go-ipfix/pkg/collector"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
)

const (
	udpTransport          = "udp"
	tcpTransport          = "tcp"
	ipfixCollectorAddress = "0.0.0.0:4739"
)

type ipfixCollector struct {
	collectingProcess *ipfixcollector.CollectingProcess
	preprocessor      *preprocessor
}

func NewIPFIXCollector(
	recordCh chan *flowpb.Flow,
	aggregatorTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol,
	caCert, serverKey, serverCert []byte,
) (*ipfixCollector, error) {
	var cpInput ipfixcollector.CollectorInput
	switch aggregatorTransportProtocol {
	case flowaggregatorconfig.AggregatorTransportProtocolTLS:
		cpInput = ipfixcollector.CollectorInput{
			Address:       ipfixCollectorAddress,
			Protocol:      tcpTransport,
			MaxBufferSize: 65535,
			TemplateTTL:   0, // use default value from go-ipfix library
			IsEncrypted:   true,
			CACert:        caCert,
			ServerKey:     serverKey,
			ServerCert:    serverCert,
		}
	case flowaggregatorconfig.AggregatorTransportProtocolTCP:
		cpInput = ipfixcollector.CollectorInput{
			Address:       ipfixCollectorAddress,
			Protocol:      tcpTransport,
			MaxBufferSize: 65535,
			TemplateTTL:   0, // use default value from go-ipfix library
			IsEncrypted:   false,
		}
	case flowaggregatorconfig.AggregatorTransportProtocolUDP:
		cpInput = ipfixcollector.CollectorInput{
			Address:       ipfixCollectorAddress,
			Protocol:      udpTransport,
			MaxBufferSize: 1024,
			TemplateTTL:   0, // use default value from go-ipfix library
			IsEncrypted:   false,
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", aggregatorTransportProtocol)
	}
	// Tell the collector to accept IEs which are not part of the IPFIX registry (hardcoded in
	// the go-ipfix library). The preprocessor will take care of removing these elements.
	cpInput.DecodingMode = ipfixcollector.DecodingModeLenientKeepUnknown
	collectingProcess, err := ipfixcollector.InitCollectingProcess(cpInput)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPFIX collector: %w", err)
	}

	preprocessor, err := newPreprocessor(collectingProcess.GetMsgChan(), recordCh)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPFIX preprocessor: %w", err)
	}

	return &ipfixCollector{
		collectingProcess: collectingProcess,
		preprocessor:      preprocessor,
	}, nil
}

func (c *ipfixCollector) Run(stopCh <-chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// blocking function, will return when c.collectingProcess.Stop() is called
		c.collectingProcess.Start()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.preprocessor.Run(stopCh)
	}()
	<-stopCh
	c.collectingProcess.Stop()
	wg.Wait()
}

func (c *ipfixCollector) GetNumRecordsReceived() int64 {
	return c.collectingProcess.GetNumRecordsReceived()
}

func (c *ipfixCollector) GetNumConnsToCollector() int64 {
	return c.collectingProcess.GetNumConnToCollector()
}
