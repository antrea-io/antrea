// Copyright 2023 Antrea Authors
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

package flowlogger

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
)

const MaxLatency = 5 * time.Second

type FlowLogger struct {
	sync.Mutex
	logger     io.Closer
	maxLatency time.Duration
	writer     *bufio.Writer
}

func NewFlowLogger(path string, maxSize int, maxBackups int, maxAge int, compress bool) *FlowLogger {
	logger := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   compress,
	}
	return &FlowLogger{
		logger:     logger,
		maxLatency: MaxLatency,
		writer:     bufio.NewWriter(logger),
	}
}

func (fl *FlowLogger) FlushLoop(stopCh <-chan struct{}) {
	t := time.NewTicker(fl.maxLatency)
	defer t.Stop()
	for {
		select {
		case <-stopCh:
			fl.Flush()
			return
		case <-t.C:
			fl.Flush()
		}
	}
}

func (fl *FlowLogger) Close() {
	fl.logger.Close()
}

func (fl *FlowLogger) WriteRecord(r *flowrecord.FlowRecord, prettyPrint bool) error {
	var protocolID string
	var ingressNetworkPolicyRuleAction, ingressNetworkPolicyType string
	var egressNetworkPolicyRuleAction, egressNetworkPolicyType string
	if prettyPrint {
		protocolID = PrettyPrintProtocolIdentifier(r.ProtocolIdentifier)
		ingressNetworkPolicyRuleAction = PrettyPrintRuleAction(r.IngressNetworkPolicyRuleAction)
		ingressNetworkPolicyType = PrettyPrintPolicyType(r.IngressNetworkPolicyType)
		egressNetworkPolicyRuleAction = PrettyPrintRuleAction(r.EgressNetworkPolicyRuleAction)
		egressNetworkPolicyType = PrettyPrintPolicyType(r.EgressNetworkPolicyType)
	} else {
		protocolID = fmt.Sprintf("%d", r.ProtocolIdentifier)
		ingressNetworkPolicyRuleAction = fmt.Sprintf("%d", r.IngressNetworkPolicyRuleAction)
		ingressNetworkPolicyType = fmt.Sprintf("%d", r.IngressNetworkPolicyType)
		egressNetworkPolicyRuleAction = fmt.Sprintf("%d", r.EgressNetworkPolicyRuleAction)
		egressNetworkPolicyType = fmt.Sprintf("%d", r.EgressNetworkPolicyType)
	}

	fields := []string{
		fmt.Sprintf("%d", r.FlowStartSeconds.Unix()),
		fmt.Sprintf("%d", r.FlowEndSeconds.Unix()),
		r.SourceIP,
		r.DestinationIP,
		fmt.Sprintf("%d", r.SourceTransportPort),
		fmt.Sprintf("%d", r.DestinationTransportPort),
		protocolID,
		r.SourcePodName,
		r.SourcePodNamespace,
		r.SourceNodeName,
		r.DestinationPodName,
		r.DestinationPodNamespace,
		r.DestinationNodeName,
		r.DestinationClusterIP,
		fmt.Sprintf("%d", r.DestinationServicePort),
		r.DestinationServicePortName,
		r.IngressNetworkPolicyName,
		r.IngressNetworkPolicyNamespace,
		r.IngressNetworkPolicyRuleName,
		ingressNetworkPolicyRuleAction,
		ingressNetworkPolicyType,
		r.EgressNetworkPolicyName,
		r.EgressNetworkPolicyNamespace,
		r.EgressNetworkPolicyRuleName,
		egressNetworkPolicyRuleAction,
		egressNetworkPolicyType,
		r.EgressName,
		r.EgressIP,
		r.AppProtocolName,
		r.HttpVals,
		r.EgressNodeName,
	}

	str := strings.Join(fields, ",")

	fl.Lock()
	defer fl.Unlock()
	if _, err := io.WriteString(fl.writer, str); err != nil {
		return err
	}
	if _, err := io.WriteString(fl.writer, "\n"); err != nil {
		return err
	}
	return nil
}

func (fl *FlowLogger) Flush() error {
	fl.Lock()
	defer fl.Unlock()
	return fl.writer.Flush()
}
