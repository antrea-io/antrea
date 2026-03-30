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

package exporter

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"

	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/flowlogger"
	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/ringbuffer"
)

type flowFilter struct {
	IngressNetworkPolicyRuleActions []uint8
	EgressNetworkPolicyRuleActions  []uint8
}

type LogExporter struct {
	config     flowaggregatorconfig.FlowLoggerConfig
	filters    []flowFilter
	flowLogger *flowlogger.FlowLogger
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewLogExporter(opt *options.Options) (*LogExporter, error) {
	config := opt.Config.FlowLogger
	klog.InfoS("FlowLogger configuration", "path", config.Path, "maxSize", config.MaxSize, "maxBackups", config.MaxBackups, "maxAge", config.MaxAge, "compress", *config.Compress, "prettyPrint", *config.PrettyPrint)
	exporter := &LogExporter{
		config: config,
	}
	exporter.buildFilters()
	return exporter, nil
}

func (e *LogExporter) buildFilters() {
	ruleActionToUint8 := func(a flowaggregatorconfig.NetworkPolicyRuleAction) uint8 {
		switch a {
		case flowaggregatorconfig.NetworkPolicyRuleActionNone:
			return uint8(flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_NO_ACTION)
		case flowaggregatorconfig.NetworkPolicyRuleActionAllow:
			return uint8(flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW)
		case flowaggregatorconfig.NetworkPolicyRuleActionDrop:
			return uint8(flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP)
		case flowaggregatorconfig.NetworkPolicyRuleActionReject:
			return uint8(flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT)
		default: // invalid case
			return math.MaxUint8
		}
	}
	convertFilter := func(in *flowaggregatorconfig.FlowFilter) flowFilter {
		ingressNetworkPolicyRuleActions := make([]uint8, len(in.IngressNetworkPolicyRuleActions))
		for idx, a := range in.IngressNetworkPolicyRuleActions {
			ingressNetworkPolicyRuleActions[idx] = ruleActionToUint8(a)
		}
		egressNetworkPolicyRuleActions := make([]uint8, len(in.EgressNetworkPolicyRuleActions))
		for idx, a := range in.EgressNetworkPolicyRuleActions {
			egressNetworkPolicyRuleActions[idx] = ruleActionToUint8(a)
		}
		return flowFilter{
			IngressNetworkPolicyRuleActions: ingressNetworkPolicyRuleActions,
			EgressNetworkPolicyRuleActions:  egressNetworkPolicyRuleActions,
		}
	}
	e.filters = make([]flowFilter, 0, len(e.config.Filters))
	for idx := range e.config.Filters {
		e.filters = append(e.filters, convertFilter(&e.config.Filters[idx]))
	}
}

func (e *LogExporter) applyFilters(r *flowrecord.FlowRecord) bool {
	if len(e.filters) == 0 {
		return true
	}
	for idx := range e.filters {
		filter := &e.filters[idx]
		if len(filter.IngressNetworkPolicyRuleActions) > 0 && !slices.Contains(filter.IngressNetworkPolicyRuleActions, r.IngressNetworkPolicyRuleAction) {
			continue
		}
		if len(filter.EgressNetworkPolicyRuleActions) > 0 && !slices.Contains(filter.EgressNetworkPolicyRuleActions, r.EgressNetworkPolicyRuleAction) {
			continue
		}
		return true
	}
	return false
}

// Run consumes flow records from the ring buffer and writes them to a local log file.
// It blocks until ctx is cancelled or the consumer signals shutdown.
func (e *LogExporter) Run(ctx context.Context, buf ringbuffer.BroadcastBuffer[*flowpb.Flow]) {
	consumer := buf.NewConsumer(ringbuffer.WithMaxConsumeDeadline(1 * time.Second))
	e.stopCh = make(chan struct{})
	e.flowLogger = flowlogger.NewFlowLogger(
		e.config.Path,
		int(e.config.MaxSize),
		int(e.config.MaxBackups),
		int(e.config.MaxAge),
		*e.config.Compress,
	)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.flowLogger.FlushLoop(e.stopCh)
	}()

	defer func() {
		close(e.stopCh)
		e.wg.Wait()
		e.flowLogger.Close()
		e.flowLogger = nil
	}()

	for {
		record, n, _, shutdown := consumer.Consume()
		if n == 0 {
			if shutdown {
				return
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}

		r, err := flowrecord.GetFlowRecord(record)
		if err != nil {
			klog.ErrorS(err, "Error when getting flow record for FlowLogger")
		} else {
			if !e.applyFilters(r) {
				klog.V(5).InfoS("Ignoring record in FlowLogger because filters do not match")
			} else if err := e.flowLogger.WriteRecord(r, *e.config.PrettyPrint); err != nil {
				klog.ErrorS(err, "Error when writing record to FlowLogger")
			}
		}

		if shutdown || ctx.Err() != nil {
			return
		}
	}
}
