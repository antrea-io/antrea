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
	"math"
	"reflect"
	"slices"
	"sync"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/klog/v2"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/flowlogger"
	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
	"antrea.io/antrea/pkg/flowaggregator/options"
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
			return registry.NetworkPolicyRuleActionNoAction
		case flowaggregatorconfig.NetworkPolicyRuleActionAllow:
			return registry.NetworkPolicyRuleActionAllow
		case flowaggregatorconfig.NetworkPolicyRuleActionDrop:
			return registry.NetworkPolicyRuleActionDrop
		case flowaggregatorconfig.NetworkPolicyRuleActionReject:
			return registry.NetworkPolicyRuleActionReject
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

func (e *LogExporter) AddRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	r := flowrecord.GetFlowRecord(record)
	if !e.applyFilters(r) {
		klog.V(5).InfoS("Ignoring record in FlowLogger because filters do not match")
		return nil
	}
	return e.flowLogger.WriteRecord(r, *e.config.PrettyPrint)
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
		// both conditions match
		return true
	}
	return false
}

func (e *LogExporter) Start() {
	e.start()
}

func (e *LogExporter) Stop() {
	e.stop()
}

func (e *LogExporter) start() {
	e.stopCh = make(chan struct{})
	e.flowLogger = flowlogger.NewFlowLogger(
		e.config.Path,
		// these are all valid conversions from int32 to int
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
}

func (e *LogExporter) stop() {
	close(e.stopCh)
	e.wg.Wait()
	e.flowLogger.Close()
	e.flowLogger = nil
}

func (e *LogExporter) UpdateOptions(opt *options.Options) {
	config := opt.Config.FlowLogger
	if reflect.DeepEqual(e.config, config) {
		return
	}
	klog.InfoS("Updating FlowLogger")
	e.stop()
	e.config = config
	klog.InfoS("New FlowLogger configuration", "path", config.Path, "maxSize", config.MaxSize, "maxBackups", config.MaxBackups, "maxAge", config.MaxAge, "compress", *config.Compress, "prettyPrint", *config.PrettyPrint)
	e.buildFilters()
	e.start()
}
