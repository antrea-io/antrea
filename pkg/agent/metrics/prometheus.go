// Copyright 2019 Antrea Authors
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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"k8s.io/klog"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

type OVSStatManager struct {
	ofClient openflow.Client
	OVSBridge    string
	OVSTableDesc *prometheus.Desc
}

func (c *OVSStatManager) OVSGetStatistics() (
	ovsFlowsByTable map[string]float64,
) {
	ovsFlowsByTable = make(map[string]float64)
	flowTableStatus :=c.ofClient.GetFlowTableStatus()
	for _, tableStatus := range flowTableStatus {
		ovsFlowsByTable[strconv.Itoa(int(tableStatus.ID))] = float64(tableStatus.FlowCount)
	}
	return
}

func (c *OVSStatManager) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.OVSTableDesc
}

func (c *OVSStatManager) Collect(ch chan<- prometheus.Metric) {
	ovsFlowsByTable := c.OVSGetStatistics()
	for tableId, tableFlowCount := range ovsFlowsByTable {
		ch <- prometheus.MustNewConstMetric(
			c.OVSTableDesc,
			prometheus.GaugeValue,
			tableFlowCount,
			tableId,
		)
	}
}

func NewOVSStatManager(ovsBridge string, ofClient openflow.Client) *OVSStatManager {
	return &OVSStatManager{
		ofClient:  ofClient,
		OVSBridge: ovsBridge,
		OVSTableDesc: prometheus.NewDesc(
			"antrea_ovs_flow_table",
			"OVS flow table flow count.",
			[]string{"table_id"},
			prometheus.Labels{"bridge": ovsBridge},
		),
	}
}

func StartListener(
	prometheusHost string,
	prometheusPort int,
	ovsBridge string,
	ifaceStore interfacestore.InterfaceStore,
	ofClient openflow.Client) {
	hostname, err := os.Hostname()
	if err != nil {
		klog.Error("Failed to retrieve agent node name, %v", err)
	}
	klog.Info("Binding antrea_local_pod_count")
	if err := prometheus.Register(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name:      "antrea_local_pod_count",
			Help:      "Number of pods on local node.",
		},
		func() float64 { return float64(ifaceStore.GetContainerInterfaceNum()) },
	)); err == nil {
		klog.Error("Failed to register local_pod_count with Prometheus")
	}

	gaugeHost := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "antrea_agent_host",
		Help:        "Antrea agent hostname (as a label), typically used in grouping/aggregating stats; " +
			"the label defaults to the hostname of the host but can be overridden by configuration. " +
			"The value of the gauge is always set to 1.",
		ConstLabels: prometheus.Labels{"host": hostname},
	})
	gaugeHost.Set(1)
	prometheus.MustRegister(gaugeHost)
	http.Handle("/metrics", promhttp.Handler())

	ovsStats := NewOVSStatManager(ovsBridge, ofClient)
	prometheus.MustRegister(ovsStats)

	err = http.ListenAndServe(net.JoinHostPort(prometheusHost, strconv.Itoa(prometheusPort)), nil)
	if err != nil {
		klog.Error("Failed to initialize Prometheus metrics server %v", err)
	}
}
