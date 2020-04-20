package metrics

import (
	"reflect"
	"testing"
	"time"

	mock "github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	openflowtest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	"github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	ovsBridge = "br-int"
)

func TestNewOVSStatManager(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	result := NewOVSStatManager(ovsBridge, ofClient)
	assert.Equal(t, result.ofClient, ofClient, "ofClient should be equal")
	assert.Equal(t, result.OVSBridge, ovsBridge, "OVSBridge should be equal")
	assert.NotEqual(t, result.OVSTableDesc, nil, "OVSTableDesc should be initialized")
}

func TestOVSStatManagerGetOVSStatistics(t *testing.T) {
	flowTable := []openflow.TableStatus{
		{0, 5, time.Now()},
		{40, 2, time.Now()},
	}
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	ofClient.EXPECT().GetFlowTableStatus().Return(flowTable)
	ovsStatManager := NewOVSStatManager(ovsBridge, ofClient)
	expected := map[string]float64{"0": 5, "40": 2}
	if !reflect.DeepEqual(expected, ovsStatManager.GetOVSStatistics()) {
		t.Error("GetOVSStatistics did not work correctly")
	}
}

func TestOVSStatManagerCollect(t *testing.T) {
	flowTable := []openflow.TableStatus{
		{0, 5, time.Now()},
	}
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	ofClient.EXPECT().GetFlowTableStatus().Return(flowTable)
	ovsStatManager := NewOVSStatManager(ovsBridge, ofClient)
	out := make(chan prometheus.Metric)
	go ovsStatManager.Collect(out)
	desc := prometheus.NewDesc(
		"antrea_agent_ovs_flow_table",
		"OVS flow table flow count.",
		[]string{"table_id"},
		prometheus.Labels{"bridge": ovsBridge},
	)
	expected := prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 5, "0")
	assert.Equal(t, <-out, expected, "Collect did not push the correct value")
}

func TestOVSStatManagerDescribe(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	ovsStatManager := NewOVSStatManager(ovsBridge, ofClient)
	expected := prometheus.NewDesc(
		"antrea_agent_ovs_flow_table",
		"OVS flow table flow count.",
		[]string{"table_id"},
		prometheus.Labels{"bridge": ovsBridge},
	)
	out := make(chan *prometheus.Desc)
	go ovsStatManager.Describe(out)
	assert.Equal(t, <-out, expected, "Describe did not assign the right value")
}

func TestInitializePrometheusMetrics(t *testing.T) {
	controller := mock.NewController(t)
	defer controller.Finish()
	ofClient := openflowtest.NewMockClient(controller)
	go InitializePrometheusMetrics(
		false,
		false,
		ovsBridge,
		interfacestore.NewInterfaceStore(),
		ofClient)
	time.Sleep(time.Second)

	// test prometheus register by duplicating register: if error -> item has already been registered
	gauge := prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "antrea_agent_local_pod_count",
			Help: "Testing",
		}, func() float64 { return 0 })
	gaugeHost := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "antrea_agent_host",
			Help: "Testing",
		})
	ovsStats := NewOVSStatManager("br-int", ofClient)
	registerPodCountError := prometheus.Register(gauge)
	if registerPodCountError == nil {
		t.Error("antrea_agent_local_pod_count was not registered")
	}
	registerGaugeHostError := prometheus.Register(gaugeHost)
	if registerGaugeHostError == nil {
		t.Error("antrea_agent_host was not registered")
	}
	registerOVSStatsError := prometheus.Register(ovsStats)
	if registerOVSStatsError == nil {
		t.Error("ovs_stats was not registered")
	}
	registerGoError := prometheus.Register(prometheus.NewGoCollector())
	if registerGoError != nil {
		t.Error("Go metrics was not unregistered when enablePrometheusGoMetrics is false")
	}
	registerProcessError := prometheus.Register(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	if registerProcessError != nil {
		t.Error("Process metrics was not unregistered when enablePrometheusProcessMetrics is false")
	}
}
