package metrics

import (
	"sync"

	kmetrics "k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog"
)

const (
	metricNSAntrea = "antrea"
	subsystemProxy = "proxy"
)

var (
	once sync.Once

	SyncProxyDuration = kmetrics.NewHistogram(
		&kmetrics.HistogramOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v4"},
			Name:        "sync_proxy_rules_duration_seconds",
			Help:        "SyncProxyRules duration of AntreaProxy in seconds",
		},
	)
	ServicesInstalledTotal = kmetrics.NewGauge(
		&kmetrics.GaugeOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v4"},
			Name:        "total_services_installed",
			Help:        "The number of Services installed by AntreaProxy",
		},
	)
	EndpointsInstalledTotal = kmetrics.NewGauge(
		&kmetrics.GaugeOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v4"},
			Name:        "total_endpoints_installed",
			Help:        "The number of Endpoints installed by AntreaProxy",
		},
	)
	ServicesUpdatesTotal = kmetrics.NewCounter(
		&kmetrics.CounterOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v4"},
			Name:        "total_services_updates",
			Help:        "The cumulative number of Service updates received by AntreaProxy",
		},
	)
	EndpointsUpdatesTotal = kmetrics.NewCounter(
		&kmetrics.CounterOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v4"},
			Name:        "total_endpoints_updates",
			Help:        "The cumulative number of Endpoint updates received by AntreaProxy",
		},
	)

	SyncProxyDurationV6 = kmetrics.NewHistogram(
		&kmetrics.HistogramOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v6"},
			Name:        "sync_proxy_rules_duration_seconds",
			Help:        "SyncProxyRules duration of AntreaProxy in seconds",
		},
	)
	ServicesInstalledTotalV6 = kmetrics.NewGauge(
		&kmetrics.GaugeOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v6"},
			Name:        "total_services_installed",
			Help:        "The number of Services installed by AntreaProxy",
		},
	)
	EndpointsInstalledTotalV6 = kmetrics.NewGauge(
		&kmetrics.GaugeOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v6"},
			Name:        "total_endpoints_installed",
			Help:        "The number of Endpoints installed by AntreaProxy",
		},
	)
	ServicesUpdatesTotalV6 = kmetrics.NewCounter(
		&kmetrics.CounterOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v6"},
			Name:        "total_services_updates",
			Help:        "The cumulative number of Service updates received by AntreaProxy",
		},
	)
	EndpointsUpdatesTotalV6 = kmetrics.NewCounter(
		&kmetrics.CounterOpts{
			Namespace:   metricNSAntrea,
			Subsystem:   subsystemProxy,
			ConstLabels: map[string]string{"ip_family": "v6"},
			Name:        "total_endpoints_updates",
			Help:        "The cumulative number of Endpoint updates received by AntreaProxy",
		},
	)
)

func Register() {
	once.Do(func() {
		klog.Infof("Registering Antrea Proxy prometheus metrics")
		legacyregistry.MustRegister(
			SyncProxyDuration,
			ServicesInstalledTotal,
			EndpointsInstalledTotal,
			ServicesUpdatesTotal,
			EndpointsUpdatesTotal,
			SyncProxyDurationV6,
			ServicesInstalledTotalV6,
			EndpointsInstalledTotalV6,
			ServicesUpdatesTotalV6,
			EndpointsUpdatesTotalV6,
		)
	})
}
