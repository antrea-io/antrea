# Prometheus Integration

## Purpose
Prometheus server can monitor various metrics and provide an observation of the 
Antrea Controller and Agent components. The doc provides general guidelines to 
the configuration of Prometheus server to operate with the Antrea components.

## About Prometheus
[Prometheus](https://prometheus.io/) is an open source monitoring and alerting 
server. Prometheus is capable of collecting metrics from various Kubernetes 
components, storing and providing alerts.
Prometheus can provide visibility by integrating with other products such as 
[Grafana](https://grafana.com/).
 
One of Prometheus capabilities is self-discovery of Kubernetes services which
expose their metrics. So Prometheus can scrape the metrics of any additional 
components which are added to the cluster without further configuration changes. 
 
## Antrea Configuration
Enable Prometheus metrics listener by setting `enablePrometheusMetrics` 
parameter to true in the Controller and the Agent configurations.
 
## Prometheus Configuration
  
### Prometheus RBAC
Prometheus requires access to Kubernetes API resources for the service discovery
capability. Reading metrics also requires access to the "/metrics" API
endpoints.
```yaml
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: prometheus
rules:
- apiGroups: [""]
  resources:
  - nodes
  - nodes/proxy
  - services
  - endpoints
  - pods
  verbs: ["get", "list", "watch"]
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
```

### Antrea Metrics Listener Access
To scrape the metrics from Antrea Controller and Agent, Prometheus needs the
following permissions
```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: prometheus-antrea
rules:
- nonResourceURLs:
  - /metrics
  verbs:
  - get
```

### Antrea Components Scraping configuration
Add the following jobs to Prometheus scraping configuration to enable metrics
collection from Antrea components

#### Controller Scraping
```yaml
- job_name: 'antrea-controllers'
kubernetes_sd_configs:
- role: endpoints
scheme: https
tls_config:
  ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  insecure_skip_verify: true
bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
relabel_configs:
- source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_pod_container_name]
  action: keep
  regex: kube-system;antrea-controller
```

#### Agent Scraping
```yaml
- job_name: 'antrea-agents'
kubernetes_sd_configs:
- role: pod
scheme: https
tls_config:
  ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  insecure_skip_verify: true
bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
relabel_configs:
- source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_pod_container_name]
  action: keep
  regex: kube-system;antrea-agent
```
For further reference see the enclosed 
[configuration file](/build/yamls/antrea-prometheus.yml).

The configuration file above can be used to deploy Prometheus Server with 
scraping configuration for Antrea services.
To deploy this configuration use
`kubectl apply -f build/yamls/antrea-prometheus.yml`
