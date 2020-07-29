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
[Grafana](https://grafana.com/) or [Elastic Stack](##Visibility-with-Elastic-Stack).
 
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

## Visibility with Elastic Stack
[Elastic Stack](https://www.elastic.co) is a group of open source products to
help collect, store, search, analyze and visualize data in real time. We will
use Elasticsearch, Kibana and Metricbeat to provide metrics visibility.

[Metricbeat](https://www.elastic.co/beats/metricbeat) works as a metrics shipper from Prometheus to Elastic Stack.
[Elasticsearch](https://www.elastic.co/elasticsearch/) is responsible for storing collected metrics and indexing.
[Kibana](https://www.elastic.co/kibana/) is mainly for data visualization and exploration.

### Deployment Steps
To create all the necessary resources in the `monitoring` namespace
and get everything up-and-running, run:
```shell
kubectl create namespace monitoring
kubectl apply -f build/yamls/antrea-visualization.yml -n monitoring
kubectl apply -f build/yamls/metrics-visualization/flow-collector.yml -n monitoring
```
Kibana dashboard is exposed as a Nodeport, which can be accessed via
`http://[NodeIP]: 30007`

To import the pre-built and recommended dashboard into Kibana, go to
**Management -> Saved Objects** and
import `build/yamls/flow/kibana-prometheus.ndjson`

### Pre-built Dashboards
The following dashboards are provided for visualizing metrics collected from Prometheus.

#### Metrics 
<img src="/docs/assets/metrics-visualization-1.png" width="900" alt="Metrics Dashboard"> 

#### Network Policy 
<img src="/docs/assets/metrics-visualization-2.png" width="900" alt="Network Policy Dashboard"> 
<img src="/docs/assets/metrics-visualization-3.png" width="900" alt="Network Policy Dashboard"> 