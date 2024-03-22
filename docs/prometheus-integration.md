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

### Prometheus version

Prometheus integration with Antrea is validated as part of CI using Prometheus v2.46.0.

### Prometheus RBAC

Prometheus requires access to Kubernetes API resources for the service discovery
capability. Reading metrics also requires access to the "/metrics" API
endpoints.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
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
apiVersion: rbac.authorization.k8s.io/v1
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
collection from Antrea components. Antrea Agent metrics endpoint is exposed through
Antrea apiserver on `apiport` config parameter given in `antrea-agent.conf` (default
value is 10350). Antrea Controller metrics endpoint is exposed through Antrea apiserver
on `apiport` config parameter given in `antrea-controller.conf` (default value is 10349).

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
- source_labels: [__meta_kubernetes_pod_node_name, __meta_kubernetes_pod_name]
  target_label: instance
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
- source_labels: [__meta_kubernetes_pod_node_name, __meta_kubernetes_pod_name]
  target_label: instance
```

For further reference see the enclosed
[configuration file](../build/yamls/antrea-prometheus.yml).

The configuration file above can be used to deploy Prometheus Server with
scraping configuration for Antrea services.
To deploy this configuration use
`kubectl apply -f build/yamls/antrea-prometheus.yml`

## Antrea Prometheus Metrics

Antrea Controller and Agents expose various metrics, some of which are provided
by the Antrea components and others which are provided by 3rd party components
used by the Antrea components.

Below is a list of metrics, provided by the components and by 3rd parties.

### Antrea Metrics

#### Antrea Agent Metrics

- **antrea_agent_conntrack_antrea_connection_count:** Number of connections
in the Antrea ZoneID of the conntrack table. This metric gets updated at
an interval specified by flowPollInterval, a configuration parameter for
the Agent.
- **antrea_agent_conntrack_max_connection_count:** Size of the conntrack
table. This metric gets updated at an interval specified by flowPollInterval,
a configuration parameter for the Agent.
- **antrea_agent_conntrack_total_connection_count:** Number of connections
in the conntrack table. This metric gets updated at an interval specified
by flowPollInterval, a configuration parameter for the Agent.
- **antrea_agent_denied_connection_count:** Number of denied connections
detected by Flow Exporter deny connections tracking. This metric gets updated
when a flow is rejected/dropped by network policy.
- **antrea_agent_egress_networkpolicy_rule_count:** Number of egress
NetworkPolicy rules on local Node which are managed by the Antrea Agent.
- **antrea_agent_flow_collector_reconnection_count:** Number of re-connections
between Flow Exporter and flow collector. This metric gets updated whenever
the connection is re-established between the Flow Exporter and the flow
collector (e.g. the Flow Aggregator).
- **antrea_agent_ingress_networkpolicy_rule_count:** Number of ingress
NetworkPolicy rules on local Node which are managed by the Antrea Agent.
- **antrea_agent_local_pod_count:** Number of Pods on local Node which are
managed by the Antrea Agent.
- **antrea_agent_networkpolicy_count:** Number of NetworkPolicies on local
Node which are managed by the Antrea Agent.
- **antrea_agent_ovs_flow_count:** Flow count for each OVS flow table. The
TableID and TableName are used as labels.
- **antrea_agent_ovs_flow_ops_count:** Number of OVS flow operations,
partitioned by operation type (add, modify and delete).
- **antrea_agent_ovs_flow_ops_error_count:** Number of OVS flow operation
errors, partitioned by operation type (add, modify and delete).
- **antrea_agent_ovs_flow_ops_latency_milliseconds:** The latency of OVS
flow operations, partitioned by operation type (add, modify and delete).
- **antrea_agent_ovs_meter_packet_dropped_count:** Number of packets dropped by
OVS meter. The value is greater than 0 when the packets exceed the rate-limit.
- **antrea_agent_ovs_total_flow_count:** Total flow count of all OVS flow
tables.

#### Antrea Controller Metrics

- **antrea_controller_acnp_status_updates:** The total number of actual
status updates performed for Antrea ClusterNetworkPolicy Custom Resources
- **antrea_controller_address_group_processed:** The total number of
address-group processed
- **antrea_controller_address_group_sync_duration_milliseconds:** The duration
of syncing address-group
- **antrea_controller_annp_status_updates:** The total number of actual
status updates performed for Antrea NetworkPolicy Custom Resources
- **antrea_controller_applied_to_group_processed:** The total number of
applied-to-group processed
- **antrea_controller_applied_to_group_sync_duration_milliseconds:** The
duration of syncing applied-to-group
- **antrea_controller_length_address_group_queue:** The length of
AddressGroupQueue
- **antrea_controller_length_applied_to_group_queue:** The length of
AppliedToGroupQueue
- **antrea_controller_length_network_policy_queue:** The length of
InternalNetworkPolicyQueue
- **antrea_controller_network_policy_processed:** The total number of
internal-networkpolicy processed
- **antrea_controller_network_policy_sync_duration_milliseconds:** The
duration of syncing internal-networkpolicy

#### Antrea Proxy Metrics

- **antrea_proxy_sync_proxy_rules_duration_seconds:** SyncProxyRules duration
of AntreaProxy in seconds
- **antrea_proxy_total_endpoints_installed:** The number of Endpoints
installed by AntreaProxy
- **antrea_proxy_total_endpoints_updates:** The cumulative number of Endpoint
updates received by AntreaProxy
- **antrea_proxy_total_services_installed:** The number of Services installed
by AntreaProxy
- **antrea_proxy_total_services_updates:** The cumulative number of Service
updates received by AntreaProxy

### Common Metrics Provided by Infrastructure

#### Aggregator Metrics

- **aggregator_discovery_aggregation_count_total:** Counter of number of
times discovery was aggregated

#### Apiserver Metrics

- **apiserver_audit_event_total:** Counter of audit events generated and
sent to the audit backend.
- **apiserver_audit_requests_rejected_total:** Counter of apiserver requests
rejected due to an error in audit logging backend.
- **apiserver_client_certificate_expiration_seconds:** Distribution of the
remaining lifetime on the certificate used to authenticate a request.
- **apiserver_current_inflight_requests:** Maximal number of currently used
inflight request limit of this apiserver per request kind in last second.
- **apiserver_delegated_authn_request_duration_seconds:** Request latency
in seconds. Broken down by status code.
- **apiserver_delegated_authn_request_total:** Number of HTTP requests
partitioned by status code.
- **apiserver_delegated_authz_request_duration_seconds:** Request latency
in seconds. Broken down by status code.
- **apiserver_delegated_authz_request_total:** Number of HTTP requests
partitioned by status code.
- **apiserver_envelope_encryption_dek_cache_fill_percent:** Percent of the
cache slots currently occupied by cached DEKs.
- **apiserver_flowcontrol_read_vs_write_current_requests:** EXPERIMENTAL:
Observations, at the end of every nanosecond, of the number of requests
(as a fraction of the relevant limit) waiting or in regular stage of execution
- **apiserver_flowcontrol_seat_fair_frac:** Fair fraction of server's
concurrency to allocate to each priority level that can use it
- **apiserver_longrunning_requests:** Gauge of all active long-running
apiserver requests broken out by verb, group, version, resource, scope and
component. Not all requests are tracked this way.
- **apiserver_request_duration_seconds:** Response latency distribution in
seconds for each verb, dry run value, group, version, resource, subresource,
scope and component.
- **apiserver_request_filter_duration_seconds:** Request filter latency
distribution in seconds, for each filter type
- **apiserver_request_sli_duration_seconds:** Response latency distribution
(not counting webhook duration and priority & fairness queue wait times)
in seconds for each verb, group, version, resource, subresource, scope
and component.
- **apiserver_request_slo_duration_seconds:** Response latency distribution
(not counting webhook duration and priority & fairness queue wait times)
in seconds for each verb, group, version, resource, subresource, scope
and component.
- **apiserver_request_total:** Counter of apiserver requests broken out
for each verb, dry run value, group, version, resource, scope, component,
and HTTP response code.
- **apiserver_response_sizes:** Response size distribution in bytes for each
group, version, verb, resource, subresource, scope and component.
- **apiserver_storage_data_key_generation_duration_seconds:** Latencies in
seconds of data encryption key(DEK) generation operations.
- **apiserver_storage_data_key_generation_failures_total:** Total number of
failed data encryption key(DEK) generation operations.
- **apiserver_storage_envelope_transformation_cache_misses_total:** Total
number of cache misses while accessing key decryption key(KEK).
- **apiserver_tls_handshake_errors_total:** Number of requests dropped with
'TLS handshake error from' error
- **apiserver_watch_events_sizes:** Watch event size distribution in bytes
- **apiserver_watch_events_total:** Number of events sent in watch clients
- **apiserver_webhooks_x509_insecure_sha1_total:** Counts the number of
requests to servers with insecure SHA1 signatures in their serving certificate
OR the number of connection failures due to the insecure SHA1 signatures
(either/or, based on the runtime environment)
- **apiserver_webhooks_x509_missing_san_total:** Counts the number of requests
to servers missing SAN extension in their serving certificate OR the number
of connection failures due to the lack of x509 certificate SAN extension
missing (either/or, based on the runtime environment)

#### Authenticated Metrics

- **authenticated_user_requests:** Counter of authenticated requests broken
out by username.

#### Authentication Metrics

- **authentication_attempts:** Counter of authenticated attempts.
- **authentication_duration_seconds:** Authentication duration in seconds
broken out by result.
- **authentication_token_cache_active_fetch_count:**
- **authentication_token_cache_fetch_total:**
- **authentication_token_cache_request_duration_seconds:**
- **authentication_token_cache_request_total:**

#### Authorization Metrics

- **authorization_attempts_total:** Counter of authorization attempts broken
down by result. It can be either 'allowed', 'denied', 'no-opinion' or 'error'.
- **authorization_duration_seconds:** Authorization duration in seconds
broken out by result.

#### Cardinality Metrics

- **cardinality_enforcement_unexpected_categorizations_total:** The count
of unexpected categorizations during cardinality enforcement.

#### Disabled Metrics

- **disabled_metrics_total:** The count of disabled metrics.

#### Field Metrics

- **field_validation_request_duration_seconds:** Response latency distribution
in seconds for each field validation value

#### Go Metrics

- **go_cgo_go_to_c_calls_calls_total:** Count of calls made from Go to C by
the current process.
- **go_cpu_classes_gc_mark_assist_cpu_seconds_total:** Estimated total CPU
time goroutines spent performing GC tasks to assist the GC and prevent it
from falling behind the application. This metric is an overestimate, and
not directly comparable to system CPU time measurements. Compare only with
other /cpu/classes metrics.
- **go_cpu_classes_gc_mark_dedicated_cpu_seconds_total:** Estimated total
CPU time spent performing GC tasks on processors (as defined by GOMAXPROCS)
dedicated to those tasks. This metric is an overestimate, and not directly
comparable to system CPU time measurements. Compare only with other
/cpu/classes metrics.
- **go_cpu_classes_gc_mark_idle_cpu_seconds_total:** Estimated total CPU
time spent performing GC tasks on spare CPU resources that the Go scheduler
could not otherwise find a use for. This should be subtracted from the
total GC CPU time to obtain a measure of compulsory GC CPU time. This
metric is an overestimate, and not directly comparable to system CPU time
measurements. Compare only with other /cpu/classes metrics.
- **go_cpu_classes_gc_pause_cpu_seconds_total:** Estimated total CPU time spent
with the application paused by the GC. Even if only one thread is running
during the pause, this is computed as GOMAXPROCS times the pause latency
because nothing else can be executing. This is the exact sum of samples in
/gc/pause:seconds if each sample is multiplied by GOMAXPROCS at the time
it is taken. This metric is an overestimate, and not directly comparable to
system CPU time measurements. Compare only with other /cpu/classes metrics.
- **go_cpu_classes_gc_total_cpu_seconds_total:** Estimated total CPU
time spent performing GC tasks. This metric is an overestimate, and not
directly comparable to system CPU time measurements. Compare only with other
/cpu/classes metrics. Sum of all metrics in /cpu/classes/gc.
- **go_cpu_classes_idle_cpu_seconds_total:** Estimated total available CPU
time not spent executing any Go or Go runtime code. In other words, the part of
/cpu/classes/total:cpu-seconds that was unused. This metric is an overestimate,
and not directly comparable to system CPU time measurements. Compare only
with other /cpu/classes metrics.
- **go_cpu_classes_scavenge_assist_cpu_seconds_total:** Estimated total CPU
time spent returning unused memory to the underlying platform in response
eagerly in response to memory pressure. This metric is an overestimate,
and not directly comparable to system CPU time measurements. Compare only
with other /cpu/classes metrics.
- **go_cpu_classes_scavenge_background_cpu_seconds_total:** Estimated total
CPU time spent performing background tasks to return unused memory to the
underlying platform. This metric is an overestimate, and not directly
comparable to system CPU time measurements. Compare only with other
/cpu/classes metrics.
- **go_cpu_classes_scavenge_total_cpu_seconds_total:** Estimated total
CPU time spent performing tasks that return unused memory to the underlying
platform. This metric is an overestimate, and not directly comparable to system
CPU time measurements. Compare only with other /cpu/classes metrics. Sum of
all metrics in /cpu/classes/scavenge.
- **go_cpu_classes_total_cpu_seconds_total:** Estimated total available CPU
time for user Go code or the Go runtime, as defined by GOMAXPROCS. In other
words, GOMAXPROCS integrated over the wall-clock duration this process has been
executing for. This metric is an overestimate, and not directly comparable to
system CPU time measurements. Compare only with other /cpu/classes metrics. Sum
of all metrics in /cpu/classes.
- **go_cpu_classes_user_cpu_seconds_total:** Estimated total CPU time spent
running user Go code. This may also include some small amount of time spent
in the Go runtime. This metric is an overestimate, and not directly comparable
to system CPU time measurements. Compare only with other /cpu/classes metrics.
- **go_gc_cycles_automatic_gc_cycles_total:** Count of completed GC cycles
generated by the Go runtime.
- **go_gc_cycles_forced_gc_cycles_total:** Count of completed GC cycles
forced by the application.
- **go_gc_cycles_total_gc_cycles_total:** Count of all completed GC cycles.
- **go_gc_duration_seconds:** A summary of the pause duration of garbage
collection cycles.
- **go_gc_gogc_percent:** Heap size target percentage configured by the
user, otherwise 100. This value is set by the GOGC environment variable,
and the runtime/debug.SetGCPercent function.
- **go_gc_gomemlimit_bytes:** Go runtime memory limit configured by the user,
otherwise math.MaxInt64. This value is set by the GOMEMLIMIT environment
variable, and the runtime/debug.SetMemoryLimit function.
- **go_gc_heap_allocs_by_size_bytes:** Distribution of heap allocations
by approximate size. Bucket counts increase monotonically. Note that this
does not include tiny objects as defined by /gc/heap/tiny/allocs:objects,
only tiny blocks.
- **go_gc_heap_allocs_bytes_total:** Cumulative sum of memory allocated to
the heap by the application.
- **go_gc_heap_allocs_objects_total:** Cumulative count of heap allocations
triggered by the application. Note that this does not include tiny objects
as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
- **go_gc_heap_frees_by_size_bytes:** Distribution of freed heap allocations
by approximate size. Bucket counts increase monotonically. Note that this
does not include tiny objects as defined by /gc/heap/tiny/allocs:objects,
only tiny blocks.
- **go_gc_heap_frees_bytes_total:** Cumulative sum of heap memory freed by
the garbage collector.
- **go_gc_heap_frees_objects_total:** Cumulative count of heap allocations
whose storage was freed by the garbage collector. Note that this does
not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only
tiny blocks.
- **go_gc_heap_goal_bytes:** Heap size target for the end of the GC cycle.
- **go_gc_heap_live_bytes:** Heap memory occupied by live objects that were
marked by the previous GC.
- **go_gc_heap_objects_objects:** Number of objects, live or unswept,
occupying heap memory.
- **go_gc_heap_tiny_allocs_objects_total:** Count of small allocations that
are packed together into blocks. These allocations are counted separately
from other allocations because each individual allocation is not tracked
by the runtime, only their block. Each block is already accounted for in
allocs-by-size and frees-by-size.
- **go_gc_limiter_last_enabled_gc_cycle:** GC cycle the last time the GC CPU
limiter was enabled. This metric is useful for diagnosing the root cause
of an out-of-memory error, because the limiter trades memory for CPU time
when the GC's CPU time gets too high. This is most likely to occur with use
of SetMemoryLimit. The first GC cycle is cycle 1, so a value of 0 indicates
that it was never enabled.
- **go_gc_pauses_seconds:** Distribution of individual GC-related
stop-the-world pause latencies. Bucket counts increase monotonically.
- **go_gc_scan_globals_bytes:** The total amount of global variable space
that is scannable.
- **go_gc_scan_heap_bytes:** The total amount of heap space that is scannable.
- **go_gc_scan_stack_bytes:** The number of bytes of stack that were scanned
last GC cycle.
- **go_gc_scan_total_bytes:** The total amount space that is scannable. Sum
of all metrics in /gc/scan.
- **go_gc_stack_starting_size_bytes:** The stack size of new goroutines.
- **go_godebug_non_default_behavior_execerrdot_events_total:** The number of
non-default behaviors executed by the os/exec package due to a non-default
GODEBUG=execerrdot=... setting.
- **go_godebug_non_default_behavior_gocachehash_events_total:** The number
of non-default behaviors executed by the cmd/go package due to a non-default
GODEBUG=gocachehash=... setting.
- **go_godebug_non_default_behavior_gocachetest_events_total:** The number
of non-default behaviors executed by the cmd/go package due to a non-default
GODEBUG=gocachetest=... setting.
- **go_godebug_non_default_behavior_gocacheverify_events_total:** The number
of non-default behaviors executed by the cmd/go package due to a non-default
GODEBUG=gocacheverify=... setting.
- **go_godebug_non_default_behavior_http2client_events_total:** The number of
non-default behaviors executed by the net/http package due to a non-default
GODEBUG=http2client=... setting.
- **go_godebug_non_default_behavior_http2server_events_total:** The number of
non-default behaviors executed by the net/http package due to a non-default
GODEBUG=http2server=... setting.
- **go_godebug_non_default_behavior_installgoroot_events_total:** The number
of non-default behaviors executed by the go/build package due to a non-default
GODEBUG=installgoroot=... setting.
- **go_godebug_non_default_behavior_jstmpllitinterp_events_total:** The
number of non-default behaviors executed by the html/template package due
to a non-default GODEBUG=jstmpllitinterp=... setting.
- **go_godebug_non_default_behavior_multipartmaxheaders_events_total:**
The number of non-default behaviors executed by the mime/multipart package
due to a non-default GODEBUG=multipartmaxheaders=... setting.
- **go_godebug_non_default_behavior_multipartmaxparts_events_total:** The
number of non-default behaviors executed by the mime/multipart package due
to a non-default GODEBUG=multipartmaxparts=... setting.
- **go_godebug_non_default_behavior_multipathtcp_events_total:** The number
of non-default behaviors executed by the net package due to a non-default
GODEBUG=multipathtcp=... setting.
- **go_godebug_non_default_behavior_panicnil_events_total:** The number of
non-default behaviors executed by the runtime package due to a non-default
GODEBUG=panicnil=... setting.
- **go_godebug_non_default_behavior_randautoseed_events_total:** The number of
non-default behaviors executed by the math/rand package due to a non-default
GODEBUG=randautoseed=... setting.
- **go_godebug_non_default_behavior_tarinsecurepath_events_total:** The
number of non-default behaviors executed by the archive/tar package due to
a non-default GODEBUG=tarinsecurepath=... setting.
- **go_godebug_non_default_behavior_tlsmaxrsasize_events_total:** The
number of non-default behaviors executed by the crypto/tls package due to
a non-default GODEBUG=tlsmaxrsasize=... setting.
- **go_godebug_non_default_behavior_x509sha1_events_total:** The number of
non-default behaviors executed by the crypto/x509 package due to a non-default
GODEBUG=x509sha1=... setting.
- **go_godebug_non_default_behavior_x509usefallbackroots_events_total:**
The number of non-default behaviors executed by the crypto/x509 package due
to a non-default GODEBUG=x509usefallbackroots=... setting.
- **go_godebug_non_default_behavior_zipinsecurepath_events_total:** The
number of non-default behaviors executed by the archive/zip package due to
a non-default GODEBUG=zipinsecurepath=... setting.
- **go_goroutines:** Number of goroutines that currently exist.
- **go_info:** Information about the Go environment.
- **go_memory_classes_heap_free_bytes:** Memory that is completely free and
eligible to be returned to the underlying system, but has not been. This
metric is the runtime's estimate of free address space that is backed by
physical memory.
- **go_memory_classes_heap_objects_bytes:** Memory occupied by live objects
and dead objects that have not yet been marked free by the garbage collector.
- **go_memory_classes_heap_released_bytes:** Memory that is completely free
and has been returned to the underlying system. This metric is the runtime's
estimate of free address space that is still mapped into the process, but
is not backed by physical memory.
- **go_memory_classes_heap_stacks_bytes:** Memory allocated from the
heap that is reserved for stack space, whether or not it is currently
in-use. Currently, this represents all stack memory for goroutines. It also
includes all OS thread stacks in non-cgo programs. Note that stacks may be
allocated differently in the future, and this may change.
- **go_memory_classes_heap_unused_bytes:** Memory that is reserved for heap
objects but is not currently used to hold heap objects.
- **go_memory_classes_metadata_mcache_free_bytes:** Memory that is reserved
for runtime mcache structures, but not in-use.
- **go_memory_classes_metadata_mcache_inuse_bytes:** Memory that is occupied
by runtime mcache structures that are currently being used.
- **go_memory_classes_metadata_mspan_free_bytes:** Memory that is reserved
for runtime mspan structures, but not in-use.
- **go_memory_classes_metadata_mspan_inuse_bytes:** Memory that is occupied
by runtime mspan structures that are currently being used.
- **go_memory_classes_metadata_other_bytes:** Memory that is reserved for
or used to hold runtime metadata.
- **go_memory_classes_os_stacks_bytes:** Stack memory allocated by the
underlying operating system. In non-cgo programs this metric is currently
zero. This may change in the future.In cgo programs this metric includes OS
thread stacks allocated directly from the OS. Currently, this only accounts
for one stack in c-shared and c-archive build modes, and other sources of
stacks from the OS are not measured. This too may change in the future.
- **go_memory_classes_other_bytes:** Memory used by execution trace buffers,
structures for debugging the runtime, finalizer and profiler specials,
and more.
- **go_memory_classes_profiling_buckets_bytes:** Memory that is used by the
stack trace hash map used for profiling.
- **go_memory_classes_total_bytes:** All memory mapped by the Go runtime
into the current process as read-write. Note that this does not include
memory mapped by code called via cgo or via the syscall package. Sum of all
metrics in /memory/classes.
- **go_memstats_alloc_bytes:** Number of bytes allocated and still in use.
- **go_memstats_alloc_bytes_total:** Total number of bytes allocated, even
if freed.
- **go_memstats_buck_hash_sys_bytes:** Number of bytes used by the profiling
bucket hash table.
- **go_memstats_frees_total:** Total number of frees.
- **go_memstats_gc_sys_bytes:** Number of bytes used for garbage collection
system metadata.
- **go_memstats_heap_alloc_bytes:** Number of heap bytes allocated and still
in use.
- **go_memstats_heap_idle_bytes:** Number of heap bytes waiting to be used.
- **go_memstats_heap_inuse_bytes:** Number of heap bytes that are in use.
- **go_memstats_heap_objects:** Number of allocated objects.
- **go_memstats_heap_released_bytes:** Number of heap bytes released to OS.
- **go_memstats_heap_sys_bytes:** Number of heap bytes obtained from system.
- **go_memstats_last_gc_time_seconds:** Number of seconds since 1970 of last
garbage collection.
- **go_memstats_lookups_total:** Total number of pointer lookups.
- **go_memstats_mallocs_total:** Total number of mallocs.
- **go_memstats_mcache_inuse_bytes:** Number of bytes in use by mcache
structures.
- **go_memstats_mcache_sys_bytes:** Number of bytes used for mcache structures
obtained from system.
- **go_memstats_mspan_inuse_bytes:** Number of bytes in use by mspan
structures.
- **go_memstats_mspan_sys_bytes:** Number of bytes used for mspan structures
obtained from system.
- **go_memstats_next_gc_bytes:** Number of heap bytes when next garbage
collection will take place.
- **go_memstats_other_sys_bytes:** Number of bytes used for other system
allocations.
- **go_memstats_stack_inuse_bytes:** Number of bytes in use by the stack
allocator.
- **go_memstats_stack_sys_bytes:** Number of bytes obtained from system for
stack allocator.
- **go_memstats_sys_bytes:** Number of bytes obtained from system.
- **go_sched_gomaxprocs_threads:** The current runtime.GOMAXPROCS setting,
or the number of operating system threads that can execute user-level Go
code simultaneously.
- **go_sched_goroutines_goroutines:** Count of live goroutines.
- **go_sched_latencies_seconds:** Distribution of the time goroutines have
spent in the scheduler in a runnable state before actually running. Bucket
counts increase monotonically.
- **go_sync_mutex_wait_total_seconds_total:** Approximate cumulative time
goroutines have spent blocked on a sync.Mutex or sync.RWMutex. This metric
is useful for identifying global changes in lock contention. Collect a
mutex or block profile using the runtime/pprof package for more detailed
contention data.
- **go_threads:** Number of OS threads created.

#### Hidden Metrics

- **hidden_metrics_total:** The count of hidden metrics.

#### Process Metrics

- **process_cpu_seconds_total:** Total user and system CPU time spent
in seconds.
- **process_max_fds:** Maximum number of open file descriptors.
- **process_open_fds:** Number of open file descriptors.
- **process_resident_memory_bytes:** Resident memory size in bytes.
- **process_start_time_seconds:** Start time of the process since unix epoch
in seconds.
- **process_virtual_memory_bytes:** Virtual memory size in bytes.
- **process_virtual_memory_max_bytes:** Maximum amount of virtual memory
available in bytes.

#### Registered Metrics

- **registered_metrics_total:** The count of registered metrics broken by
stability level and deprecation version.

#### Workqueue Metrics

- **workqueue_adds_total:** Total number of adds handled by workqueue
- **workqueue_depth:** Current depth of workqueue
- **workqueue_longest_running_processor_seconds:** How many seconds has the
longest running processor for workqueue been running.
- **workqueue_queue_duration_seconds:** How long in seconds an item stays
in workqueue before being requested.
- **workqueue_retries_total:** Total number of retries handled by workqueue
- **workqueue_unfinished_work_seconds:** How many seconds of work has
done that is in progress and hasn't been observed by work_duration. Large
values indicate stuck threads. One can deduce the number of stuck threads
by observing the rate at which this increases.
- **workqueue_work_duration_seconds:** How long in seconds processing an
item from workqueue takes.
