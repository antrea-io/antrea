# Antrea Layer 7 NetworkPolicy

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [HTTP](#http)
    - [More examples](#more-examples)
  - [TLS](#tls)
    - [More examples](#more-examples-1)
  - [Logs](#logs)
- [Limitations](#limitations)
<!-- /toc -->

## Introduction

NetworkPolicy was initially used to restrict network access at layer 3 (Network) and 4 (Transport) in the OSI model,
based on IP address, transport protocol, and port. Securing applications at IP and port level provides limited security
capabilities, as the service an application provides is either entirely exposed to a client or not accessible by that
client at all. Starting with v1.10, Antrea introduces support for layer 7 NetworkPolicy, an application-aware policy
which provides fine-grained control over the network traffic beyond IP, transport protocol, and port. It enables users
to protect their applications by specifying how they are allowed to communicate with others, taking into account
application context. For example, you can enforce policies to:

- Grant access of privileged URLs to specific clients while make other URLs publicly accessible.
- Prevent applications from accessing unauthorized domains.
- Block network traffic using an unauthorized application protocol regardless of port used.

This guide demonstrates how to configure layer 7 NetworkPolicy.

## Prerequisites

Layer 7 NetworkPolicy was introduced in v1.10 as an alpha feature and is disabled by default. A feature gate,
`L7NetworkPolicy`, must be enabled in antrea-controller.conf and antrea-agent.conf in the `antrea-config` ConfigMap.
Additionally, due to the constraint of the application detection engine, TX checksum offloading must be disabled via the
`disableTXChecksumOffload` option in antrea-agent.conf for the feature to work. An example configuration is as below:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    disableTXChecksumOffload: true
    featureGates:
      L7NetworkPolicy: true
  antrea-controller.conf: |
    featureGates:
      L7NetworkPolicy: true
```

Alternatively, you can use the following helm installation command to configure the above options:

```bash
helm install antrea antrea/antrea --namespace kube-system --set featureGates.L7NetworkPolicy=true,disableTXChecksumOffload=true
```

## Usage

There isn't a separate resource type for layer 7 NetworkPolicy. It is one kind of Antrea-native policies, which has the
`l7Protocols` field specified in the rules. Like layer 3 and layer 4 policies, the `l7Protocols` field can be specified
for ingress and egress rules in Antrea ClusterNetworkPolicy and Antrea NetworkPolicy. It can be used with the `from` or
`to` field to select the network peer, and the `ports` to select the transport protocol and/or port for which the layer
7 rule applies to. The `action` of a layer 7 rule can only be `Allow`.

**Note**: Any traffic matching the layer 3/4 criteria (specified by `from`, `to`, and `port`) of a layer 7 rule will be
forwarded to an application-aware engine for protocol detection and rule enforcement, and the traffic will be allowed if
the layer 7 criteria is also matched, otherwise it will be dropped. Therefore, any rules after a layer 7 rule will not
be enforced for the traffic that match the layer 7 rule's layer 3/4 criteria.

As of now, the only supported layer 7 protocol is HTTP. Support for more protocols may be added in the future and we
welcome feature requests for protocols that you are interested in.

### HTTP

An example layer 7 NetworkPolicy for the HTTP protocol is like below:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: NetworkPolicy
metadata:
  name: ingress-allow-http-request-to-api-v2
spec:
  priority: 5
  tier: application
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - name: allow-http   # Allow inbound HTTP GET requests to "/api/v2" from Pods with label "app=client".
      action: Allow      # All other traffic from these Pods will be automatically dropped, and subsequent rules will not be considered.
      from:
        - podSelector:
            matchLabels:
              app: client
      l7Protocols:
        - http:
            path: "/api/v2/*"
            host: "foo.bar.com"
            method: "GET"
    - name: drop-other   # Drop all other inbound traffic (i.e., from Pods without label "app=client" or from external clients).
      action: Drop
```

**path**: The `path` field represents the URI path to match. Both exact matches and wildcards are supported, e.g.
`/api/v2/*`, `*/v2/*`, `/index.html`. If not set, the rule matches all URI paths.

**host**: The `host` field represents the hostname present in the URI or the HTTP Host header to match. It does not
contain the port associated with the host. Both exact matches and wildcards are supported, e.g. `*.foo.com`, `*.foo.*`,
`foo.bar.com`. If not set, the rule matches all hostnames.

**method**: The `method` field represents the HTTP method to match. It could be GET, POST, PUT, HEAD, DELETE, TRACE,
OPTIONS, CONNECT and PATCH. If not set, the rule matches all methods.

#### More examples

The following NetworkPolicy grants access of privileged URLs to specific clients while making other URLs publicly
accessible:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: NetworkPolicy
metadata:
  name: allow-privileged-url-to-admin-role
spec:
  priority: 5
  tier: securityops
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - name: for-admin    # Allow inbound HTTP GET requests to "/admin" and "/public" from Pods with label "role=admin".
      action: Allow
      from:
        - podSelector:
            matchLabels:
              role: admin
      l7Protocols:
        - http:
            path: "/admin/*"
        - http:
            path: "/public/*"
    - name: for-public   # Allow inbound HTTP GET requests to "/public" from everyone.
      action: Allow      # All other inbound traffic will be automatically dropped.
      l7Protocols:
        - http:
            path: "/public/*"
```

The following NetworkPolicy prevents applications from accessing unauthorized domains:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: allow-web-access-to-internal-domain
spec:
  priority: 5
  tier: securityops
  appliedTo:
    - podSelector:
        matchLabels:
          egress-restriction: internal-domain-only
  egress:
    - name: allow-dns          # Allow outbound DNS requests.
      action: Allow
      ports:
        - protocol: TCP
          port: 53
        - protocol: UDP
          port: 53
    - name: allow-http-only    # Allow outbound HTTP requests towards "*.bar.com". 
      action: Allow            # As the rule's "to" and "ports" are empty, which means it selects traffic to any network
      l7Protocols:             # peer's any port using any transport protocol, all outbound HTTP requests towards other
        - http:                # domains and non-HTTP requests will be automatically dropped, and subsequent rules will
            host: "*.bar.com"  # not be considered.
```

The following NetworkPolicy blocks network traffic using an unauthorized application protocol regardless of the port used.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: NetworkPolicy
metadata:
  name: allow-http-only
spec:
  priority: 5
  tier: application
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - name: http-only    # Allow inbound HTTP requests only.
      action: Allow      # As the rule's "from" and "ports" are empty, which means it selects traffic from any network
      l7Protocols:       # peer to any port of the Pods this policy applies to, all inbound non-HTTP requests will be
        - http: {}       # automatically dropped, and subsequent rules will not be considered.
```

### TLS

An example layer 7 NetworkPolicy for the TLS protocol is like below:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: NetworkPolicy
metadata:
  name: ingress-allow-tls-handshake
spec:
  priority: 5
  tier: application
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - name: allow-tls    # Allow inbound TLS/SSL handshake packets to server name "foo.bar.com" from Pods with label "app=client".
      action: Allow      # All other traffic from these Pods will be automatically dropped, and subsequent rules will not be considered.
      from:
        - podSelector:
            matchLabels:
              app: client
      l7Protocols:
        - tls:
            sni: "foo.bar.com"
    - name: drop-other   # Drop all other inbound traffic (i.e., from Pods without label "app=client" or from external clients).
      action: Drop
```

**sni**: The `sni` field matches the TLS/SSL Server Name Indication (SNI) field in the TLS/SSL handshake process. Both
exact matches and wildcards are supported, e.g. `*.foo.com`, `*.foo.*`, `foo.bar.com`. If not set, the rule matches all names.

#### More examples

The following NetworkPolicy prevents applications from accessing unauthorized SSL/TLS server names:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: allow-tls-handshake-to-internal
spec:
  priority: 5
  tier: securityops
  appliedTo:
    - podSelector:
        matchLabels:
          egress-restriction: internal-tls-only
  egress:
    - name: allow-dns          # Allow outbound DNS requests.
      action: Allow
      ports:
        - protocol: TCP
          port: 53
        - protocol: UDP
          port: 53
    - name: allow-tls-only      # Allow outbound SSL/TLS handshake packets towards "*.bar.com". 
      action: Allow             # As the rule's "to" and "ports" are empty, which means it selects traffic to any network
      l7Protocols:              # peer's any port of any transport protocol, all outbound SSL/TLS handshake packets towards
        - tls:                  # other server names and non-SSL/non-TLS handshake packets will be automatically dropped, 
            sni: "*.bar.com"    # and subsequent rules will not be considered.
```

The following NetworkPolicy blocks network traffic using an unauthorized application protocol regardless of the port used.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: NetworkPolicy
metadata:
  name: allow-tls-only
spec:
  priority: 5
  tier: application
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - name: tls-only     # Allow inbound SSL/TLS handshake packets only.
      action: Allow      # As the rule's "from" and "ports" are empty, which means it selects traffic from any network
      l7Protocols:       # peer to any port of the Pods this policy applies to, all inbound non-SSL/non-TLS handshake 
        - tls: {}        # packets will be automatically dropped, and subsequent rules will not be considered.
```

### Logs

Layer 7 traffic that matches the NetworkPolicy will be logged in an event
triggered log file (`/var/log/antrea/networkpolicy/l7engine/eve-YEAR-MONTH-DAY.json`).
Logs are categorized by **event_type**. The event type for allowed traffic is `http`,
for dropped traffic it is `alert`. If `enableLogging` is set for the rule, dropped
packets that match the rule will also be logged in addition to the event with
event type `packet`. Below are examples for allow, drop, packet scenarios.

Allow ingress from client (10.10.1.8) to web (10.10.1.7/public/*)

```json
{
  "timestamp": "2024-02-22T21:26:07.074791+0000",
  "flow_id": 757085628206447,
  "in_iface": "antrea-l7-tap0",
  "event_type": "http",
  "vlan": [1],
  "src_ip": "10.10.1.8",
  "src_port": 44132,
  "dest_ip": "10.10.1.7",
  "dest_port": 80,
  "proto": "TCP",
  "tx_id": 0,
  "http": {
      "hostname": "10.10.1.7",
      "url": "/public/main.html",
      "http_user_agent": "Wget/1.21.1",
      "http_content_type": "text/html",
      "http_method": "GET",
      "protocol": "HTTP/1.1",
      "status": 404,
      "length": 153
  }
}
```

Deny ingress from client (10.10.1.5) to web (10.10.1.4/admin)

```json
{
  "timestamp": "2023-03-09T20:00:28.210821+0000",
  "flow_id": 627175734391745,
  "in_iface": "antrea-l7-tap0",
  "event_type": "alert",
  "vlan": [
    1
  ],
  "src_ip": "10.10.1.5",
  "src_port": 43352,
  "dest_ip": "10.10.1.4",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 1,
    "rev": 0,
    "signature": "Reject by AntreaClusterNetworkPolicy:test-l7-ingress",
    "category": "",
    "severity": 3,
    "tenant_id": 1
  },
  "http": {
    "hostname": "10.10.1.4",
    "url": "/admin",
    "http_user_agent": "curl/7.74.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 284,
    "bytes_toclient": 74,
    "start": "2023-03-09T20:00:28.209857+0000"
  }
}
```

Additional packet log when `enableLogging` is set

```json
{
  "timestamp": "2023-03-09T20:00:28.225016+0000",
  "flow_id": 627175734391745,
  "in_iface": "antrea-l7-tap0",
  "event_type": "packet",
  "vlan": [
    1
  ],
  "src_ip": "10.10.1.4",
  "src_port": 80,
  "dest_ip": "10.10.1.5",
  "dest_port": 43352,
  "proto": "TCP",
  "packet": "/lhtPRglzmQvxnJoCABFAAAoUGYAAEAGFE4KCgEECgoBBQBQqVhIGzbi/odenlAUAfsR7QAA",
  "packet_info": {
    "linktype": 1
  }
}
```

## Limitations

This feature is currently only supported for Nodes running Linux.
