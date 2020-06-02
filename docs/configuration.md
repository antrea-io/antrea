# Configuration

## antrea-agent

### Command line options

```
--config string                    The path to the configuration file
--v Level                          number for the log level verbosity
```

Use `antrea-agent -h` to see complete options.

### Configuration

```yaml
# clientConnection specifies the kubeconfig file and client connection settings for the agent
# to communicate with the apiserver.
#clientConnection:
  # Path of the kubeconfig file that is used to configure access to a K8s cluster.
  # If not specified, InClusterConfig will be used.
  #kubeconfig: <PATH_TO_KUBE_CONF>

# antreaClientConnection specifies the kubeconfig file and client connection settings for the
# agent to communicate with the Antrea Controller apiserver.
#antreaClientConnection:
  # Path of the kubeconfig file that is used to configure access to the Antrea Controller
  # apiserver. If not specified, InClusterConfig will be used.
  #kubeconfig: <PATH_TO_ANTREA_KUBE_CONF>

# Name of the OpenVSwitch bridge antrea-agent will create and use.
# Make sure it doesn't conflict with your existing OpenVSwitch bridges.
#ovsBridge: br-int

# Datapath type to use for the OpenVSwitch bridge created by Antrea. Supported values are:
# - system
# - netdev
# 'system' is the default value and corresponds to the kernel datapath. Use 'netdev' to run
# OVS in userspace mode. Userspace mode requires the tun device driver to be available.
#ovsDatapathType: system

# Name of the gateway interface for the local Pod subnet. antrea-agent will create the interface on the OVS bridge.
# Make sure it doesn't conflict with your existing interfaces.
#hostGateway: gw0

# Encapsulation mode for communication between Pods across Nodes, supported values:
# - vxlan (default)
# - geneve
# - gre
# - stt
#tunnelType: vxlan

# Whether or not to enable IPsec encryption of tunnel traffic. IPsec encryption is only supported
# for the GRE tunnel type.
#enableIPSecTunnel: false

# Default MTU to use for the host gateway interface and the network interface of
# each Pod. If omitted, antrea-agent will default this value to 1450 to accommodate
# for tunnel encapsulate overhead.
#defaultMTU: 1450

# CIDR Range for services in cluster. It's required to support egress network policy, should
# be set to the same value as the one specified by --service-cluster-ip-range for kube-apiserver.
#serviceCIDR: 10.96.0.0/12

# Mount location of the /proc directory. The default is "/host", which is appropriate when
# antrea-agent is run as part of the Antrea DaemonSet (and the host's /proc directory is mounted
# as /host/proc in the antrea-agent container). When running antrea-agent as a process,
# hostProcPathPrefix should be set to "/" in the YAML config.
#hostProcPathPrefix: /host

# The port for the antrea-agent APIServer to serve on.
#apiPort: 10350
```

## antrea-controller

### Command line options

```
--config string                    The path to the configuration file
--v Level                          number for the log level verbosity
```

Use `antrea-controller -h` to see complete options.

### Configuration

```yaml
# clientConnection specifies the kubeconfig file and client connection settings for the 
# controller to communicate with the apiserver.
clientConnection:
  # Path of the kubeconfig file that is used to configure access to a K8s cluster.
  # If not specified, InClusterConfig will be used, which handles API host discovery and authentication automatically.
  #kubeconfig: <PATH_TO_KUBE_CONF>

# The port for the antrea-controller APIServer to serve on.
#apiPort: 10349

# Indicates whether to use auto-generated self-signed TLS certificate.
# If false, A secret named "kube-system/antrea-controller-tls" must be provided with the following keys:
#   ca.crt: <CA certificate>
#   tls.crt: <TLS certificate>
#   tls.key: <TLS private key>
#selfSignedCert: true
```

## CNI configuration

A typical CNI configuration looks like this:

```json
  {
    "cniVersion":"0.3.0",
    "name": "antrea",
    "plugins": [
      {
        "type": "antrea",
        "ipam": {
          "type": "host-local"
        }
      },
      {
        "type": "portmap",
        "capabilities": {
          "portMappings": true
        }
      }
    ]
  }
```

You can also set the MTU (for the Pod's network interface) in the CNI
configuration using `"mtu": <MTU_SIZE>`. When using an `antrea.yml` manifest, the
MTU should be set with the `antrea-agent` `defaultMTU` configuration parameter,
which will apply to all Pods and the host gateway interface on every Node. It is
strongly discouraged to set the `"mtu"` field in the CNI configuration to a
value that does not match the `defaultMTU` parameter, as it may lead to
performance degradation or packet drops.

Antrea enables portmap CNI plugin by default to support `hostPort`
functionality for Pods. In order to disable the portmap plugin, remove the
following from Antrea CNI config:

```json
{
  "type": "portmap",
  "capabilities": {
    "portMappings": true
  }
}
```
