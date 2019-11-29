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
clientConnection:
  # Path of the kubeconfig file that is used to configure access to a K8s cluster.
  # If not specified, InClusterConfig will be used.
  #kubeconfig: <PATH_TO_KUBE_CONF>

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
#tunnelType: vxlan

# Default MTU to use for the host gateway interface and the network interface of
# each Pod. If omitted, antrea-agent will default this value to 1450 to accommodate
# for tunnel encapsulate overhead.
#defaultMTU: 1450

# Mount location of the /proc directory. The default is "/host", which is appropriate when
# antrea-agent is run as part of the Antrea DaemonSet (and the host's /proc directory is mounted
# as /host/proc in the antrea-agent container). When running antrea-agent as a process,
# hostProcPathPrefix should be set to "/" in the YAML config.
#hostProcPathPrefix: /host
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
```

## CNI configuration

A typical CNI configuration looks like this:
```json
  {
    "cniVersion":"0.3.0",
    "name": "antrea",
    "type": "antrea",
    "ipam": {
      "type": "host-local"
    }
  }
```

You can also set the MTU (for the Pod's network interface) in the CNI
configuration using `"mtu": <MTU_SIZE>`. When using an `antrea.yml` manifest, the
MTU should be set with the `antrea-agent` `defaultMTU` configuration parameter,
which will apply to all Pods and the host gateway interface on every Node. It is
strongly discouraged to set the `"mtu"` field in the CNI configuration to a
value that does not match the `defaultMTU` parameter, as it may lead to
performance degradation or packet drops.
