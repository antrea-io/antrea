# Configuration

## okn-agent

### Command line options
```
--config string                    The path to the configuration file
--v Level                          number for the log level verbosity
```
Use `okn-agent -h` to see complete options.

### Configuration
```
# clientConnection specifies the kubeconfig file and client connection settings for the agent
# to communicate with the apiserver.
clientConnection:
  # Path of the kubeconfig file that is used to configure access to a K8s cluster.
  # If not specified, InClusterConfig will be used.
  #kubeconfig: <PATH_TO_KUBE_CONF>

# Name of the OpenVSwitch bridge okn-agent will create and use.
# Make sure it doesn't conflict with your existing OpenVSwitch bridges.
#ovsBridge: br-int

# Name of the gateway interface for the local Pod subnet. okn-agent will create the interface on the OVS bridge.
# Make sure it doesn't conflict with your existing interfaces.
#hostGateway: gw0

# Encapsulation mode for communication between Pods across Nodes, supported values:
# - vxlan (default)
# - geneve
#tunnelType: vxlan

# Mount location of the /proc directory. The default is "/host", which is appropriate when
# okn-agent is run as part of the OKN DaemonSet (and the host's /proc directory is mounted
# as /host/proc in the okn-agent container). When running okn-agent as a process,
# hostProcPathPrefix should be set to "/" in the YAML config.
#hostProcPathPrefix: /host
```