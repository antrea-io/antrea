# Configuration

## antrea-agent

### Command line options

```text
--config string                    The path to the configuration file
--v Level                          number for the log level verbosity
```

Use `antrea-agent -h` to see complete options.

### Configuration

The `antrea-agent` configuration file specifies the agent configuration
parameters. For all the agent configuration parameters of a Linux Node, refer to
this [base configuration file](/build/yamls/base/conf/antrea-agent.conf).
For all the configuration parameters of a Windows Node, refer to this [base
configuration file](/build/yamls/windows/base/conf/antrea-agent.conf)

## antrea-controller

### Command line options

```text
--config string                    The path to the configuration file
--v Level                          number for the log level verbosity
```

Use `antrea-controller -h` to see complete options.

### Configuration

The `antrea-controller` configuration file specifies the controller
configuration parameters. For all the controller configuration parameters,
refer to this [base configuration file](/build/yamls/base/conf/antrea-controller.conf).

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
      },
      {
        "type": "bandwidth",
        "capabilities": {
          "bandwidth": true
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

Antrea enables portmap and bandwidth CNI plugins by default to support `hostPort`
and traffic shaping functionalities for Pods respectively. In order to disable
them, remove the corresponding section from `antrea-cni.conflist` in the Antrea
manifest. For example, removing the following section disables portmap plugin:

```json
{
  "type": "portmap",
  "capabilities": {
    "portMappings": true
  }
}
```
