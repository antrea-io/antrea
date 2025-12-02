# Network Requirements

Antrea has a few network requirements to get started, ensure that your hosts and
firewalls allow the necessary traffic based on your configuration.

| Configuration                                  | Host(s)                               | Protocols/Ports                            | Configurable | Other                        |
|------------------------------------------------|---------------------------------------|--------------------------------------------|--------------|------------------------------|
| Antrea with VXLAN enabled                      | All                                   | UDP 4789                                   | Yes          |                              |
| Antrea with Geneve enabled                     | All                                   | UDP 6081                                   | Yes          |                              |
| Antrea with STT enabled                        | All                                   | TCP 7471                                   | Yes          |                              |
| Antrea with GRE enabled                        | All                                   | IP Protocol ID 47                          | No           | No support for IPv6 clusters |
| Antrea with IPsec ESP enabled                  | All                                   | IP protocol ID 50 and 51, UDP 500 and 4500 | No           |                              |
| Antrea with WireGuard enabled                  | All                                   | UDP 51820<sup>[3]</sup>                    | Yes          |                              |
| Antrea Multi-cluster with WireGuard encryption | Multi-cluster Gateway Node            | UDP 51821                                  | Yes          |                              |
| Antrea with feature BGPPolicy enabled          | Selected by user-provided BGPPolicies | TCP 179<sup>[1]</sup>                      | Yes          |                              |
| All                                            | Kube-apiserver host                   | TCP 443 or 6443<sup>[2]</sup>              | Yes          |                              |
| All                                            | All                                   | TCP 10349, 10350, 10351, UDP 10351         | Yes          |                              |
| Antrea with proxyAll enabled                   | All                                   | TCP 10256<sup>[4]</sup>                    | Yes          | Optional, for external LBs   |

[1] _The default value is 179, but a user created BGPPolicy can assign a different
port number._

[2] _The value is passed to kube-apiserver `--secure-port` flag. You can find the port
number from the output of `kubectl get svc kubernetes -o yaml`._

[3] _Antrea automatically adds the firewall rules to allow the WireGuard packets
(starting from v2.4), so the manual configuration on the host is not needed._

[4] _The default value is 10256, but it can be overridden in the antrea-agent
configuration `antreaProxy.serviceHealthCheckServerBindAddress`. It is used only
for external load balancer health checks. If `antreaProxy.disableServiceHealthCheckServer`
is set `true`, the health check server listening on the port will be disabled._
