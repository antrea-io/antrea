# Network Requirements

Antrea has a few network requirements to get started, ensure that your hosts and
firewalls allow the necessary traffic based on your configuration.

| Configuration                                  | Host(s)                               | Protocols/Ports                            | Other                        |
|------------------------------------------------|---------------------------------------|--------------------------------------------|------------------------------|
| Antrea with VXLAN enabled                      | All                                   | UDP 4789                                   |                              |
| Antrea with Geneve enabled                     | All                                   | UDP 6081                                   |                              |
| Antrea with STT enabled                        | All                                   | TCP 7471                                   |                              |
| Antrea with GRE enabled                        | All                                   | IP Protocol ID 47                          | No support for IPv6 clusters |
| Antrea with IPsec ESP enabled                  | All                                   | IP protocol ID 50 and 51, UDP 500 and 4500 |                              |
| Antrea with WireGuard enabled                  | All                                   | UDP 51820                                  |                              |
| Antrea Multi-cluster with WireGuard encryption | Multi-cluster Gateway Node            | UDP 51821                                  |                              |
| Antrea with feature BGPPolicy enabled          | Selected by user-provided BGPPolicies | TCP 179<sup>[1]</sup>                      |                              |
| All                                            | Kube-apiserver host                   | TCP 443 or 6443<sup>[2]</sup>              |                              |
| All                                            | All                                   | TCP 10349, 10350, 10351, UDP 10351         |                              |

[1] _The default value is 179, but a user created BGPPolicy can assign a different
port number._

[2] _The value is passed to kube-apiserver `--secure-port` flag. You can find the port
number from the output of `kubectl get svc kubernetes -o yaml`._
