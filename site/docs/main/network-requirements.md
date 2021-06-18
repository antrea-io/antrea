# Network Requirements

Antrea has a few network requirements to get started, ensure that your hosts and
firewalls allow the necessary traffic based on your configuration.

| Configuration                 | Host(s)             | ports/protocols                            |
| ----------------------------- | ------------------- | ------------------------------------------ |
| Antrea with VXLAN enabled     | All                 | UDP 4789                                   |
| Antrea with Geneve enabled    | All                 | UDP 6081                                   |
| Antrea with STT enabled       | All                 | TCP 7471                                   |
| Antrea with GRE enabled       | All                 | IP Protocol ID 47                          |
| Antrea with IPSec ESP enabled | All                 | IP protocol ID 50 and 51, UDP 500 and 4500 |
| All                           | kube-apiserver host | TCP 443 or 6443\*                          |
| All                           | All                 | TCP 10349, 10350                           |

\* _The value passed to kube-apiserver using the --secure-port flag. If you cannot
locate this, check the targetPort value returned by kubectl get svc kubernetes -o yaml._
