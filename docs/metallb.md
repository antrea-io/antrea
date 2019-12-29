# Deploying metallb with Antrea

MetalLB is a load-balancer implementation for bare metal Kubernetes clusters, using standard routing protocols.
As Antrea does not implement a LoadBalancer service, it can be complemented with MetalLB to provide that functionality.

To install MetalLB, apply the following:

```bash
kubectl apply -f https://raw.githubusercontent.com/google/metallb/v0.8.3/manifests/metallb.yaml
```
which deploys MetalLB controller service and speaker daemonset.

MetalLB requires additional configuration and allocation of external IP addresses.
For further information see [MetalLB configuration and installation guide](https://metallb.universe.tf/configuration/).
