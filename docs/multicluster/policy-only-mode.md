# Antrea Multi-cluster with NetworkPolicy Only Mode

Multi-cluster Gateway works with Antrea `networkPolicyOnly` mode, in which
cross-cluster traffic is routed by Multi-cluster Gateways of member clusters,
and the traffic goes through Antrea overlay tunnels between Gateways and local
cluster Pods. Pod traffic within a cluster is still handled by the primary CNI,
not Antrea.

## Deploying Antrea in `networkPolicyOnly` mode with Multi-cluster feature

This section describes steps to deploy Antrea in `networkPolicyOnly` mode
with the Multi-cluster feature enabled on an EKS cluster.

You can follow [the EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/create-cluster.html)
to create an EKS cluster, and follow the [Antrea EKS installation guide](../eks-installation.md)
to deploy Antrea to an EKS cluster. Please note there are a few changes required
by Antrea Multi-cluster. You should set the following configuration parameters in
 `antrea-agent.conf` of the Antrea deployment manifest to enable the `Multicluster`
 feature and Antrea Multi-cluster Gateway:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
 name: antrea-config
 namespace: kube-system
data:
 antrea-agent.conf: |
   featureGates:
     Multicluster: true
   multicluster:
     enableGateway: true
     namespace: "" # Change to the Namespace where antrea-mc-controller is deployed.
```

Repeat the same steps to deploy Antrea for all member clusters in a ClusterSet.
Besides the Antrea deployment, you also need to deploy Antrea Multi-cluster Controller
in each member cluster. Make sure the Service CIDRs (ClusterIP ranges) must not overlap
among the member clusters. Please refer to [the quick start guide](./quick-start.md)
or [the user guide](./user-guide.md) to learn more information about how to configure
a ClusterSet.

## Connectivity between Clusters

When EKS clusters of a ClusterSet are in different VPCs, you may need to enable connectivity
between VPCs to support Multi-cluster traffic. You can check the following steps to set up VPC
connectivity for a ClusterSet.

In the following descriptions, we take a ClusterSet with two member clusters in two VPCs as
an example to describe the VPC configuration.

| Cluster ID    | PodCIDR       | Gateway IP   |
| ------------  | ------------- | ------------ |
| west-cluster  | 110.13.0.0/16 | 110.13.26.12 |
| east-cluster  | 110.14.0.0/16 | 110.14.18.50 |

### VPC Peering Configuration

When the Gateway Nodes do not have public IPs, you may create a VPC peering connection between
the two VPCs for the Gateways to reach each other. You can follow the
[AWS documentation](https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html) to
configure VPC peering.

You also need to add a route to the route tables of the Gateway Nodes' subnets, to enable
routing across the peering connection. For `west-cluster`, the route should have `east-cluster`'s
Pod CIDR: `110.14.0.0/16` to be the destination, and the peering connection to be the target;
for `east-cluster`, the route should have `west-cluster`'s Pod CIDR: `110.13.0.0/16` to be the
destination. To learn more about VPC peering routes, please refer to the [AWS documentation](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html).

### Security Groups

AWS security groups may need to be configured to allow tunnel traffic to Multi-cluster Gateways,
especially when the member clusters are in different VPCs. EKS should have already created a
security group for each cluster, which should have a description like "EKS created security group
applied to ENI that is attached to EKS Control Plane master nodes, as well as any managed workloads.".
You can add a new rule to the security group for Gateway traffic. For `west-cluster`, add an inbound
rule with source to be `east-cluster`'s Gateway IP `110.14.18.50/32`; for `east-cluster`, the source
should be `west-cluster`'s Gateway IP `110.13.26.12/32`.

By default, Multi-cluster Gateway IP should be the `InternalIP` of the Gateway Node, but you may
configure Antrea Multi-cluster to use the Node `ExternalIP`. Please use the right Node IP address
as the Gateway IP in the security group rule.
