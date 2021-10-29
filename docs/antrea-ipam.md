# Antrea IPAM Capabilities

## Running NodeIPAM within Antrea Controller

NodeIPAM is a Kubernetes component, which manages IP address pool allocation per
each Node, when the Node initializes.

On single stack deployments, NodeIPAM allocates a single IPv4 or IPv6 CIDR per
Node, while in dual stack deployments, NodeIPAM allocates two CIDRs per each
Node: one for each IP family.

NodeIPAM is configured with a CIDR per each family, which it slices into smaller
per-Node CIDRs. When a Node is initialized, the CIDRs are set to the podCIDRs
attribute of the Node spec.

Antrea NodeIPAM controller can be executed in scenarios where the
NodeIPAMController is disabled in kube-controller-manager.

Note that running Antrea NodeIPAM while NodeIPAMController runs within 
kube-controller-manager would cause conflicts and result in an unstable 
behavior.   

### Configuration

Antrea Controller NodeIPAM configuration items are grouped under `nodeIPAM`
dictionary key.

NodeIPAM dictionary contains the following items:

- `enableNodeIPAM`: Enable the integrated NodeIPAM controller within the Antrea
controller. Default is false.

- `clusterCIDRs`: CIDR Ranges for Pods in cluster. String array containing single
CIDR range, or multiple ranges. The CIDRs could be either IPv4 or IPv6.

- `serviceCIDR`: CIDR Range for IPv4 Services in cluster. It is not necessary to
specify it when there is no overlap with clusterCIDRs.

- `serviceCIDRv6`: CIDR Range for IPv6 Services in cluster. It is not necessary to
  specify it when there is no overlap with clusterCIDRs.

- `nodeCIDRMaskSizeIPv4`: Mask size for IPv4 Node CIDR in IPv4 or dual-stack
cluster. Valid range is 16 to 30. Default is 24.

- `nodeCIDRMaskSizeIPv6`: Mask size for IPv6 Node CIDR in IPv6 or dual-stack
cluster. Valid range is 64 to 126. Default is 64.
