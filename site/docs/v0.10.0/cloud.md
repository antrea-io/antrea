# Deploying Antrea on a cloud provider

Antrea may run in networkPolicyOnly mode in some cloud managed clusters. This document describes
 steps to create EKS using terraform.

## Common Prerequisites
1. To run EKS cluster, install and configure AWS cli(either version 1 or 2), see
   https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html, and
   https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
2. Install aws-iam-authenticator, see 
https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html
3. Install terraform, see https://learn.hashicorp.com/terraform/getting-started/install.html
4. You must already have ssh key-pair created. This key pair will be used to access worker Node via
 ssh.
```bash
ls ~/.ssh/
id_rsa  id_rsa.pub
```


## Create an EKS cluster via terraform
Ensures that you have permission to create EKS cluster, and have already
created EKS cluster role as well as worker Node profile.

```bash
export TF_VAR_eks_cluster_iam_role_name=YOUR_EKS_ROLE
export TF_VAR_eks_iam_instance_profile_name=YOUR_EKS_WORKER_NODE_PROFILE
export TF_VAR_eks_key_pair_name=YOUR_KEY_PAIR_TO_ACCESS_WORKER_NODE
```

Where 
- TF_VAR_eks_cluster_iam_role_name may be created by following these
 [instructions](https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html#create-service-role)
- TF_VAR_eks_iam_instance_profile_name may be created by following these
 [instructions](https://docs.aws.amazon.com/eks/latest/userguide/worker_node_IAM_role.html#create-worker-node-role)
- TF_VAR_eks_key_pair_name is the aws key pair name you have configured by following these
 [instructions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#how-to-generate-your-own-key-and-import-it-to-aws),
 using ssh-pair created in Prerequisites item 4
 


Create EKS cluster

```bash
./hack/terraform-eks.sh create
```

Interact with EKS cluster

```bash
./hack/terraform-eks.sh kubectl ... // issue kubectl commands to EKS cluster
./hack/terraform-eks.sh load ... // load local built images to EKS cluster
./hack/terraform-eks.sh destroy // destroy EKS cluster
```

and worker Node can be accessed with ssh via their external IPs.

Apply Antrea to EKS cluster

```bash
 ./hack/generate-manifest.sh --encap-mode networkPolicyOnly | ~/terraform/eks kubectl apply -f -
```