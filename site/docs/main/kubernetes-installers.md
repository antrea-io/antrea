# K8s Installers and Distributions

## Tested installers and distributions

The table below is not comprehensive. Antrea should work with most K8s
installers and distributions. The table refers to specific version combinations
which are known to work and have been tested, but support is not limited to that
list. Each Antrea version supports [multiple K8s minor
versions](versioning.md#supported-k8s-versions), and installers / distributions
based on any one of these K8s versions should work with that Antrea version.

| Antrea Version | Installer / Distribution | Cloud Infra | Node Info | Node Size | Conformance Results | Comments |
|-|-|-|-|-|-|-|
| v1.0.0 | Kubeadm v1.21.0 | AWS EC2 | Ubuntu 20.04.2 LTS (5.4.0-1045-aws) amd64, docker://20.10.6 | t3.medium |  |  |
| - | - | - | Windows Server 2019 Datacenter (10.0.17763.1817), docker://19.3.14 | t3.medium |  |  |
| - | - | - | Ubuntu 20.04.2 LTS (5.4.0-1045-aws) arm64, docker://20.10.6 | t3.medium |  |  |
| - | Cluster API Provider vSphere (CAPV), K8s 1.19.1 | VMC on AWS, vSphere 7.0.1 | Ubuntu 18.04, containerd | 2 vCPUs, 8GB RAM |  | Antrea CI |
| - | Rancher v2.5.7, K8s v1.20.5-rancher1-1 | AWS EC2 | Ubuntu 18.04.5 LTS (5.4.0-1045-aws) amd64, docker://19.3.15 | t3a.medium | Some tests failing because of [this issue](https://github.com/kubernetes/kubernetes/issues/100197) |  |
| - | K3s v1.19.8+k3s1 | [OSUOSL] | Ubuntu 20.04.1 LTS (5.4.0-66-generic) arm64, containerd://1.4.3-k3s3 | 2 vCPUs, 4GB RAM |  | Antrea CI, cluster installed with [k3sup] 0.9.13 |
| - | Kops v1.20, K8s v1.20.5 | AWS EC2 | Ubuntu 20.04.2 LTS (5.4.0-1041-aws) amd64, containerd://1.4.4 | t3.medium | [results tarball](http://downloads.antrea.io/artifacts/sonobuoy-conformance/kops_202104212218_sonobuoy_bf0f8e77-c9df-472a-85e2-65e456cf4d83.tar.gz) |  |
| - | EKS, K8s v1.17.12 | AWS | AmazonLinux2, docker | t3.medium |  | Antrea CI |
| - | GKE, K8s v1.19.8-gke.1600 | GCP | Ubuntu 18.04, docker | e2-standard-4 |  | Antrea CI |
| - | AKS, K8s v1.18.14 | Azure | Ubuntu 18.04, moby | Standard_DS2_v2 |  | Antrea CI |
| - | AKS, K8s v1.19.9 | Azure | Ubuntu 18.04, containerd | Standard_DS2_v2 |  | Antrea CI |
| - | Kind v0.9.0, K8s v1.19.1 | N/A | Ubuntu 20.10, containerd://1.4.0 | N/A |  | [Requirements for using Antrea on Kind](kind.md) |

## Installer-specific instructions

### Kubeadm

When running `kubeadm init` to create a cluster, you need to provide a range of
IP addresses for the Pod network using `--pod-network-cidr`. By default, a /24
subnet will be allocated out of the CIDR to every Node which joins the cluster,
so make sure you use a large enough CIDR to accommodate the number of Nodes you
want. Once the cluster has been created, this CIDR cannot be changed.

### Rancher

When creating a workload cluster, set the [network
plugin](https://rancher.com/docs/rke/latest/en/config-options/add-ons/network-plugins/)
to `none`.

### K3s

When creating a cluster, run K3s with the following options:

* `--flannel-backend=none`, which lets you run the [CNI of your
  choice](https://rancher.com/docs/k3s/latest/en/installation/network-options/)
* `--disable-network-policy`, to disable the K3s NetworkPolicy controller

### Kops

When creating a cluster, run Kops with `--networking cni`, to enable CNI for the
cluster without deploying a specific network plugin.

### Kind

To deploy Antrea on Kind, please follow these [steps](kind.md).

## Updating the list

You can [open a Pull Request](CONTRIBUTING.md) to:

* Add a new K8s installer or distribution to the table above.
* Add a new combination of versions that you have tested successfully to the
  table above.

Please make sure that you run conformance tests with [sonobuoy] and consider
uploading the test results to a publicly accessible location. You can run
sonobuoy with:

```bash
sonobuoy run --mode certified-conformance
```

[k3sup]: https://github.com/alexellis/k3sup
[OSUOSL]: https://osuosl.org/services/aarch64/
[sonobuoy]: https://github.com/vmware-tanzu/sonobuoy
