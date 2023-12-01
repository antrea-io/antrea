# K8s Installers and Distributions

## Tested installers and distributions

The table below is not comprehensive. Antrea should work with most K8s
installers and distributions. The table refers to specific version combinations
which are known to work and have been tested, but support is not limited to that
list. Each Antrea version supports [multiple K8s minor versions](versioning.md#supported-k8s-versions),
and installers / distributions based on any one of these K8s versions should
work with that Antrea version.

| Antrea Version | Installer / Distribution | Cloud Infra | Node Info | Node Size | Conformance Results | Comments |
|-|-|-|-|-|-|-|
| v1.0.0 | Kubeadm v1.21.0 | AWS EC2 | Ubuntu 20.04.2 LTS (5.4.0-1045-aws) amd64, docker://20.10.6 | t3.medium |  |  |
| - | - | - | Windows Server 2019 Datacenter (10.0.17763.1817), docker://19.3.14 | t3.medium |  |  |
| - | - | - | Ubuntu 20.04.2 LTS (5.4.0-1045-aws) arm64, docker://20.10.6 | t3.medium |  |  |
| - | Cluster API Provider vSphere (CAPV), K8s 1.19.1 | VMC on AWS, vSphere 7.0.1 | Ubuntu 18.04, containerd | 2 vCPUs, 8GB RAM |  | Antrea CI |
| - | K3s v1.19.8+k3s1 | [OSUOSL] | Ubuntu 20.04.1 LTS (5.4.0-66-generic) arm64, containerd://1.4.3-k3s3 | 2 vCPUs, 4GB RAM |  | Antrea CI, cluster installed with [k3sup] 0.9.13 |
| - | Kops v1.20, K8s v1.20.5 | AWS EC2 | Ubuntu 20.04.2 LTS (5.4.0-1041-aws) amd64, containerd://1.4.4 | t3.medium | [results tarball](http://downloads.antrea.io/artifacts/sonobuoy-conformance/kops_202104212218_sonobuoy_bf0f8e77-c9df-472a-85e2-65e456cf4d83.tar.gz) |  |
| - | EKS, K8s v1.17.12 | AWS | AmazonLinux2, docker | t3.medium |  | Antrea CI |
| - | GKE, K8s v1.19.8-gke.1600 | GCP | Ubuntu 18.04, docker | e2-standard-4 |  | Antrea CI |
| - | AKS, K8s v1.18.14 | Azure | Ubuntu 18.04, moby | Standard_DS2_v2 |  | Antrea CI |
| - | AKS, K8s v1.19.9 | Azure | Ubuntu 18.04, containerd | Standard_DS2_v2 |  | Antrea CI |
| - | Kind v0.9.0, K8s v1.19.1 | N/A | Ubuntu 20.10, containerd://1.4.0 | N/A |  | [Requirements for using Antrea on Kind](kind.md) |
| - | Minikube v1.25.0 | N/A | Ubuntu 20.04.2 LTS (5.10.76-linuxkit) arm64, docker://20.10.12 | 8GB RAM | | |
| v1.10.0 | Rancher v2.7.0, K8s v1.24.10 | vSphere | Ubuntu 22.04.1 LTS (5.15.0-57-generic) amd64, docker://20.10.21 | 4 vCPUs, 4GB RAM |  |  |
| v1.11.0 | Kubeadm v1.20.2 | N/A | openEuler 22.03 LTS, docker://18.09.0 | 10GB RAM | | |
| v1.11.0 | Kubeadm v1.25.5 | N/A | openEuler 22.03 LTS, containerd://1.6.18 | 10GB RAM | | |
| v1.15.0 | Talos v1.5.5 | Docker provisioner | Talos | 2 vCPUs, 2.1 GB RAM | Pass | Requires Antrea v1.15 or above |
| - | - | QEMU provisioner | Talos | 2 vCPUs, 2.1 GB RAM | Pass | Requires Antrea v1.15 or above |

## Installer-specific instructions

### Kubeadm

When running `kubeadm init` to create a cluster, you need to provide a range of
IP addresses for the Pod network using `--pod-network-cidr`. By default, a /24
subnet will be allocated out of the CIDR to every Node which joins the cluster,
so make sure you use a large enough CIDR to accommodate the number of Nodes you
want. Once the cluster has been created, this CIDR cannot be changed.

### Rancher

Follow these steps to deploy Antrea (as a [custom CNI](https://rke.docs.rancher.com/config-options/add-ons/network-plugins/custom-network-plugin-example))
on [Rancher](https://ranchermanager.docs.rancher.com/pages-for-subheaders/kubernetes-clusters-in-rancher-setup) cluster:

* Edit the cluster YAML and set the `network-plugin` option to none.

* Add an addon for Antrea, in the following manner:

  ```yaml
  addons_include:
  - <link of the antrea.yml file>
  ```

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

### Minikube

To deploy Antrea on minikube, please follow these [steps](minikube.md).

### Talos

[Talos](https://www.talos.dev/) is a Linux distribution designed for running
Kubernetes. Antrea can be used as the CNI on Talos clusters (tested with both
the Docker provisioner and the QEMU provisioner). However, because of some
built-in security settings in Talos, the default configuration values cannot be
used when installing Antrea. You will need to install Antrea using Helm, with a
few custom values. Antrea v1.15 or above is required.

Follow these steps to deploy Antrea on a Talos cluster:

* Make sure that your Talos cluster is created without a CNI. To ensure this,
  you can use a config patch. For example, to create a Talos cluster without a
  CNI, using the Docker provisioner:

  ```bash
  cat << EOF > ./patch.yaml
  cluster:
  network:
    cni:
      name: none
  EOF

  talosctl cluster create --config-patch=@patch.yaml --wait=false --workers 2
  ```

  Notice how we use `--wait=false`: the cluster will never be "ready" until a
  CNI is installed.

  Note that while we use the Docker provisioner here, you can use the Talos
  platform of your choice.

* Ensure that you retrieve the Kubeconfig for your new cluster once it is
  available. You may need to use the `talosctl kubeconfig` command for this.

* Install Antrea using Helm, with the appropriate values:

  ```bash
  cat << EOF > ./values.yaml
  agent:
    dontLoadKernelModules: true
    installCNI:
      securityContext:
        capabilities: []
  EOF

  helm install -n kube-system antrea -f value.yml antrea/antrea
  ```

  The above configuration will drop all capabilities from the `installCNI`
  container, and instruct the Antrea Agent not to try loading any Kernel module
  explicitly.

## Updating the list

You can [open a Pull Request](../CONTRIBUTING.md) to:

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
