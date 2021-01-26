# Mellanox CI

Mellanox CI is used to test hardware offload in the Antrea project.
It deploys Kubernetes with the Antrea image and tests whether the
OVS has hardware offload capabilities or not.

## Workflow

The CI tests run on a single node cluster with a ConnectX5 NIC card,
the latest stable Kubernetes binaries are built each time the scripts
run. In addition to Kubernetes and Antrea, the scripts deploy
Multus CNI, SRIOV device plugin, and container networking plugins. The
versions for the used components are summarized as follow:

* Kubernetes: Latest stable.
* Antrea: Image built from pull request.
* Multus: A nightly pulled latest stable Multus image.
* SRIOV device plugin: A nightly built image from the main branch.
* container networking plugins: Latest binaries built from the main branch.

The CI uses three scripts to run the tests:

* start_ci.sh: Build and deploy the testing environment.
* test.sh: Test the hardware offload.
* stop_ci.sh: Stop and clean the testing environment.

The CI can be triggered by commenting `/test-hw-offload` on an
opened pull request.

## Configurations

The scripts use Bash environment variables to configure their behavior.
The following table shows what variables can be configured:

|  Variable<br />(Default value)  |  Comments |
|  ------ |  ------ |
|  RECLONE<br />(true) | Whether to clone projects again in case of single workspace |
|  WORKSPACE<br />(/tmp/k8s_$$) | The directory that will contain all the project components |
|  LOGDIR<br />($WORKSPACE/logs) | The directory where the logs should be put |
|  ARTIFACTS<br />($WORKSPACE/artifacts) | The directory where configuration files should be put |
|  TIMEOUT<br />(300) | Timeout time in seconds for Kubernetes resources status change |
|  POLL_INTERVAL<br />(10) | The interval to wait between each check for Kubernetes resources status change |
|  KUBERNETES_VERSION<br />(latest_stable) | The Kubernetes version (or branch) to build |
|  HARBOR_REGISTRY<br />(harbor.mellanox.com) | The docker registry to pull images from |
|  HARBOR_PROJECT<br />(cloud-orchestration) | The docker registry project to pull the images from |
|  MULTUS_CNI_REPO<br />(<https://github.com/intel/multus-cni>) | Multus CNI repository URL |
|  MULTUS_CNI_BRANCH<br />(master) | Multus CNI branch to build |
|  MULTUS_CNI_PR<br />() | Multus CNI pull request number to pull, if this is used the MULTUS_CNI_BRANCH is ignored |
|  MULTUS_CNI_HARBOR_IMAGE<br />(${HARBOR_REGISTRY}/${HARBOR_PROJECT}/multus) | The Multus image to pull in case the project was not built |
|  PLUGINS_REPO<br />(<https://github.com/containernetworking/plugins.git>) | containernetworking repository URL |
|  PLUGINS_BRANCH<br />(master) | containernetworking branch to build |
|  PLUGINS_BRANCH_PR<br />() | containernetworking pull request number to pull, if this is used the PLUGINS_BRANCH is ignored |
|  SRIOV_NETWORK_DEVICE_PLUGIN_REPO<br />(<https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin>) | SRIOV network device plugin repository to use |
|  SRIOV_NETWORK_DEVICE_PLUGIN_BRANCH<br />(master) | SRIOV network device plugin branch to build |
|  SRIOV_NETWORK_DEVICE_PLUGIN_PR<br />() | SRIOV network device plugin pull request number to pull, adding this will ignore SRIOV_NETWORK_DEVICE_PLUGIN_BRANCH |
|  SRIOV_NETWORK_DEVICE_PLUGIN_HARBOR_IMAGE<br />(${HARBOR_REGISTRY}/${HARBOR_PROJECT}/sriov-device-plugin) | The SRIOV network device plugin image to pull in case the project was not built |
|  GOPATH<br />(${WORKSPACE}) ||
|  PATH<br />(/usr/local/go/bin/:<br />$GOPATH/src/k8s.io/kubernetes/third_party/etcd:<br />$PATH) ||
|  CNI_BIN_DIR<br />(/opt/cni/bin/) | This is used to configure Kubernetes $local_cluser_up.sh CNI_BIN_DIR |
|  CNI_CONF_DIR<br />(/etc/cni/net.d/) | This is used to configure Kubernetes local_cluser_up.sh CNI_CONF_DIR |
|  API_HOST<br />($(hostname)) | The Node name to use |
|  API_HOST_IP<br />($(hostname -I \| awk '{print $1}')) | The API server IP |
|  POD_CIDR<br />(192.168.0.0/16) | The Pods network subnet |
|  SERVICE_CIDR<br />(172.0.0.0/16) | The Service network subnet |
|  KUBECONFIG<br />(/etc/kubernetes/admin.conf) | The KUBECONFIG file to use |
|  SRIOV_INTERFACE<br />(auto_detect) | The Mellanox interface to use to create the VFs |
|  NETWORK<br />(192.168.$N) | This is used to setup the MACVLAN network range, N is randomly generated |
|  ANTREA_CNI_REPO<br />(<https://github.com/vmware-tanzu/antrea.git>)| Antrea project repository to use |
|  ANTREA_CNI_BRANCH<br />(main) | Antrea project branch to use |
|  ANTREA_CNI_PR<br />() | Antrea project pull request number to pull, adding this will ignore ANTREA_CNI_BRANCH |
|  ANTREA_CNI_HARBOR_IMAGE<br />(${HARBOR_REGISTRY}/${HARBOR_PROJECT}/antrea) | The Antrea image to pull in case the project was not built |
|  VFS_NUM<br />(4) | Number of SRIOV VFs to create |
