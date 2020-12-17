# Mellanox CI
Mellanox CI is used to test hardware offload in the antrea project. It deploys Kubernetes with the antrea image and tests wither the OVS have hardware offload capabilities or not.

### Workflow
The CI uses three scripts to run the tests:
* start.sh: Build and deploy the kubernetes test environment including the antrea.
* test.sh: Test the hardware offload.
* stop.sh: Stop and clean the testing environment.

The CI can be triggered by commenting `/test-hw-offload` on an opened pull request.

### Configurations
The scripts use bash environment variables to configure its behavior. The following table shows what variables can be configured:

|  Variable |  DEFAULT VALUE |  Comments |
|  ------ |  ------ |  ------ |
|  RECLONE | true | whether or not to reclone projects in case of single workspace |
|  WORKSPACE | /tmp/k8s | The directory that willcontain all the project components |
|  LOGDIR | $WORKSPACE/logs | The directory where the logs should be put |
|  ARTIFACTS | $WORKSPACE/artifacts | The directory where configuration files should be put |
|  TIMEOUT | 300 | Timeout time for pods status |
|  POLL_INTERVAL | 10 | The interval to wait between each check for pods status change |
|  KUBERNETES_VERSION | latest_stable | The kubernetes version (or branch) to build |
|  HARBOR_REGESTRY | harbor.mellanox.com | The docker registry to use to pull images from |
|  HARBOR_PROJECT | cloud-orchestration | The docker registry project to use to pull the images from |
|  MULTUS_CNI_REPO | https://github.com/intel/multus-cni | multus cni repo URL |
|  MULTUS_CNI_BRANCH | master | multus cni branch to build |
|  MULTUS_CNI_PR || multus cni pr to pull, if this is used the MULTUS_CNI_BRANCH is ignored |
|  MULTUS_CNI_HARBOR_IMAGE | ${HARBOR_REGESTRY}/${HARBOR_PROJECT}/multus | The multus image to pull in case the project was not built |
|  PLUGINS_REPO | https://github.com/containernetworking/plugins.git | containernetworking repo URL |
|  PLUGINS_BRANCH | master | containernetworking branch to build |
|  PLUGINS_BRANCH_PR || containernetworking cni pr to pull, if this is used the PLUGINS_BRANCH is ignored |
|  SRIOV_NETWORK_DEVICE_PLUGIN_REPO | https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin | SRIOV network device plugin repo to use |
|  SRIOV_NETWORK_DEVICE_PLUGIN_BRANCH | master | SRIOV network device plugin branch to build |
|  SRIOV_NETWORK_DEVICE_PLUGIN_PR || SRIOV network device plugin pull request to pull, adding this will ignore SRIOV_NETWORK_DEVICE_PLUGIN_BRANCH |
|  SRIOV_NETWORK_DEVICE_PLUGIN_HARBOR_IMAGE | ${HARBOR_REGESTRY}/${HARBOR_PROJECT}/sriov-device-plugin | The sriov-network-device-plugin image to pull in case the project was not built |
|  GOPATH | ${WORKSPACE} ||
|  PATH | /usr/local/go/bin/:$GOPATH/src/k8s.io/kubernetes/third_party/etcd:$PATH ||
|  CNI_BIN_DIR | /opt/cni/bin/ | this is used to configure Kubernetes local_cluser_up.sh CNI_BIN_DIR |
|  CNI_CONF_DIR | /etc/cni/net.d/ | this is used to configure Kubernetes local_cluser_up.sh CNI_CONF_DIR |
|  API_HOST | $(hostname) | The node name to use |
|  API_HOST_IP | $(hostname -I | awk '{print $1}') | The API server IP |
|  POD_CIDER | 192.168.0.0/16 | The pods network subnet |
|  SERVICE_CIDER | 172.0.0.0/16 | The service network subnet |
|  KUBECONFIG | /etc/kubernetes/admin.conf | The KUBECONFIG file to use |
|  SRIOV_INTERFACE | auto_detect | The Mellanox interface to use to create the VFs |
|  NETWORK | "192.168.$N" | this is used to setup the macvlan network range, N is randomly generated |
|  ANTREA_CNI_REPO | https://github.com/vmware-tanzu/antrea.git | antrea project repo to use |
|  ANTREA_CNI_BRANCH | master | antrea project branch to use |
|  ANTREA_CNI_PR | | antrea project pull request to pull, adding this will ignore ANTREA_CNI_BRANCH |
|  ANTREA_CNI_HARBOR_IMAGE | ${HARBOR_REGESTRY}/${HARBOR_PROJECT}/antrea | The antrea image to pull in case the project was not built |
|  VFS_NUM | 4 | number of SRIOV VFs to create |
