#!/bin/bash -x

source ./common/common_functions.sh

export RECLONE=${RECLONE:-true}
export WORKSPACE=${WORKSPACE:-/tmp/k8s_$$}
export LOGDIR=$WORKSPACE/logs
export ARTIFACTS=$WORKSPACE/artifacts
export TIMEOUT=${TIMEOUT:-300}
export POLL_INTERVAL=${POLL_INTERVAL:-10}

export ANTREA_CNI_REPO=${ANTREA_CNI_REPO:-https://github.com/vmware-tanzu/antrea.git}
export ANTREA_CNI_BRANCH=${ANTREA_CNI_BRANCH:-''}
export ANTREA_CNI_PR=${ANTREA_CNI_PR:-''}
export ANTREA_CNI_HARBOR_IMAGE=${ANTREA_CNI_HARBOR_IMAGE:-${HARBOR_REGESTRY}/${HARBOR_PROJECT}/antrea}

export GOPATH=${WORKSPACE}
export PATH=/usr/local/go/bin/:$GOPATH/src/k8s.io/kubernetes/third_party/etcd:$PATH

export CNI_BIN_DIR=${CNI_BIN_DIR:-/opt/cni/bin/}
export CNI_CONF_DIR=${CNI_CONF_DIR:-/etc/cni/net.d/}
export KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}

#TODO add autodiscovering
export SRIOV_INTERFACE=${SRIOV_INTERFACE:-auto_detect}
export VFS_NUM=${VFS_NUM:-4}

antrea_scm_dir="/jenkins/workspace/antrea_ci/PR/${ANTREA_CNI_PR}"

function download_and_build {
    status=0
    if [ "$RECLONE" != true ] ; then
        return $status
    fi

    [ -d /var/lib/cni/sriov ] && rm -rf /var/lib/cni/sriov/*

    deploy_sriov_device_plugin
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "ERROR: Failed to build the sriov-network-device-plugin project!"
        return $status
    fi

    cat > $ARTIFACTS/configMap.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: sriovdp-config
  namespace: kube-system
data:
  config.json: |
    {
      "resourceList": [{
          "resourcePrefix": "mellanox.com",
          "resourceName": "sriov_antrea",
          "selectors": {
                  "vendors": ["15b3"],
                  "devices": ["1018"],
                  "drivers": ["mlx5_core"]
              }
      }
      ]
    }
EOF

    cp /etc/pcidp/config.json $ARTIFACTS
    
    echo "Download Antrea components"
    rm -rf $WORKSPACE/antrea-cni

	    if test ${ANTREA_CNI_PR}; then
		if [[ ! -d "$antrea_scm_dir" ]];then
            echo "ERROR: No directory found at $antrea_scm_dir!!"
            return 1
        fi
        cp -rf "$antrea_scm_dir" $WORKSPACE/antrea-cni
        pushd $WORKSPACE/antrea-cni
        
        VERSION=latest make build
        let status=status+$?
        popd
    else
        build_github_project "antrea-cni" "export VERSION=latest && make build"
        let status=status+$?
    fi

    if [ "$status" != 0 ]; then
        echo "ERROR: Failed to build the antrea-cni project!"
        return $status
    fi

    if [[ -z "${ANTREA_CNI_PR}${ANTREA_CNI_BRANCH}" ]];then
        change_image_name $ANTREA_CNI_HARBOR_IMAGE antrea/antrea-ubuntu
    fi
    
    if [[ -z "$(grep hw-offload $WORKSPACE/antrea-cni/build/yamls/antrea.yml)" ]];then
        sed -i '/start_ovs/a\        - --hw-offload' $WORKSPACE/antrea-cni/build/yamls/antrea.yml
    fi

    cat > $ARTIFACTS/antrea-net.yaml <<EOF
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
    name: sriov-antrea-net
    namespace: kube-system
    annotations:
        k8s.v1.cni.cncf.io/resourceName: mellanox.com/sriov_antrea
spec:
    config: '{
    "cniVersion": "0.3.1",
    "name": "sriov-antrea-net",
    "type": "antrea",
         "ipam": {
         "type": "host-local"
       }
}'
EOF
    popd
    return 0
}


function create_vfs {
    if [ $SRIOV_INTERFACE == 'auto_detect' ]; then
        export SRIOV_INTERFACE=$(ls -l /sys/class/net/ | grep $(lspci |grep Mellanox | grep MT27800|head -n1|awk '{print $1}') | awk '{print $9}')
    fi
    echo 0 > /sys/class/net/$SRIOV_INTERFACE/device/sriov_numvfs
    sleep 5
    echo $VFS_NUM > /sys/class/net/$SRIOV_INTERFACE/device/sriov_numvfs
    sleep 5

    vfs_pci_list=$(grep PCI_SLOT_NAME /sys/class/net/"$SRIOV_INTERFACE"/device/virtfn*/uevent | cut -d'=' -f2)
    for pci in $vfs_pci_list
    do
        echo "$pci" > /sys/bus/pci/drivers/mlx5_core/unbind
    done

   interface_pci=$(grep PCI_SLOT_NAME /sys/class/net/"$SRIOV_INTERFACE"/device/uevent\
                     | cut -d'=' -f2 -s)
   devlink dev eswitch set pci/"$interface_pci" mode switchdev

   for pci in $vfs_pci_list
   do
       echo "$pci" > /sys/bus/pci/drivers/mlx5_core/bind
   done
}
#TODO add docker image mellanox/mlnx_ofed_linux-4.4-1.0.0.0-centos7.4 presence

create_workspace

create_vfs

pushd $WORKSPACE

deploy_k8s_with_multus
if [ $? -ne 0 ]; then
    echo "Failed to deploy k8s"
    exit 1
fi

pushd $WORKSPACE

download_and_build
if [ $? -ne 0 ]; then
    echo "Failed to download and build components"
    exit 1
fi

pushd $WORKSPACE/multus-cni 
./build
cp bin/multus /opt/cni/bin/
popd

echo " {\"cniVersion\": \"0.4.0\", \"name\": \"multus-cni-network\", \"type\": \"multus\", \"logLevel\": \"debug\", \"logFile\": \"/var/log/multus.log\", \"kubeconfig\": \"$KUBECONFIG\", \"clusterNetwork\": \"sriov-antrea-net\" }"\
       	> /etc/cni/net.d/00-multus.conf

kubectl create -f $ARTIFACTS/antrea-net.yaml

kubectl create -f $ARTIFACTS/configMap.yaml
kubectl create -f $(ls -l $WORKSPACE/sriov-network-device-plugin/deployments/*/sriovdp-daemonset.yaml|tail -n1|awk '{print $NF}')

kubectl create -f $WORKSPACE/antrea-cni/build/yamls/antrea.yml

cp $ARTIFACTS/antrea-net.yaml $(ls -l $WORKSPACE/sriov-network-device-plugin/deployments/*/sriovdp-daemonset.yaml|tail -n1|awk '{print $NF}') $ARTIFACTS/
echo "All code in $WORKSPACE"
echo "All logs $LOGDIR"
echo "All confs $ARTIFACTS"

echo "Setup is up and running. Run following to start tests:"
echo "# WORKSPACE=$WORKSPACE NETWORK=$NETWORK ./scripts/test.sh"
popd
exit $status
