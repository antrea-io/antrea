#!/bin/bash

export RECLONE=${RECLONE:-true}
export WORKSPACE=${WORKSPACE:-/tmp/k8s_$$}
export LOGDIR=$WORKSPACE/logs
export ARTIFACTS=$WORKSPACE/artifacts
export TIMEOUT=${TIMEOUT:-600}
export POLL_INTERVAL=${POLL_INTERVAL:-10}

# can be <latest_stable|master|vA.B.C>
export KUBERNETES_VERSION=${KUBERNETES_VERSION:-latest_stable}

export HARBOR_REGISTRY=${HARBOR_REGISTRY:-harbor.mellanox.com}
export HARBOR_PROJECT=${HARBOR_PROJECT:-cloud-orchestration}

export MULTUS_CNI_REPO=${MULTUS_CNI_REPO:-https://github.com/intel/multus-cni}
export MULTUS_CNI_BRANCH=${MULTUS_CNI_BRANCH:-''}
export MULTUS_CNI_PR=${MULTUS_CNI_PR:-''}
export MULTUS_CNI_HARBOR_IMAGE=${MULTUS_CNI_HARBOR_IMAGE:-${HARBOR_REGISTRY}/${HARBOR_PROJECT}/multus}

export SRIOV_NETWORK_DEVICE_PLUGIN_REPO=${SRIOV_NETWORK_DEVICE_PLUGIN_REPO:-https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin}
export SRIOV_NETWORK_DEVICE_PLUGIN_BRANCH=${SRIOV_NETWORK_DEVICE_PLUGIN_BRANCH:-''}
export SRIOV_NETWORK_DEVICE_PLUGIN_PR=${SRIOV_NETWORK_DEVICE_PLUGIN_PR:-''}
export SRIOV_NETWORK_DEVICE_PLUGIN_HARBOR_IMAGE=${SRIOV_NETWORK_DEVICE_PLUGIN_HARBOR_IMAGE:-${HARBOR_REGISTRY}/${HARBOR_PROJECT}/sriov-device-plugin}

export PLUGINS_REPO=${PLUGINS_REPO:-https://github.com/containernetworking/plugins.git}
export PLUGINS_BRANCH=${PLUGINS_BRANCH:-''}
export PLUGINS_BRANCH_PR=${PLUGINS_BRANCH_PR:-''}

export GOPATH=${WORKSPACE}
export PATH=/usr/local/go/bin/:$GOPATH/src/k8s.io/kubernetes/third_party/etcd:$PATH

export API_HOST=$(hostname)
export API_HOST_IP=$(hostname -I | awk '{print $1}')
export POD_CIDR=${POD_CIDR:-'192.168.0.0/16'}
export SERVICE_CIDR=${SERVICE_CIDR:-'172.0.0.0/16'}
export KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}

export CNI_BIN_DIR=${CNI_BIN_DIR:-/opt/cni/bin/}
export CNI_CONF_DIR=${CNI_CONF_DIR:-/etc/cni/net.d/}

export SRIOV_INTERFACE=${SRIOV_INTERFACE:-auto_detect}

# generate random network
N=$((1 + RANDOM % 128))
export NETWORK=${NETWORK:-"192.168.$N"}

export SCRIPTS_DIR=${SCRIPTS_DIR:-$(pwd)}

##################################################
##################################################
###############   Functions   ####################
##################################################
##################################################

create_workspace(){
    echo "Working in $WORKSPACE"
    mkdir -p $WORKSPACE
    mkdir -p $LOGDIR
    mkdir -p $ARTIFACTS

    date +"%Y-%m-%d %H:%M:%S" > ${LOGDIR}/start-time.log
}

get_arch(){
    if [[ $(uname -a) == *"ppc"* ]]; then
        echo ppc
    else
        echo amd
    fi
}

k8s_build(){
    status=0
    echo "Download K8S"
    rm -f /usr/local/bin/kubectl
    if [ ${KUBERNETES_VERSION} == 'latest_stable' ]; then
        export KUBERNETES_VERSION=$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)
    fi
    rm -rf $GOPATH/src/k8s.io/kubernetes

    git clone https://github.com/kubernetes/kubernetes.git $WORKSPACE/src/k8s.io/kubernetes

    pushd $WORKSPACE/src/k8s.io/kubernetes
    git checkout ${KUBERNETES_VERSION}
    git log -p -1 > $ARTIFACTS/kubernetes.txt

    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to build K8S ${KUBERNETES_VERSION}: Failed to clean k8s dir."
        return $status
    fi

    make kubectl kubeadm kubelet

    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to build K8S ${KUBERNETES_VERSION}: Failed to make."
        return $status
    fi

    cp _output/bin/kubectl _output/bin/kubeadm _output/bin/kubelet  /usr/local/bin/

    kubectl version --client
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to run kubectl please fix the error above!"
        return $status
    fi

    popd
}

prepare_kubelet(){
    cp -rf ${SCRIPTS_DIR}/deploy/kubelet/* /etc/systemd/system/
    sudo systemctl daemon-reload
}

get_distro(){
    grep ^NAME= /etc/os-release | cut -d'=' -f2 -s | tr -d '"' | tr [:upper:] [:lower:] | cut -d" " -f 1
}

configure_firewall(){
    local os_distro=$(get_distro)
    if [[ "$os_distro" == "ubuntu" ]];then
        sudo systemctl stop ufw
        sudo systemctl disable ufw
    elif [[ "$os_distro" == "centos" ]]; then
        sudo systemctl stop firewalld
        sudo systemctl stop iptables
        sudo systemctl disable firewalld
        sudo systemctl disable iptables
    else
        echo "Warning: Unknown Distribution \"$os_distro\", stopping iptables..."
        sudo systemctl stop iptables
        sudo systemctl disable iptables
    fi
}

k8s_run(){
    status=0

    prepare_kubelet

    configure_firewall

    sudo sysctl -p /etc/sysctl.conf

    sudo systemctl restart docker

    sudo kubeadm init --apiserver-advertise-address=$API_HOST_IP --node-name=$API_HOST --pod-network-cidr $POD_CIDR --service-cidr $SERVICE_CIDR
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo 'Failed to run kubeadm!'
        return $status
    fi

    mkdir -p $HOME/.kube

    sudo chmod 644 /etc/kubernetes/*.conf

    kubectl taint nodes $(kubectl get nodes -o name | cut -d'/' -f 2) --all node-role.kubernetes.io/master-
    return $?
}

network_plugins_install(){
    status=0
    echo "Download $PLUGINS_REPO"
    rm -rf $WORKSPACE/plugins
    git clone $PLUGINS_REPO $WORKSPACE/plugins
    pushd $WORKSPACE/plugins
    if test ${PLUGINS_PR}; then
        git fetch --tags --progress ${PLUGINS_REPO} +refs/pull/*:refs/remotes/origin/pr/*
        git pull origin pull/${PLUGINS_PR}/head
        let status=status+$?
        if [ "$status" != 0 ]; then
            echo "Failed to fetch container networking pull request #${PLUGINS_PR}!!"
            return $status
        fi
    elif test $PLUGINS_BRANCH; then
        git checkout $PLUGINS_BRANCH
        if [ "$status" != 0 ]; then
            echo "Failed to switch to container networking branch ${PLUGINS_BRANCH}!!"
            return $status
        fi
    fi
    git log -p -1 > $ARTIFACTS/plugins-git.txt
    bash ./build_linux.sh
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to build $PLUGINS_REPO $PLUGINS_BRANCH"
        return $status
    fi

    cp bin/* $CNI_BIN_DIR/
    popd
}

multus_install(){
    status=0
    build_github_project "multus-cni" "sudo docker build -t $MULTUS_CNI_HARBOR_IMAGE ."

    change_k8s_resource "DaemonSet" "kube-multus-ds" "spec.template.spec.containers[0].image"\
        "$MULTUS_CNI_HARBOR_IMAGE" "$WORKSPACE/multus-cni/deployments/multus-daemonset.yml"
}

multus_configuration() {
    status=0
    echo "Configure Multus"
    local arch=$(get_arch)
    date
    sleep 30
    sed -i 's;/etc/cni/net.d/multus.d/multus.kubeconfig;/etc/kubernetes/admin.conf;g' $WORKSPACE/multus-cni/deployments/multus-daemonset.yml

    kubectl create -f $WORKSPACE/multus-cni/deployments/multus-daemonset.yml

    kubectl -n kube-system get ds
    rc=$?
    let stop=$(date '+%s')+$TIMEOUT
    d=$(date '+%s')
    while [ $d -lt $stop ]; do
       echo "Wait until multus is ready"
       ready=$(kubectl -n kube-system get ds |grep kube-multus-ds|awk '{print $4}')
       rc=$?
       kubectl -n kube-system get ds
       d=$(date '+%s')
       sleep $POLL_INTERVAL
       if [ $ready -eq 1 ]; then
           echo "System is ready"
           break
      fi
    done
    if [ $d -gt $stop ]; then
        kubectl -n kube-system get ds
        echo "kube-multus-ds-${arch}64 is not ready in $TIMEOUT sec"
        return 1
    fi

    multus_config=$CNI_CONF_DIR/99-multus.conf
    cat > $multus_config <<EOF
    {
        "cniVersion": "0.3.0",
        "name": "macvlan-network",
        "type": "macvlan",
        "mode": "bridge",
          "ipam": {
                "type": "host-local",
                "subnet": "${NETWORK}.0/24",
                "rangeStart": "${NETWORK}.100",
                "rangeEnd": "${NETWORK}.216",
                "routes": [{"dst": "0.0.0.0/0"}],
                "gateway": "${NETWORK}.1"
            }
        }
EOF
    cp $multus_config $ARTIFACTS

    sleep 20

    sudo chmod 664 /etc/cni/net.d/00-multus.conf

    return $?
}

function replace_placeholder {
    local placeholder=$1
    local new_value=$2
    local file=$3

    echo "Changing \"$placeholder\" into \"$new_value\" in $file"
    sed -i "s;$placeholder;$new_value;" $file
}

function yaml_write {
    local key=$1
    local new_value=$2
    local file=$3

    echo "Changing the value of \"$key\" in $file to \"$new_value\""
    yq w -i "$file" "$key" -- "$new_value"
}

function yaml_read {
    local key=$1
    local file=$2
    
    yq r "$file" "$key"
}

function deploy_k8s_with_multus {

    network_plugins_install
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to install container networking plugins!!"
        popd
        return $status
    fi

    multus_install
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to clone multus!!"
        popd
        return $status
    fi

    k8s_build
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to build Kubernetes!!"
        popd
        return $status
    fi

    k8s_run
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to run Kubernetes!!"
        popd
        return $status
    fi

    multus_configuration
    let status=status+$?
    if [ "$status" != 0 ]; then
        echo "Failed to run multus!!"
        popd
        return $status
    fi
}

function change_k8s_resource {
    local resource_kind="$1"
    local resource_name="$2"
    local resource_key="$3"
    local resource_new_value="$4"
    local resource_file="$5"

    let doc_num=0
    changed="false"
    for kind in $(yq r -d "*" $resource_file kind);do
        if [[ "$kind" == "$resource_kind" ]];then
            name=$(yq r -d "$doc_num" $resource_file metadata.name)
            if [[ "$name" == "$resource_name" ]];then
                echo "changing $resource_key to $resource_new_value"
                yq w -i -d "$doc_num" "$resource_file" "$resource_key" "$resource_new_value"
                changed="true"
                break
            fi
        fi
        let doc_num=$doc_num+1
    done

    if [[ "$changed" == "false" ]];then
        echo "Failed to change $resource_key to $resource_new_value in $resource_file!"
        return 1
   fi

   return 0
}

function deploy_sriov_device_plugin {
    build_github_project "sriov-network-device-plugin" \
        "sed -i 's;^TAG=.*;TAG=$SRIOV_NETWORK_DEVICE_PLUGIN_HARBOR_IMAGE;' Makefile && make image"

    change_k8s_resource "DaemonSet" "kube-sriov-device-plugin-amd64" "spec.template.spec.containers[0].image"\
        "$SRIOV_NETWORK_DEVICE_PLUGIN_HARBOR_IMAGE" "$WORKSPACE/sriov-network-device-plugin/deployments/k8s-v1.16/sriovdp-daemonset.yaml"

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
          "resourceName": "sriov_rdma",
          "selectors": {
                  "vendors": ["15b3"],
                  "devices": ["1018"],
                  "drivers": ["mlx5_core"],
                  "isRdma": true
              }
      }
      ]
    }
EOF
}

function build_github_project {
    local project_name="$1"
    local image_build_command="${2:-make image}"

    local status=0

    if [[ -z "$project_name" ]];then
        echo "ERROR: No project specified to build!"
        return 1
    fi

    local upper_case_project_name="$(tr "-" "_" <<< $project_name | tr '[:lower:]' '[:upper:]')"

    local repo_variable="${upper_case_project_name}_REPO"
    local branch_variable="${upper_case_project_name}_BRANCH"
    local pr_variable="${upper_case_project_name}_PR"
    local harbor_image_variable="${upper_case_project_name}_HARBOR_IMAGE"

    echo "Downloading ${!repo_variable}"
    rm -rf "$WORKSPACE"/"$project_name"

    git clone "${!repo_variable}" "$WORKSPACE"/"$project_name"

    local sed_match_reg='s/(@| |^|=|	)docker($| )/\1sudo docker\2/'

    pushd $WORKSPACE/"$project_name"
    # Check if a pull request or a branch of the project is specified, if so build the image, otherwise pull
    # the image from the custom registry.
    if test ${!pr_variable}; then
        git fetch --tags --progress ${!repo_variable} +refs/pull/${!pr_variable}/*:refs/remotes/origin/pull-requests/${!pr_variable}/*
        git checkout pull-requests/${!pr_variable}/head
        let status=$status+$?
        if [[ "$status" != "0" ]];then
            echo "ERROR: Failed to checkout the $project_name pull request number ${!pr_variable}!"
            return "$status"
        fi

        sed -ri "${sed_match_reg}" Makefile

        eval "$image_build_command"
        let status=$status+$?
    elif test ${!branch_variable}; then
        git checkout ${!branch_variable}
        let status=$status+$?
        if [[ "$status" != "0" ]];then
            echo "ERROR: Failed to checkout the $project_name branch ${!branch_variable}!"
            return "$status"
        fi

        sed -ri "${sed_match_reg}" Makefile

        eval "$image_build_command"
        let status=$status+$?
    else
        sudo docker pull ${!harbor_image_variable}
        let status=$status+$?
    fi

    git log -p -1 > $ARTIFACTS/${project_name}-git.txt

    popd

    if [[ "$status" != "0" ]];then
        echo "ERROR: Failed to build the $project_name Project!"
        return "$status"
    fi

    return $status
}

function change_image_name {
    local old_image_name="$1"
    local new_image_name="$2"

    sudo docker tag $old_image_name $new_image_name
    if [[ "$?" != "0" ]];then
        echo "ERROR: Failed to rename the image $old_image_name to $new_image_name"
        return 1
    fi

    sudo docker rmi $old_image_name
}

function get_auto_net_device {
    ls -l /sys/class/net/ | grep $(lspci |grep Mellanox | grep -Ev 'MT27500|MT27520' | head -n1 | awk '{print $1}') | awk '{print $9}'
}

function load_core_drivers {
    sudo modprobe mlx5_core
    sudo modprobe ib_core
}
