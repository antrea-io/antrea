#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is required for Antrea to work properly in a Kind cluster on Linux. It takes care of
# disabling TX hardware checksum offload for the veth interface (in the host's network namespace) of
# each Kind Node. This is required when using OVS in userspace mode. Refer to
# https://github.com/vmware-tanzu/antrea/issues/14 for more information.

# The script uses the antrea/ethtool Docker image (so that ethtool does not need to be installed on
# the Linux host).

CLUSTER_NAME=""
ANTREA_IMAGE="antrea/antrea-ubuntu:latest"
IMAGES=$ANTREA_IMAGE
ANTREA_CNI=true
POD_CIDR="10.10.0.0/16"
NUM_WORKERS=2
SUBNETS=""

set -eo pipefail
function echoerr {
    >&2 echo "$@"
}

_usage="
Usage: $0 create CLUSTER_NAME] [--pod-cidr POD_CIDR] [--antrea-cni true|false ] [--num-workers NUM_WORKERS] [--images IMAGES] [--subnets SUBNETS]
                  destroy CLUSTER_NAME
                  modify-node NODE_NAME
                  help
where:
  create: create a kind cluster with name CLUSTER_NAME
  destroy: delete a kind cluster with name CLUSTER_NAME
  modify-node: modify kind node with name NODE_NAME
  --pod-cidr: specifies pod cidr used in kind cluster, default is $POD_CIDR
  --antrea-cni: specifies use antrea or default cni in kind cluster, default is $ANTREA_CNI
  --num-workers: specifies number of worker nodes in kind cluster, default is $NUM_WORKERS
  --images: specifies images loaded to kind cluster, default is $IMAGES
  --subnetnets: sp0ecifies subnets and bridge networks used worker nodes, default is empty all worker
    connected to docker0 bridge network
"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 help' for more information."
}

function modify {
  node="$1"
  peerIdx=$(docker exec "$node" ip link | grep eth0 | awk -F[@:] '{ print $3 }' | cut -c 3-)
  peerName=$(docker run --net=host antrea/ethtool:latest ip link | grep ^"$peerIdx": | awk -F[:@] '{ print $2 }' | cut -c 2-)
  echo "Disabling TX checksum offload for node $node ($peerName)"
  docker run --net=host --privileged antrea/ethtool:latest ethtool -K "$peerName" tx off
}

function configure_networks {
  networks=$(docker network ls -f name=$CLUSTER_NAME --format '{{.Name}}')
  networks="$(echo $networks)"
  if [[ -z $SUBNETS ]] && [[ -z $networks ]]; then
    echo "Using default docker bridges"
    return
  fi

  # remove old networks
  nodes="$(kind get nodes --name $CLUSTER_NAME | grep worker)"
  nodes=$(echo $nodes)
  networks+=" bridge"
  echo "removing worker nodes $nodes from networks $networks"
  for n in $networks; do
    rm_nodes=$(docker network inspect $n --format '{{range $i, $conf:=.Containers}}{{$conf.Name}} {{end}}')
    for rn in $rm_nodes; do
      if [[  $nodes =~ $rn ]]; then
        docker network disconnect $n $rn > /dev/null 2>&1
        echo "disconnected worker $rn from network $n"
      fi
    done
    if [[ $n != "bridge" ]]; then
      docker network rm $n > /dev/null 2>&1
      echo "removed network $n"
    fi
  done

  # create new bridge network per subnet
  i=0
  networks=()
  for s in $SUBNETS; do
    network=$CLUSTER_NAME-$i
    docker network create -d bridge --subnet $s $network >/dev/null 2>&1
    echo "created network $network"
    networks+=($network)
    i=$((i+1))
  done

  num_networks=${#networks[@]}
  if [[ $num_networks -eq 0 ]]; then
    networks+=("bridge")
    num_networks=$((num_networks+1))
  fi

  i=0
  for node in $nodes; do
    network=${networks[i]}
    docker network connect $network $node >/dev/null 2>&1
    echo "connected worker $node to network $network"
    node_ip=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')
    docker exec -t $node sed -i "s/node-ip=.*/node-ip=$node_ip/g" /var/lib/kubelet/kubeadm-flags.env
    echo "change node ip to $node_ip"
    docker restart $node
    i=$((i+1))
    if [[ $i -ge $num_networks ]]; then
      i=0
    fi
  done

  # Inject allow all iptables to preempt docker bridge isolation rules
  if [[ ! -z $SUBNETS ]]; then
    sudo iptables -C DOCKER-USER -j ACCEPT > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      sudo iptables -I DOCKER-USER -j ACCEPT
    fi
  fi
}

function delete_networks {
  networks=$(docker network ls -f name=$CLUSTER_NAME --format '{{.Name}}')
  networks="$(echo $networks)"
  if [[ ! -z $networks ]]; then
    docker network rm $networks > /dev/null 2>&1
    echo "deleted networks $networks"
  fi
}

function load_images {
  set +e
  for img in $IMAGES; do
    docker image inspect $img > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      echoerr "docker image $img not found"
      continue
    fi
    kind load docker-image $img --name $CLUSTER_NAME > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      echoerr "docker image $img failed to load"
      continue
    fi
    echo "loaded image $img"
  done
  set -e
}

function create {
  if [[ -z $CLUSTER_NAME ]]; then
    erroerr "cluster-name not provided"
    exit 1
  fi

  set +e
  kind get clusters | grep $CLUSTER_NAME > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echoerr "cluster $CLUSTER_NAME already created"
    exit 0
  fi
  set -e

  config_file="/tmp/kind.yml"
  cat <<EOF > $config_file
kind: Cluster
apiVersion: kind.sigs.k8s.io/v1alpha3
networking:
  disableDefaultCNI: $ANTREA_CNI
  podSubnet: $POD_CIDR
nodes:
- role: control-plane
EOF
  for i in $(seq 1 $NUM_WORKERS); do
    echo -e "- role: worker" >> $config_file
  done
  kind create cluster --name $CLUSTER_NAME --config $config_file

  configure_networks
  load_images

  nodes="$(kind get nodes --name $CLUSTER_NAME)"
  nodes="$(echo $nodes)"
  for node in $nodes; do
    modify $node
  done

  if [[ $ANTREA_CNI == true ]]; then
    cmd=$(dirname $0)
    cmd+="/generate-manifest.sh"
    eval "$cmd --kind | kubectl apply -f -"
  fi
}

function destroy {
  if [[ -z $CLUSTER_NAME ]]; then
    erroerr "cluster-name not provided"
    exit 1
  fi
  kind delete cluster --name $CLUSTER_NAME
  delete_networks
}

while [[ $# -gt 0 ]]
 do
 key="$1"

  case $key in
    create)
      CLUSTER_NAME="$2"
      shift 2
      ;;
    destroy)
      CLUSTER_NAME="$2"
      destroy
      exit 0
      ;;
    modify-node)
      modify "$2"
      exit 0
      ;;
    --pod-cidr)
      POD_CIDR="$2"
      shift 2
      ;;
    --subnets)
      SUBNETS="$2"
      shift 2
      ;;
    --images)
      IMAGES="$2"
      shift 2
      ;;
    --antrea-cni)
      ANTREA_CNI="$2"
      shift 2
      ;;
    --num-workers)
      NUM_WORKERS="$2"
      shift 2
      ;;
    help)
      print_usage
      exit 0
      ;;
    *)    # unknown option
      echoerr "Unknown option $1"
      exit 1
      ;;
 esac
 done

create