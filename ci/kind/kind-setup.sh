#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
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

# The script creates and deletes kind testbeds. Kind testbeds may be created with
# docker images preloaded, antrea-cni preloaded, antrea-cni's encapsulation mode,
# and docker bridge network connecting to worker Node.

CLUSTER_NAME=""
ANTREA_IMAGE="projects.registry.vmware.com/antrea/antrea-ubuntu:latest"
IMAGES=$ANTREA_IMAGE
ANTREA_CNI=false
POD_CIDR="10.10.0.0/16"
IP_FAMILY="ipv4"
NUM_WORKERS=2
SUBNETS=""
ENCAP_MODE=""
PROXY=true
KUBE_PROXY_MODE="iptables"
PROMETHEUS=false

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -eo pipefail
function echoerr {
    >&2 echo "$@"
}

_usage="
Usage: $0 create CLUSTER_NAME [--pod-cidr POD_CIDR] [--antrea-cni] [--num-workers NUM_WORKERS] [--images IMAGES] [--subnets SUBNETS] [--ip-family ipv4|ipv6]
                  destroy CLUSTER_NAME
                  help
where:
  create: create a kind cluster with name CLUSTER_NAME
  destroy: delete a kind cluster with name CLUSTER_NAME
  --pod-cidr: specifies pod cidr used in kind cluster, default is $POD_CIDR
  --encap-mode: inter-node pod traffic encap mode, default is encap
  --no-proxy: disable Antrea proxy
  --no-kube-proxy: disable Kube proxy
  --antrea-cni: install Antrea CNI in Kind cluster; by default the cluster is created without a CNI installed
  --prometheus: create RBAC resources for Prometheus, default is false
  --num-workers: specifies number of worker nodes in kind cluster, default is $NUM_WORKERS
  --images: specifies images loaded to kind cluster, default is $IMAGES
  --subnets: a subnet creates a separate docker bridge network (named 'antrea-<idx>') with assigned subnet that worker nodes may connect to. Default is empty: all worker
    Node connected to default docker bridge network created by Kind.
  --ip-family: specifies the ip-family for the kind cluster, default is $IP_FAMILY. A valid pod-cidr must be configured in the same family
"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 help' for more information."
}

function get_encap_mode {
  if [[ $ENCAP_MODE == "" ]]; then
    echo ""
    return
  fi
  echo "--encap-mode $ENCAP_MODE"
}

function configure_networks {
  echo "Configuring networks"
  networks=$(docker network ls -f name=antrea --format '{{.Name}}')
  networks="$(echo $networks)"
  if [[ -z $SUBNETS ]] && [[ -z $networks ]]; then
    echo "Using default kind docker network"
    return
  fi

  # Inject allow all iptables to preempt docker bridge isolation rules
  if [[ ! -z $SUBNETS ]]; then
    set +e
    docker run --net=host --privileged antrea/ethtool:latest iptables -C DOCKER-USER -j ACCEPT > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      docker run --net=host --privileged antrea/ethtool:latest iptables -I DOCKER-USER -j ACCEPT
    fi
    set -e
  fi

  # remove old networks
  nodes="$(kind get nodes --name $CLUSTER_NAME | grep worker)"
  node_cnt=$(kind get nodes --name $CLUSTER_NAME | grep worker | wc -l)
  nodes=$(echo $nodes)
  networks+=" kind"
  echo "removing worker nodes $nodes from networks $networks"
  for n in $networks; do
    rm_nodes=$(docker network inspect $n --format '{{range $i, $conf:=.Containers}}{{$conf.Name}} {{end}}')
    for rn in $rm_nodes; do
      if [[  $nodes =~ $rn ]]; then
        docker network disconnect $n $rn > /dev/null 2>&1
        echo "disconnected worker $rn from network $n"
      fi
    done
    if [[ $n != "kind" ]]; then
      docker network rm $n > /dev/null 2>&1
      echo "removed network $n"
    fi
  done

  # create new bridge network per subnet
  i=0
  networks=()
  for s in $SUBNETS; do
    network=antrea-$i
    echo "creating network $network with $s"
    docker network create -d bridge --subnet $s $network >/dev/null 2>&1
    networks+=($network)
    i=$((i+1))
  done

  num_networks=${#networks[@]}
  if [[ $num_networks -eq 0 ]]; then
    networks+=("kind")
    num_networks=$((num_networks+1))
  fi

  control_plane_ip=$(docker inspect $CLUSTER_NAME-control-plane --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')

  i=0
  for node in $nodes; do
    network=${networks[i]}
    docker network connect $network $node >/dev/null 2>&1
    echo "connected worker $node to network $network"
    node_ip=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')

    # reset network
    docker exec -t $node ip link set eth1 down
    docker exec -t $node ip link set eth1 name eth0
    docker exec -t $node ip link set eth0 up
    gateway=$(echo "${node_ip/%?/1}")
    docker exec -t $node ip route add default via $gateway
    echo "node $node is ready with ip change to $node_ip with gw $gateway"

    # change kubelet config before reset network
    docker exec -t $node sed -i "s/node-ip=.*/node-ip=$node_ip/g" /var/lib/kubelet/kubeadm-flags.env
    # this is needed to ensure that the worker node can still connect to the apiserver
    docker exec -t $node bash -c "echo '$control_plane_ip $CLUSTER_NAME-control-plane' >> /etc/hosts"
    docker exec -t $node pkill kubelet
    # it's possible that kube-proxy is not running yet on some Nodes
    docker exec -t $node pkill kube-proxy || true
    i=$((i+1))
    if [[ $i -ge $num_networks ]]; then
      i=0
    fi
  done

  for node in $nodes; do
    node_ip=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')
    while true; do
      tmp_ip=$(kubectl describe node $node | grep InternalIP)
      if [[ "$tmp_ip" == *"$node_ip"* ]]; then
        break
      fi
      echo "current ip $tmp_ip, wait for new node ip $node_ip"
      sleep 2
    done
  done

  nodes="$(kind get nodes --name $CLUSTER_NAME)"
  nodes="$(echo $nodes)"
  for node in $nodes; do
    # disable tx checksum offload
    # otherwise we observe that inter-Node tunnelled traffic crossing Docker networks is dropped
    # because of an invalid outer checksum.
    docker exec "$node" ethtool -K eth0 tx off
  done
}

function delete_networks {
  networks=$(docker network ls -f name=antrea --format '{{.Name}}')
  networks="$(echo $networks)"
  if [[ ! -z $networks ]]; then
    docker network rm $networks > /dev/null 2>&1
    echo "deleted networks $networks"
  fi
}

function load_images {
  echo "load images"
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
    echoerr "cluster-name not provided"
    exit 1
  fi

  # Having a simple validation check for now.
  # TODO: Making this comprehensive check confirming with rfc1035/rfc1123
  if [[ "$CLUSTER_NAME" =~ [^a-z0-9-] ]]; then
     echoerr "Invalid string. Conform to rfc1035/rfc1123"
     exit 1
  fi

  if [[ "$IP_FAMILY" != "ipv4" ]] && [[ "$IP_FAMILY" != "ipv6" ]]; then
    echoerr "Invalid value for --ip-family \"$IP_FAMILY\", expected \"ipv4\" or \"ipv6\""
    exit 1
  fi

  if [[ $ANTREA_CNI != true ]] && [[ $PROMETHEUS == true ]]; then
    echoerr "Cannot use --prometheus without --antrea-cni"
    exit 1
  fi

  if [[ $ANTREA_CNI != true ]] && [[ $ENCAP_MODE != "" ]]; then
    echoerr "Using --encap-mode without --antrea-cni has no effect"
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
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
  NetworkPolicyEndPort: true
networking:
  disableDefaultCNI: true
  podSubnet: $POD_CIDR
  ipFamily: $IP_FAMILY
  kubeProxyMode: $KUBE_PROXY_MODE
nodes:
- role: control-plane
EOF
  for (( i=0; i<$NUM_WORKERS; i++ )); do
    echo -e "- role: worker" >> $config_file
  done
  kind create cluster --name $CLUSTER_NAME --config $config_file

  # force coredns to run on control-plane node because it
  # is attached to kind bridge and uses host dns.
  # Worker Node may be configured to attach to custom bridges
  # which use dockerd as dns, causing coredns to detect
  # dns loop and crash
  patch=$(cat <<EOF
spec:
  template:
    spec:
      nodeSelector:
        kubernetes.io/hostname: $CLUSTER_NAME-control-plane
EOF
)
  kubectl patch deployment coredns -p "$patch" -n kube-system

  configure_networks
  load_images

  if [[ $ANTREA_CNI == true ]]; then
    cmd=$(dirname $0)
    cmd+="/../../hack/generate-manifest.sh"
    if [[ $PROXY == false ]]; then
      cmd+=" --no-proxy"
    fi
    echo "$cmd $(get_encap_mode) | kubectl apply --context kind-$CLUSTER_NAME -f -"
    eval "$cmd $(get_encap_mode) | kubectl apply --context kind-$CLUSTER_NAME -f -"

    if [[ $PROMETHEUS == true ]]; then
      kubectl apply --context kind-$CLUSTER_NAME -f $THIS_DIR/../../build/yamls/antrea-prometheus-rbac.yml
    fi
  fi

  # wait for cluster info
  while [[ -z $(kubectl cluster-info dump | grep cluster-cidr) ]]; do
    echo "waiting for k8s cluster readying"
    sleep 2
  done
}

function destroy {
  if [[ -z $CLUSTER_NAME ]]; then
    echoerr "cluster-name not provided"
    exit 1
  fi
  kind delete cluster --name $CLUSTER_NAME
  delete_networks
}

if ! command -v kind &> /dev/null
then
    echoerr "kind could not be found"
    exit 1
fi

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
    --pod-cidr)
      POD_CIDR="$2"
      shift 2
      ;;
    --ip-family)
      IP_FAMILY="$2"
      shift 2
      ;;
    --encap-mode)
      ENCAP_MODE="$2"
      shift 2
      ;;
    --no-proxy)
      PROXY=false
      shift
      ;;
    --no-kube-proxy)
      KUBE_PROXY_MODE="none"
      shift
      ;;
    --prometheus)
      PROMETHEUS=true
      shift
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
      ANTREA_CNI=true
      shift
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

kind_version=$(kind version | awk  '{print $2}')
kind_version=${kind_version:1} # strip leading 'v'
function version_lt() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" != "$1"; }
if version_lt "$kind_version" "0.12.0" && [[ "$KUBE_PROXY_MODE" == "none" ]]; then
    # This patch is required when using Antrea without kube-proxy:
    # https://github.com/kubernetes-sigs/kind/pull/2375
    echoerr "You have kind version v$kind_version installed"
    echoerr "You need to upgrade to kind >= v0.12.0 when disabling kube-proxy"
    exit 1
fi

create
