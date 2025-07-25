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
ANTREA_IMAGES="antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest"
IMAGES=$ANTREA_IMAGES
ANTREA_CNI=false
ACTION=""
UNTIL_TIME_IN_MINS=""
POD_CIDR=""
SERVICE_CIDR=""
IP_FAMILY="ipv4"
NUM_WORKERS=2
SUBNETS=()
VLAN_SUBNETS=()
EXTRA_NETWORKS=""
ENCAP_MODE=""
PROXY=true
KUBE_PROXY_MODE="iptables"
PROMETHEUS=false
K8S_VERSION=""
KUBE_NODE_IPAM=true
DEPLOY_EXTERNAL_AGNHOST=false
DEPLOY_EXTERNAL_FRR=false
FLEXIBLE_IPAM=false
positional_args=()
options=()

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -eo pipefail
function echoerr {
    >&2 echo "$@"
}

_usage="
Usage: $0 create CLUSTER_NAME [--pod-cidr POD_CIDR] [--service-cidr SERVICE_CIDR] [--antrea-cni] [--num-workers NUM_WORKERS] [--images IMAGES] [--subnets SUBNETS] [--ip-family ipv4|ipv6|dual] [--k8s-version VERSION]
       $0 destroy CLUSTER_NAME
       $0 help
where:
  create: create a kind cluster with name CLUSTER_NAME.
  destroy: delete a kind cluster with name CLUSTER_NAME.
  --pod-cidr: specify pod cidr used in kind cluster, kind's default value will be used if empty.
  --service-cidr: specify service clusterip cidr used in kind cluster, kind's default value will be used if empty.
  --encap-mode: inter-node pod traffic encap mode, default is encap.
  --no-proxy: disable Antrea proxy.
  --no-kube-proxy: disable Kube proxy.
  --no-kube-node-ipam: disable NodeIPAM in kube-controller-manager.
  --antrea-cni: install Antrea CNI in Kind cluster; by default the cluster is created without a CNI installed.
  --prometheus: create RBAC resources for Prometheus, default is false.
  --num-workers: specify number of worker nodes in kind cluster, default is $NUM_WORKERS.
  --images: specify images loaded to kind cluster, default is $IMAGES.
  --subnets: a subnet creates a separate Docker bridge network (named 'antrea-<idx>') with the assigned subnet. A worker
    Node will be connected to one of those networks. Default is empty: all worker Nodes connected to the default Docker
    bridge network created by kind. For example, '--subnets 20.20.20.0/24,fd00:dead:beef::/64', '--subnets 20.20.20.0/24',
    '--subnets fd00:dead:beef::/64'. This option can be specified multiple times to create multiple networks.
  --vlan-subnets: specify the id and subnets of the VLAN to which all Nodes will be connected, in addition to the primary network.
    The IP expression of the subnet will be used as the gateway IP. For example, '--vlan-subnets 10=172.100.10.1/24,fd00:172:100:10::1/96,' means
    that a VLAN sub-interface will be created on the primary Docker bridge, and it will be assigned the 10.100.100.1/24 and fd00:172:100:10::1/96 addresses
    and vlan-id 10. This option can be specified multiple times.
  --extra-networks: an extra network creates a separate Docker bridge network (named 'antrea-<idx>') with the assigned
    subnet. All worker Nodes will be connected to all the extra networks, in addition to the default Docker bridge
    network. Note, '--extra-networks' and '--subnets' cannot be specified together.
  --ip-family: specify the ip-family for the kind cluster, default is $IP_FAMILY.
  --k8s-version: specify the Kubernetes version of the kind cluster, kind's default K8s version will be used if empty.
  --deploy-external-agnhost: deploy a container running agnhost as an external server for the cluster, default is $DEPLOY_EXTERNAL_AGNHOST.
  --deploy-external-frr: deploy a container running FRR as an external router for the cluster, default is $DEPLOY_EXTERNAL_FRR.
  --all: delete all kind clusters.
  --until: delete kind clusters that have been created before the specified duration.
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

function add_option {
  local option="$1"
  local action="$2"
  options+=("$option $action")
}

function docker_run_with_host_net {
  docker run --rm --net=host --privileged antrea/toolbox:latest "$@"
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
    for cmd in iptables ip6tables; do
      [[ "$IP_FAMILY" == "ipv4" ]] && [[ "$cmd" == "ip6tables" ]] && continue
      [[ "$IP_FAMILY" == "ipv6" ]] && [[ "$cmd" == "iptables" ]] && continue
      docker_run_with_host_net "$cmd" -C DOCKER-USER -j ACCEPT > /dev/null 2>&1
      if [[ $? -ne 0 ]]; then
        docker_run_with_host_net "$cmd" -I DOCKER-USER -j ACCEPT
      fi
    done
    set -e
  fi

  # remove old networks
  nodes="$(kind get nodes --name $CLUSTER_NAME | grep worker)"
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
  for subnet in $SUBNETS; do
    network=antrea-$i
    docker_network_args=("-d" "bridge")
    # append gateway_mode options based on Docker version
    if version_ge "$docker_version" "28.0.0"; then
      if [[ "$IP_FAMILY" != "ipv4" ]]; then
        docker_network_args+=("-o" "com.docker.network.bridge.gateway_mode_ipv6=nat-unprotected")
      fi
      if [[ "$IP_FAMILY" != "ipv6" ]]; then
        docker_network_args+=("-o" "com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected")
      fi
    fi
    # append --ipv6 option for IPv6 only
    if [[ "$IP_FAMILY" != "ipv4" ]]; then
      docker_network_args+=("--ipv6")
    fi

    IFS=',' read -ra subnet_array <<< "$subnet"
    for subnet in "${subnet_array[@]}"; do
      docker_network_args+=("--subnet" "$subnet")
    done

    echo "Creating docker network $network with args: ${docker_network_args[@]}"
    docker network create "${docker_network_args[@]}" $network >/dev/null 2>&1
    networks+=($network)
    i=$((i+1))
  done

  num_networks=${#networks[@]}
  if [[ $num_networks -eq 0 ]]; then
    networks+=("kind")
    num_networks=$((num_networks+1))
  fi

  control_plane_ip4=$(docker inspect $CLUSTER_NAME-control-plane --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')
  control_plane_ip6=$(docker inspect $CLUSTER_NAME-control-plane --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.GlobalIPv6Address}}{{end}}')

  i=0
  for node in $nodes; do
    network=${networks[i]}
    ifname="eth1"
    # the com.docker.network.endpoint.ifname label is only supported starting with Docker Engine v28
    # prior to that, the interface should be named "eth1" by default
    # note that providing an unsupported label does not generate an error
    docker network connect --driver-opt=com.docker.network.endpoint.ifname=$ifname $network $node
    echo "connected worker $node to network $network"
    node_ip4=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')
    node_ip6=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.GlobalIPv6Address}}{{end}}')
    node_ip6_prefix=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.GlobalIPv6PrefixLen}}{{end}}')

    # reset network
    docker exec -t $node ip link set $ifname down
    docker exec -t $node ip link set $ifname name eth0
    docker exec -t $node ip link set eth0 up
    # set IPv4 address and route for IPv4 only or dual stack
    if [[ "$IP_FAMILY" != "ipv6" ]]; then
      gateway4=$(echo "${node_ip4/%?/1}")
      docker exec -t "$node" ip route add default via "$gateway4"
      echo "node $node is ready with ip changed to $node_ip4 with gw $gateway4"
    fi
    # set IPv6 address and route for IPv6 only or dual stack
    if [[ "$IP_FAMILY" != "ipv4" ]]; then
      prefix_len="${node_ip6_prefix:-64}"
      docker exec -t "$node" ip -6 addr add "$node_ip6/$prefix_len" dev eth0
      gateway6=$(echo "$node_ip6" | sed -E 's/::[0-9a-fA-F]*$/::1/')
      docker exec -t "$node" ip -6 route add default via "$gateway6"
      echo "node $node is ready with ip changed to $node_ip6 with gw $gateway6"
    fi
    # remove IPv4 address for IPv6 only
    if [[ "$IP_FAMILY" == "ipv6" ]]; then
      docker exec -t "$node" ip addr del "$node_ip4" dev eth0
      echo "removed IPv4 addr from $node for IPv6 only"
    fi
    # generate internal IPs
    node_ips=""
    if [[ "$IP_FAMILY" == "dual" ]]; then
      node_ips="$node_ip4,$node_ip6"
    elif [[ "$IP_FAMILY" == "ipv4" ]]; then
      node_ips="$node_ip4"
    elif [[ "$IP_FAMILY" == "ipv6" ]]; then
      node_ips="$node_ip6"
    fi
    # change kubelet config before reset network
    docker exec -t $node sed -i "s/node-ip=.*/node-ip=$node_ips/g" /var/lib/kubelet/kubeadm-flags.env
    # this is needed to ensure that the worker node can still connect to the apiserver
    [[ "$IP_FAMILY" != "ipv6" ]] && docker exec -t $node bash -c "echo '$control_plane_ip4 $CLUSTER_NAME-control-plane' >> /etc/hosts"
    [[ "$IP_FAMILY" != "ipv4" ]] && docker exec -t $node bash -c "echo '$control_plane_ip6 $CLUSTER_NAME-control-plane' >> /etc/hosts"
    docker exec -t $node pkill kubelet
    # it's possible that kube-proxy is not running yet on some Nodes
    docker exec -t $node pkill kube-proxy || true
    i=$((i+1))
    if [[ $i -ge $num_networks ]]; then
      i=0
    fi
  done

  for node in $nodes; do
    node_ip4=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.IPAddress}}{{end}}')
    [[ "$IP_FAMILY" == "ipv6" ]] && node_ip4=""
    node_ip6=$(docker inspect $node --format '{{range $i, $conf:=.NetworkSettings.Networks}}{{$conf.GlobalIPv6Address}}{{end}}')

    echo "Waiting for node $node to be assigned InternalIP..."
    max_attempts=30
    attempt=0
    # verify the internal IPs
    while (( attempt < max_attempts )); do
      internal_ips=$(kubectl get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')

      ok4=true
      ok6=true
      [[ -n "$node_ip4" && "$internal_ips" != *"$node_ip4"* ]] && ok4=false
      [[ -n "$node_ip6" && "$internal_ips" != *"$node_ip6"* ]] && ok6=false

      if $ok4 && $ok6; then
        echo "Node $node is ready with expected internal IPs: $node_ip4 $node_ip6"
        break
      fi

      echo "Attempt $((++attempt)): got IPs [$internal_ips]"
      ! $ok4 && echo "Missing IPv4: $node_ip4"
      ! $ok6 && echo "Missing IPv6: $node_ip6"

      sleep 2
    done

    if (( attempt >= max_attempts )); then
        echo "Timeout waiting for node $node to have expected internal IPs: $node_ip4 $node_ip6"
        exit 1
      fi
  done

  nodes="$(kind get nodes --name $CLUSTER_NAME)"
  for node in $nodes; do
    # disable tx checksum offload
    # otherwise we observe that inter-Node tunnelled traffic crossing Docker networks is dropped
    # because of an invalid outer checksum.
    docker exec "$node" ethtool -K eth0 tx off
  done
}

function configure_extra_networks {
  if [[ -z $EXTRA_NETWORKS ]]; then
    return
  fi
  echo "Configuring extra networks"

  # create new bridge networks
  i=0
  networks=()
  for s in $EXTRA_NETWORKS ; do
    network=antrea-$i
    echo "creating network $network with $s"
    docker network create -d bridge --subnet $s $network >/dev/null 2>&1
    networks+=($network)
    i=$((i+1))
  done

  nodes="$(kind get nodes --name $CLUSTER_NAME)"
  for node in $nodes; do
    i=1
    for network in $networks; do
      ifname="eth$i"
      docker network connect --driver-opt=com.docker.network.endpoint.ifname=$ifname $network $node
      echo "connected worker $node to network $network"
    done
    i=$((i+1))
  done
}

# update_kind_ipam_routes add and del routes for non-ipam test-pods.
function update_kind_ipam_routes {
  local operation="$1"
  if [[ "$operation" == "del" ]]; then
    echo "Deleting routes"
  else  
    echo "Adding routes"
  fi

  node_data=$(kubectl get nodes -o jsonpath='{range .items[*]}{.spec.podCIDR}{" "}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' 2>/dev/null || true)
  if [[ -z $node_data ]]; then
    return
  fi
  echo "$node_data"| while read pod_cidr node_ip; do
    docker_run_with_host_net ip route "$operation" "$pod_cidr" via "$node_ip" >/dev/null 2>&1 || true
  done
}

function configure_vlan_subnets {
  if [[ ${#VLAN_SUBNETS[@]} -eq 0 ]]; then
    return
  fi
  echo "Configuring VLAN subnets"

  bridge_id=$(docker network inspect kind -f {{.ID}})
  bridge_interface="br-${bridge_id:0:12}"
  
  vlan_interfaces=()
  for vlan_subnet in "${VLAN_SUBNETS[@]}"; do
    # Extract VLAN ID and subnets
    vlan_id=$(echo $vlan_subnet | cut -d= -f1)
    subnets=$(echo $vlan_subnet | cut -d= -f2)
    
    vlan_interface="br-${bridge_id:0:7}.$vlan_id"
    vlan_interfaces+=("$vlan_interface")

    docker_run_with_host_net ip link add link $bridge_interface name $vlan_interface type vlan id $vlan_id
    docker_run_with_host_net ip link set $vlan_interface up
    
    IFS=',' read -r -a subnet_array <<< "$subnets"
    for subnet in "${subnet_array[@]}" ; do
      echo "Configuring extra IP $subnet to VLAN interface $vlan_interface"
      docker_run_with_host_net ip addr add dev $vlan_interface $subnet
    done

    docker_run_with_host_net iptables -t filter -A FORWARD -i $bridge_interface -o $vlan_interface -j ACCEPT
    docker_run_with_host_net iptables -t filter -A FORWARD -i $vlan_interface -o $bridge_interface -j ACCEPT
    docker_run_with_host_net iptables -t filter -A FORWARD -i $vlan_interface -o $vlan_interface -j ACCEPT
  done

  # Allow traffic between VLANs
  for ((i=0; i<${#vlan_interfaces[@]}; i++)); do
    for ((j=i+1; j<${#vlan_interfaces[@]}; j++)); do
      docker_run_with_host_net iptables -t filter -A FORWARD -i ${vlan_interfaces[i]} -o ${vlan_interfaces[j]} -j ACCEPT
      docker_run_with_host_net iptables -t filter -A FORWARD -i ${vlan_interfaces[j]} -o ${vlan_interfaces[i]} -j ACCEPT
    done
  done

  if [[ $FLEXIBLE_IPAM == true ]]; then
    docker_run_with_host_net ipset create excluded_subnets hash:net
    docker_run_with_host_net ipset add excluded_subnets 192.168.241.0/24
    docker_run_with_host_net ipset add excluded_subnets 192.168.242.0/24
    docker_run_with_host_net ipset add excluded_subnets 192.168.240.0/24
    docker_run_with_host_net ipset list excluded_subnets
    
    # Bypass default Docker SNAT rule for FlexibleIPAM traffic from the untagged subnet (192.168.240.0/24, which is the subnet for the Docker bridge network)
    # and destined to the VLAN subnets (192.168.241.0/24, 192.168.242.0/24).
    docker_run_with_host_net iptables -t nat -I POSTROUTING 1 ! -o $bridge_interface -s 192.168.240.0/24 -m set --match-set excluded_subnets dst -j RETURN

    # With FlexibleIPAM, Antrea SNAT is disabled (noSNAT: true) so Pods don't have access to the external network by default (including regular / NodeIPAM Pods).
    # Our e2e tests require external network access for regular Pods, so we need to add a custom SNAT rule.
    docker_run_with_host_net iptables -t nat -A POSTROUTING ! -o $bridge_interface -s 10.244.0.0/16 -m set ! --match-set excluded_subnets dst -j MASQUERADE
  fi
}

function delete_vlan_subnets {
  echo "Deleting VLAN subnets"

  bridge_id=$(docker network inspect kind -f {{.ID}})
  bridge_interface="br-${bridge_id:0:12}"
  vlan_interface_prefix="br-${bridge_id:0:7}."

  found_vlan_interfaces=$(docker_run_with_host_net ip -br link show type vlan | cut -d " " -f 1)
  for interface in $found_vlan_interfaces ; do
    if [[ $interface =~ ${vlan_interface_prefix}[0-9]+@${bridge_interface} ]]; then
      interface_name=${interface%@*}
      docker_run_with_host_net iptables -t filter -D FORWARD -i $bridge_interface -o $interface_name -j ACCEPT || true
      docker_run_with_host_net iptables -t filter -D FORWARD -o $bridge_interface -i $interface_name -j ACCEPT || true
      docker_run_with_host_net ip link del $interface_name
    fi
  done

  if [[ $FLEXIBLE_IPAM == true ]]; then
    docker_run_with_host_net iptables -t nat -D POSTROUTING ! -o $bridge_interface -s 192.168.240.0/24 -m set --match-set excluded_subnets dst -j RETURN || true
    docker_run_with_host_net iptables -t nat -D POSTROUTING ! -o $bridge_interface -s 10.244.0.0/16 -m set ! --match-set excluded_subnets dst -j MASQUERADE || true
    docker_run_with_host_net ipset destroy excluded_subnets || true  
  fi
}

function delete_network_by_filter {
  local networks=$(docker network ls -f name="$1" --format '{{.Name}}')
  if [[ -n $networks ]]; then
    docker network rm $networks > /dev/null 2>&1
    echo "Deleted networks: $networks"
  fi
}

function delete_networks {
  if [[ $FLEXIBLE_IPAM == true ]]; then
    delete_network_by_filter "kind"
  fi
  delete_network_by_filter "antrea"
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

  if [[ "$IP_FAMILY" != "ipv4" ]] && [[ "$IP_FAMILY" != "ipv6" ]] && [[ "$IP_FAMILY" != "dual" ]]; then
    echoerr "Invalid value for --ip-family \"$IP_FAMILY\", expected \"ipv4\", \"ipv6\", or \"dual\""
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
  kind get clusters | grep -x "$CLUSTER_NAME" > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echoerr "cluster $CLUSTER_NAME already created"
    exit 0
  fi
  set -e

  config_file="/tmp/kind.yml"
  cat <<EOF > $config_file
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: $POD_CIDR
  serviceSubnet: $SERVICE_CIDR
  ipFamily: $IP_FAMILY
  kubeProxyMode: $KUBE_PROXY_MODE
# it's to prevent inherit search domains from the host which slows down DNS resolution 
# and cause problems to IPv6 only clusters running on IPv4 host.
  dnsSearch: [] 
nodes:
- role: control-plane
EOF
  if [[ $KUBE_NODE_IPAM == false ]]; then
    cat <<EOF >> $config_file
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    controllerManager:
      extraArgs:
        controllers: "*,bootstrapsigner,tokencleaner,-nodeipam"
EOF
  fi
  for (( i=0; i<$NUM_WORKERS; i++ )); do
    echo -e "- role: worker" >> $config_file
  done

  # When only the control plane Node is provisioned (no worker Node),
  # we configure port mappings so that the Antrea Agent and Controller
  # running on the control plane Node can be easily accessed, including on macOS.
  # This is useful for accessing Antrea APIs. With worker Nodes, 
  # we don't configure these port mappings: in particular,
  # we wouldn't know on which Node the Controller is running.
  if [[ $NUM_WORKERS == 0 ]]; then
    echo -e "  extraPortMappings:\n  - containerPort: 10349\n    hostPort: 10349\n  - containerPort: 10350\n    hostPort: 10350" >> $config_file
  fi

  IMAGE_OPT=""
  if [[ "$K8S_VERSION" != "" ]]; then
    if [[ "$K8S_VERSION" != v* ]]; then
      K8S_VERSION="v${K8S_VERSION}"
    fi
    IMAGE_OPT="--image kindest/node:${K8S_VERSION}"
  fi

  flock ~/.antrea/.clusters.lock --command "echo \"$CLUSTER_NAME $(date +%s)\" >> ~/.antrea/.clusters"
  rm -rf ~/.antrea/.clusters.lock
  kind create cluster --name $CLUSTER_NAME --config $config_file $IMAGE_OPT

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
  configure_extra_networks
  configure_vlan_subnets
  setup_external_servers
  load_images
  if [[ $FLEXIBLE_IPAM == true ]]; then
      update_kind_ipam_routes "add"
  fi

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
    echo "waiting for K8s cluster readying"
    sleep 2
  done
}

function destroy {
  update_kind_ipam_routes "del"
  if [[ $UNTIL_TIME_IN_MINS != "" ]]; then
      if [[ -e ~/.antrea/.clusters ]]; then
          clean_kind
      fi
  else
      kind delete cluster --name $CLUSTER_NAME
  fi
  destroy_external_servers
  delete_vlan_subnets
  delete_networks
}

function printUnixTimestamp {
    runtimeOS="$(uname)"
    if [[ "$runtimeOS" == "Darwin" ]]; then
        echo $(date -ju -f "%Y-%m-%dT%H:%M:%SZ" "$1" "+%s")
    else
        echo $(date -d "$1" '+%s')
    fi
}

function setup_external_servers {
  if [[ $DEPLOY_EXTERNAL_AGNHOST == true ]]; then
    docker run -d --name antrea-external-agnhost-$RANDOM --network kind -it --rm registry.k8s.io/e2e-test-images/agnhost:2.40 netexec &> /dev/null
  fi

  if [[ $DEPLOY_EXTERNAL_FRR == true ]]; then
    docker run -d \
      --name antrea-external-frr-$RANDOM \
      --network kind --cap-add=NET_BIND_SERVICE \
      --cap-add=NET_ADMIN \
      --cap-add=NET_RAW \
      --cap-add=SYS_ADMIN \
      -it \
      --rm \
      frrouting/frr:v8.4.0 \
      bash -c "/bin/sed -i s/bgpd=no/bgpd=yes/g /etc/frr/daemons && /sbin/tini -- /usr/lib/frr/docker-start" &> /dev/null
    fi
}

function destroy_external_servers {
  echo "Deleting external servers"
  cid=$(docker ps -f name="^antrea-external-agnhost" --format '{{.ID}}')
  docker rm -f $cid &> /dev/null || true

  cid=$(docker ps -f name="^antrea-external-frr" --format '{{.ID}}')
  docker rm -f $cid &> /dev/null || true
}

function clean_kind {
    echo "=== Cleaning up stale kind clusters ==="
    (
      flock -x 200

      current_timestamp=$(date +%s)
      > ~/.antrea/.clusters.swp
      while IFS=' ' read -r name creationTimestamp; do
          if [[ -z "$name" || -z "$creationTimestamp" ]]; then
              continue
          fi
          # Calculate the time difference
          time_difference=$((current_timestamp - creationTimestamp))
          # Check if the creation happened more than 1 hour ago (3600 seconds)
          if (( time_difference > 3600 )); then
              echo "The creation of $name happened more than 1 hour ago."
              kind delete cluster --name "$name" || echo "Cluster could not be deleted"
          else
              echo "The creation of $name happened within the last hour."
              echo "$name $creationTimestamp" >> ~/.antrea/.clusters.swp
          fi
      done < ~/.antrea/.clusters
      mv ~/.antrea/.clusters.swp ~/.antrea/.clusters
    ) 200>>~/.antrea/.clusters.lock
    rm -rf ~/.antrea/.clusters.lock
}

if ! command -v kind &> /dev/null
then
    echoerr "kind could not be found"
    exit 1
fi

mkdir -p ~/.antrea

while [[ $# -gt 0 ]]
 do
 key="$1"

  case $key in
    create)
      ACTION="create"
      shift
      ;;
    destroy)
      ACTION="destroy"
      shift
      ;;
    --pod-cidr)
      add_option "--pod-cidr" "create"
      POD_CIDR="$2"
      shift 2
      ;;
    --service-cidr)
      add_option "--service-cidr" "create"
      SERVICE_CIDR="$2"
      shift 2
      ;;
    --ip-family)
      add_option "--ip-family" "create"
      IP_FAMILY="$2"
      shift 2
      ;;
    --encap-mode)
      add_option "--encap-mode" "create"
      ENCAP_MODE="$2"
      shift 2
      ;;
    --no-proxy)
      add_option "--no-proxy" "create"
      PROXY=false
      shift
      ;;
    --no-kube-proxy)
      add_option "--no-kube-proxy" "create"
      KUBE_PROXY_MODE="none"
      shift
      ;;
    --no-kube-node-ipam)
      add_option "--no-kube-node-ipam" "create"
      KUBE_NODE_IPAM=false
      shift
      ;;
    --prometheus)
      add_option "--prometheus" "create"
      PROMETHEUS=true
      shift
      ;;
    --subnets)
      add_option "--subnets" "create"
      SUBNETS+=("$2")
      shift 2
      ;;
    --extra-networks)
      add_option "--extra-networks" "create"
      EXTRA_NETWORKS="$2"
      shift 2
      ;;
    --vlan-subnets)
      add_option "--vlan-subnets" "create"
      VLAN_SUBNETS+=("$2")
      shift 2
      ;;
    --flexible-ipam)
      FLEXIBLE_IPAM=true
      shift
      ;; 
    --images)
      add_option "--image" "create"
      IMAGES="$2"
      shift 2
      ;;
    --antrea-cni)
      add_option "--antrea-cni" "create"
      ANTREA_CNI=true
      shift
      ;;
    --num-workers)
      add_option "--num-workers" "create"
      NUM_WORKERS="$2"
      shift 2
      ;;
    --k8s-version)
      add_option "--k8s-version" "create"
      K8S_VERSION="$2"
      shift 2
      ;;
    --deploy-external-agnhost)
      add_option "--deploy-external-agnhost" "create"
      DEPLOY_EXTERNAL_AGNHOST=true
      shift
      ;;
    --deploy-external-frr)
      add_option "--deploy-external-frr" "create"
      DEPLOY_EXTERNAL_FRR=true
      shift
      ;;
    --all)
      add_option "--all" "destroy"
      CLUSTER_NAME="*"
      shift
      ;;
    --until)
      add_option "--until" "destroy"
      UNTIL_TIME_IN_MINS="$2"
      shift 2
      ;;
    help)
      print_usage
      exit 0
      ;;
    -*)    # unknown option
      echoerr "Unknown option $1"
      exit 1
      ;;
    *)    # positional arg
      positional_args+=("$1")
      shift
      ;;
 esac
 done

for option in "${options[@]}"; do
    args=($option)
    name="${args[0]}"
    action="${args[1]}"
    if [[ "$action" != "$ACTION" ]]; then
        echoerr "Option '$name' cannot be used for '$ACTION'"
        exit 1
    fi
  done

if (( ${#positional_args[@]} > 1 )); then
    echoerr "Too many positional arguments, only expected one (cluster name)"
    exit 1
fi

if (( ${#positional_args[@]} == 1 )) && [[ "$CLUSTER_NAME" == "*" ]]; then
    echoerr "Cannot specify cluster name when using --all"
    exit 1
fi

if (( ${#positional_args[@]} == 1 )); then
    CLUSTER_NAME=${positional_args[0]}
fi

if [[ -z "$CLUSTER_NAME" ]]; then
    echoerr "Missing cluster name"
    exit 1
fi

if [[ $ACTION == "destroy" ]]; then
      destroy
      exit
fi

kind_version=$(kind version | awk  '{print $2}')
kind_version=${kind_version:1} # strip leading 'v'
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "")
function version_lt() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" != "$1"; }
function version_ge() { test "$(printf '%s\n' "$@" | sort -rV | head -n 1)" == "$1"; }
if version_lt "$kind_version" "0.12.0" && [[ "$KUBE_PROXY_MODE" == "none" ]]; then
    # This patch is required when using Antrea without kube-proxy:
    # https://github.com/kubernetes-sigs/kind/pull/2375
    echoerr "You have kind version v$kind_version installed"
    echoerr "You need to upgrade to kind >= v0.12.0 when disabling kube-proxy"
    exit 1
fi

if [[ $ACTION == "create" ]]; then
    if [[ ! -z $SUBNETS ]] && [[ ! -z $EXTRA_NETWORKS ]]; then
        echoerr "Only one of '--subnets' and '--extra-networks' can be specified"
        exit 1
    fi

    # Create the docker bridge network used as the primary network for the kind cluster. As long as
    # we use the expected name, kind will use our network.
    # We mostly replicate what is in:
    # https://github.com/kubernetes-sigs/kind/blob/180d624f741e3da5ceba52b643e29c4e64538537/pkg/cluster/internal/providers/docker/network.go#L149-L160
    # We also add some extra options required for our use case.
    docker_network_mtu=$(docker network inspect bridge -f '{{ index .Options "com.docker.network.driver.mtu" }}')
    docker_network_args=("-d" "bridge")
    docker_network_args+=("-o" "com.docker.network.bridge.enable_ip_masquerade=true")
    docker_network_args+=("-o" "com.docker.network.driver.mtu=$docker_network_mtu")
    # Use nat-unprotected to revert to the legacy default behavior (pre Docker Engine v28)
    # Without this, access to the K8s apiserver from Nodes using a non-default network will be
    # blocked because of port mapping hardening.
    # See https://www.docker.com/blog/docker-engine-28-hardening-container-networking-by-default/
    # While this is only required when we create extra docker networks, it's easier to use it
    # consistently. It is also better than modifying the iptables rules installed by docker.
    if version_ge "$docker_version" "28.0.0"; then
       docker_network_args+=("-o" "com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected")
    fi
    if [[ "$IP_FAMILY" != "ipv4" ]]; then
        if version_ge "$docker_version" "28.0.0"; then
            docker_network_args+=("-o" "com.docker.network.bridge.gateway_mode_ipv6=nat-unprotected")
        fi
        docker_network_args+=("--ipv6")
    fi
    if [[ $FLEXIBLE_IPAM == true ]]; then
        docker_network_args+=("--subnet" "192.168.240.0/24")
        docker_network_args+=("--gateway" "192.168.240.1")
        # Reserve IPs after 192.168.240.63 for e2e tests.
        docker_network_args+=("--ip-range" "192.168.240.0/26")
    fi
    echo "Creating docker network $CLUSTER_NAME with args: ${docker_network_args[@]}"
    docker network create "${docker_network_args[@]}" "$CLUSTER_NAME"
    create
fi
