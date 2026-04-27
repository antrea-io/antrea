#!/usr/bin/env bash

# Copyright 2024 Antrea Authors
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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--setup-only|--test-only|--cleanup-only] [--help|-h]
        --setup-only                  Only perform setting up the cluster and run test.
        --test-only                   Only run test on current cluster. Not set up/clean up the cluster.
        --cleanup-only                Only perform cleaning up the cluster.
        --help, -h                    Print this message and exit.
"

function print_usage {
    echoerr -n "$_usage"
}

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TESTBED_CMD=$THIS_DIR"/kind-setup.sh"
ATTACHMENT_DEFINITION_YAML=$THIS_DIR"/../../test/e2e-secondary-network/infra/network-attachment-definition-crd.yml"
SECONDARY_NETWORKS_YAML=$THIS_DIR"/../../test/e2e-secondary-network/infra/secondary-networks.yml"
ANTREA_NODE_CONFIGS_LINUX_YAML=$THIS_DIR"/../../test/e2e-secondary-network/infra/antrea-node-configs-linux.yml"
ANTREA_NODE_CONFIGS_NODEPOOL_YAML=$THIS_DIR"/../../test/e2e-secondary-network/infra/antrea-node-configs-nodepools.yml"
ANTREA_CHART="$THIS_DIR/../../build/charts/antrea"

# JSON for helm --set-json (keep in a single-quoted variable to avoid nested quote/EOF parse issues).
SECONDARY_OVS_BRIDGES_JSON='[{"bridgeName":"br-secondary","physicalInterfaces":["eth1"]}]'

TIMEOUT="5m"
# Antrea is deployed by this script. Do not deploy it again in the test.
ANTREA_LOG_DIR="${ANTREA_LOG_DIR:-${PWD}/log}"
mkdir -p "$ANTREA_LOG_DIR"
TEST_OPTIONS=(--logs-export-dir="$ANTREA_LOG_DIR" --deploy-antrea=false)
EXTRA_NETWORK="20.20.20.0/24"

# One control-plane plus this many workers (total nodes = NUM_WORKERS + 1).
NUM_WORKERS=3
# Label the first two and last two nodes (sorted by name) for pool scheduling tests.
NODEPOOL_LABEL_KEY="antrea.io/node-pool"

setup_only=false
cleanup_only=false
test_only=false

function quit {
  result=$?
  if [[ "$setup_only" == "true" || "$test_only" == "true" ]]; then
    exit $result
  fi
  echoerr "Cleaning testbed"
  $TESTBED_CMD destroy kind
}

function cleanup_stale_kind {
  echoerr "Cleaning up stale kind cluster and Docker networks if any"
  $TESTBED_CMD destroy kind 2>/dev/null || true
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --setup-only)
    setup_only=true
    shift
    ;;
    --cleanup-only)
    cleanup_only=true
    shift
    ;;
    --test-only)
    test_only=true
    shift
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)    # unknown option
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

if [[ $cleanup_only == "true" ]];then
  $TESTBED_CMD destroy kind
  exit 0
fi

# trap "quit" INT EXIT

IMAGE_LIST=("antrea/toolbox:1.5-1" \
            "antrea/antrea-agent-ubuntu:latest" \
            "antrea/antrea-controller-ubuntu:latest")

printf -v IMAGES "%s " "${IMAGE_LIST[@]}"

function setup_cluster {
  args=$1
  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind --ip-family dual $args"
}

function docker_bridge_for_network {
  local net_name="$1"
  local opt_name nid
  opt_name="$(docker network inspect "$net_name" -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || true)"
  if [[ -n "$opt_name" ]]; then
    echo "$opt_name"
    return 0
  fi
  nid="$(docker network inspect "$net_name" -f '{{.Id}}')"
  echo "br-${nid:0:12}"
}

# Docker 28+: --gw-priority (highest wins default GW). Use negative on secondary nets so Kind eth0 stays default.
function docker_network_connect_lab_iface {
  local ifname="$1" net="$2" node="$3"
  local -a args=(--driver-opt=com.docker.network.endpoint.ifname="$ifname")
  if docker network connect --help 2>&1 | grep -q '[[:space:]]--gw-priority[[:space:]]'; then
    args+=(--gw-priority -1000)
  fi
  docker network connect "${args[@]}" "$net" "$node"
}

# List interface names enslaved to a Linux bridge (same view as /sys/class/net/<br>/brif).
function kind_linux_bridge_port_names {
  local br="$1"
  ip link show master "$br" 2>/dev/null | sed -n 's/^[0-9]\+: \([^@[:space:]]\+\)@.*/\1/p'
}

# After Kind nodes are connected: program bridge self and each slave port for lab VLAN IDs.
# First VLAN in the list is the port PVID: untagged Docker / host RX maps to that VLAN (pvid).
# Do not use "untagged" on the PVID: that adds "Egress Untagged" in bridge vlan show and makes the
# lab VLAN egress untagged on the veth; we want trunk-style egress (tagged) while still classifying
# untagged RX to the lab VID. Remaining VLANs are tagged trunks only.
function kind_bridge_apply_lab_vlans {
  local br="$1"
  shift
  local -a vids=("$@")
  if [[ "${#vids[@]}" -eq 0 ]]; then
    return 0
  fi
  local pvid="${vids[0]}"
  local vid port

  bridge vlan add dev "$br" vid "$pvid" pvid self 2>/dev/null || true
  for vid in "${vids[@]}"; do
    [[ "$vid" == "$pvid" ]] && continue
    bridge vlan add dev "$br" vid "$vid" self 2>/dev/null || true
  done
  while IFS= read -r port; do
    [[ -n "$port" ]] || continue
    bridge vlan add dev "$port" vid "$pvid" pvid 2>/dev/null || true
    for vid in "${vids[@]}"; do
      [[ "$vid" == "$pvid" ]] && continue
      bridge vlan add dev "$port" vid "$vid" 2>/dev/null || true
    done
  done < <(kind_linux_bridge_port_names "$br")

  # With vlan_filtering enabled, the kernel / Docker typically leaves VID 1 as egress-untagged on
  # bridge ports even after we set the lab PVID (100/300). Remove VID 1 when the lab PVID is not 1.
  if [[ "$pvid" -ne 1 ]]; then
    bridge vlan del dev "$br" vid 1 self 2>/dev/null || true
    while IFS= read -r port; do
      [[ -n "$port" ]] || continue
      bridge vlan del dev "$port" vid 1 2>/dev/null || true
    done < <(kind_linux_bridge_port_names "$br")
  fi
}

function prepare_cluster_nodes {
  # This is for testing AntreaNodeConfigs with label selector support.
  echo "Removing control-plane NoSchedule taint so Pods can schedule on control-plane Nodes"
  for n in $(kubectl get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    kubectl taint nodes "$n" node-role.kubernetes.io/control-plane:NoSchedule- 2>/dev/null || true
    kubectl taint nodes "$n" node-role.kubernetes.io/master:NoSchedule- 2>/dev/null || true
  done

  echo "Labeling two Nodes with ${NODEPOOL_LABEL_KEY}=pool1 and two with ${NODEPOOL_LABEL_KEY}=pool2"
  mapfile -t _sn_nodes < <(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | LC_ALL=C sort)
  if [[ "${#_sn_nodes[@]}" -lt 4 ]]; then
    echoerr "Expected at least 4 Nodes for pool labeling, got ${#_sn_nodes[@]}"
    exit 1
  fi
  kubectl label node "${_sn_nodes[0]}" "${NODEPOOL_LABEL_KEY}=pool1" --overwrite
  kubectl label node "${_sn_nodes[1]}" "${NODEPOOL_LABEL_KEY}=pool1" --overwrite
  kubectl label node "${_sn_nodes[2]}" "${NODEPOOL_LABEL_KEY}=pool2" --overwrite
  kubectl label node "${_sn_nodes[3]}" "${NODEPOOL_LABEL_KEY}=pool2" --overwrite
}

function run_test {
  echo "Deploying Antrea to the kind cluster"
  # Create a secondary OVS bridge with the Node's physical interface on the extra
  # network. Use upgrade --install so --test-only re-runs do not fail when the
  # release already exists.
  helm upgrade --install antrea "$ANTREA_CHART" --namespace kube-system \
     --set featureGates.SecondaryNetwork=true,featureGates.AntreaIPAM=true \
     --set-json secondaryNetwork.ovsBridges="$SECONDARY_OVS_BRIDGES_JSON"

  echo "Waiting for all Nodes to be Ready"
  kubectl wait --for=condition=Ready nodes --all --timeout=10m

  # Wait for antrea-controller start to make sure the IPPool validation webhook is ready.
  kubectl rollout status --timeout=1m deployment.apps/antrea-controller -n kube-system
  # An extra small delay to reduce the possibility of failure in CI.
  sleep 5
  kubectl apply -f "$ATTACHMENT_DEFINITION_YAML"
  kubectl apply -f "$SECONDARY_NETWORKS_YAML"

  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network -run=TestVLANNetwork -provider=kind "${TEST_OPTIONS[@]}"
  run_test_with_antrenodeconfigs
}

# Lab-style VLAN-aware bridges: create Docker bridge networks (Docker owns the Linux bridge), enable
# vlan_filtering on those bridges, connect every Kind node container with fixed interface names eth2/eth3,
# then program bridge VLAN on bridge self and each veth. Requires root for ip/bridge;
# Assumes eth2/eth3 are free inside nodes (single antrea-<cluster>-0 extra net → only eth1 in use).
function kind_extra_network_with_vlan_awareness_bridges {
  # Union of VLAN IDs referenced in test/e2e-secondary-network/infra/antrea-node-configs-nodepools.yml
  # (pool1 eth2: 100,101; pool1 eth3: 300; pool2 eth2: 100; pool2 eth3: 400).
  KIND_EXTRA_BRIDGE_1_VLAN_IDS=(100 101) # eth2
  KIND_EXTRA_BRIDGE_2_VLAN_IDS=(300 400) # eth3
  # Kind cluster name passed to kind-setup.sh create (must match docker networks antrea-<name>-<idx>).
  KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"

  if [[ "$(id -u)" -ne 0 ]]; then
    echoerr "kind_extra_network_with_vlan_awareness_bridges requires root (sudo)."
    return 1
  fi

  local net_eth2="kind-vlan-lab-eth2"
  local net_eth3="kind-vlan-lab-eth3"

  if ! docker network inspect "$net_eth2" &>/dev/null; then
    docker network create -d bridge \
      --subnet="20.20.21.0/24" \
      --gateway="20.20.21.1" \
      "$net_eth2"
  fi
  if ! docker network inspect "$net_eth3" &>/dev/null; then
    docker network create -d bridge \
      --subnet="20.20.22.0/24" \
      --gateway="20.20.22.1" \
      "$net_eth3"
  fi

  local br_eth2 br_eth3
  br_eth2="$(docker_bridge_for_network "$net_eth2")"
  br_eth3="$(docker_bridge_for_network "$net_eth3")"
  
  ip link set "$br_eth2" up 2>/dev/null
  ip link set "$br_eth3" up 2>/dev/null
  ip link set "$br_eth2" type bridge vlan_filtering 1
  ip link set "$br_eth3" type bridge vlan_filtering 1

  local node node_nets
  for node in $(kind get nodes --name "$KIND_CLUSTER_NAME"); do
    node_nets="$(docker inspect "$node" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)"
    if [[ " ${node_nets} " != *" ${net_eth2} "* ]]; then
      docker_network_connect_lab_iface eth2 "$net_eth2" "$node"
      echo "connected $node to Docker network $net_eth2 as eth2"
    else
      echo "$node already on $net_eth2"
    fi
    node_nets="$(docker inspect "$node" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)"
    if [[ " ${node_nets} " != *" ${net_eth3} "* ]]; then
      docker_network_connect_lab_iface eth3 "$net_eth3" "$node"
      echo "connected $node to Docker network $net_eth3 as eth3"
    else
      echo "$node already on $net_eth3"
    fi
  done

  kind_bridge_apply_lab_vlans "$br_eth2" "${KIND_EXTRA_BRIDGE_1_VLAN_IDS[@]}"
  kind_bridge_apply_lab_vlans "$br_eth3" "${KIND_EXTRA_BRIDGE_2_VLAN_IDS[@]}"
}

function run_test_with_antrenodeconfigs {
  echo "Start testing AntreaNodeConfig with label selector support"
  echo "Applying AntreaNodeConfig for Linux nodes with a new secondary OVS bridge name br1"
  kubectl apply -f "$ANTREA_NODE_CONFIGS_LINUX_YAML"
  sleep 5
  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network -run=TestVLANNetwork -provider=kind "${TEST_OPTIONS[@]}"
  echo "Clean up the previous AntreaNodeConfig"
  kubectl delete -f "$ANTREA_NODE_CONFIGS_LINUX_YAML"
  sleep 5
  kind_extra_network_with_vlan_awareness_bridges
  echo "Apply new AntreaNodeConfigs for NodePool 1 and NodePool 2 nodes"
  kubectl apply -f "$ANTREA_NODE_CONFIGS_NODEPOOL_YAML"
  sleep 5
  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network \
    -run='TestNodePoolsVLANNetwork' -provider=kind "${TEST_OPTIONS[@]}"
}

echo "======== Testing Antrea-native secondary network support =========="
if [[ "$test_only" == "false" ]];then
  cleanup_stale_kind
  setup_cluster "--extra-networks \"$EXTRA_NETWORK\" --images \"$IMAGES\" --num-workers $NUM_WORKERS"
fi
prepare_cluster_nodes
run_test
exit 0
