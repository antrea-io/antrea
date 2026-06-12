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
# Subnets for extra Docker bridge networks: eth1 (static bridge), eth2 & eth3 (VLAN-tagged bridges).
EXTRA_NETWORKS="20.20.20.0/24 20.20.21.0/24 20.20.22.0/24"

NUM_WORKERS=3
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

trap "quit" INT EXIT

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

# List interface names enslaved to a Linux bridge (same view as /sys/class/net/<br>/brif).
function kind_linux_bridge_port_names {
  local br="$1"
  ip link show master "$br" 2>/dev/null | sed -n 's/^[0-9]\+: \([^@[:space:]]\+\)@.*/\1/p'
}

# Apply VLAN configuration to the bridge device and every slave port.
# The first VLAN ID is the PVID (untagged ingress); remaining VLANs are tagged trunks.
# VID 1 is removed unless it is the PVID, since the kernel leaves it as egress-untagged
# by default even after vlan_filtering is enabled.
function kind_bridge_apply_vlans {
  local br="$1"
  shift
  local -a vids=("$@")
  if [[ "${#vids[@]}" -eq 0 ]]; then
    return 0
  fi
  local pvid="${vids[0]}"
  local vid dev self_flag

  for dev in "$br" $(kind_linux_bridge_port_names "$br"); do
    [[ -n "$dev" ]] || continue
    if [[ "$dev" == "$br" ]]; then
      self_flag="self"
    else
      self_flag=""
    fi
    sudo bridge vlan add dev "$dev" vid "$pvid" pvid $self_flag 2>/dev/null || true
    for vid in "${vids[@]}"; do
      [[ "$vid" == "$pvid" ]] && continue
      sudo bridge vlan add dev "$dev" vid "$vid" $self_flag 2>/dev/null || true
    done
    if [[ "$pvid" -ne 1 ]]; then
      sudo bridge vlan del dev "$dev" vid 1 $self_flag 2>/dev/null || true
    fi
  done
}

function prepare_cluster_nodes {
  # Allow Pods to schedule on control-plane Nodes for pool testing.
  echo "Removing control-plane NoSchedule taint"
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

# VLAN bridge configuration: configure_extra_networks (kind-setup.sh) has already created
# Docker bridge networks antrea-<cluster>-1 (eth2) and antrea-<cluster>-2 (eth3) and connected
# every Kind node.  This function enables vlan_filtering on the underlying Linux bridges and
# programs per-port VLANs so that the ANC-per-interface allowedVLANs test exercises real
# VLAN filtering.  Requires root (sudo ip link / bridge).
function configure_vlan_bridges {
  local cluster_name="${KIND_CLUSTER_NAME:-kind}"
  local net_eth2="antrea-${cluster_name}-1"
  local net_eth3="antrea-${cluster_name}-2"


  local br_eth2 br_eth3
  br_eth2="$(docker_bridge_for_network "$net_eth2")"
  br_eth3="$(docker_bridge_for_network "$net_eth3")"

  sudo ip link set "$br_eth2" type bridge vlan_filtering 1
  sudo ip link set "$br_eth3" type bridge vlan_filtering 1

  # VLAN IDs from antrea-node-configs-nodepools.yml:
  #   pool1 eth2: 100,101; pool1 eth3: 300
  #   pool2 eth2: 100;     pool2 eth3: 400
  kind_bridge_apply_vlans "$br_eth2" 100 101
  kind_bridge_apply_vlans "$br_eth3" 300 400
}

function run_test_with_antrenodeconfigs {
  echo "Start testing AntreaNodeConfig with label selector support"
  echo "Applying AntreaNodeConfig for Linux nodes with a new secondary OVS bridge name br1"
  kubectl apply -f "$ANTREA_NODE_CONFIGS_LINUX_YAML"
  sleep 5
  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network -run=TestVLANNetwork -provider=kind "${TEST_OPTIONS[@]}"

  echo "Modifying multicast-snooping under the same bridge name"
  kubectl patch antreanodeconfig secondary-network-node-pool-all-linux --type=merge -p '{"spec":{"secondaryNetwork":{"ovsBridges":[{"bridgeName":"br1","enableMulticastSnooping":true,"physicalInterfaces":[{"name":"eth1"}]}]}}}'
  sleep 5
  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network -run=TestVLANNetwork -provider=kind "${TEST_OPTIONS[@]}"

  echo "Clean up the previous AntreaNodeConfig"
  kubectl delete -f "$ANTREA_NODE_CONFIGS_LINUX_YAML"
  sleep 5

  echo "Verifying fallback to static config after AntreaNodeConfig deletion"
  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network -run=TestVLANNetwork -provider=kind "${TEST_OPTIONS[@]}"

  configure_vlan_bridges
  echo "Apply new AntreaNodeConfigs for NodePool 1 and NodePool 2 nodes"
  kubectl apply -f "$ANTREA_NODE_CONFIGS_NODEPOOL_YAML"
  sleep 5
  go test -v -timeout="$TIMEOUT" antrea.io/antrea/v2/test/e2e-secondary-network \
    -run='TestNodePoolsVLANNetwork' -provider=kind "${TEST_OPTIONS[@]}"
}

echo "======== Testing Antrea-native secondary network support =========="
if [[ "$test_only" == "false" ]];then
  cleanup_stale_kind
  setup_cluster "--extra-networks \"$EXTRA_NETWORKS\" --images \"$IMAGES\" --num-workers $NUM_WORKERS"
fi
prepare_cluster_nodes
run_test
exit 0
