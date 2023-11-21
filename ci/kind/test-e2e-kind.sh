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

# The script runs kind e2e tests with different traffic encapsulation modes.

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

_usage="Usage: $0 [--encap-mode <mode>] [--ip-family <v4|v6|dual>] [--coverage] [--help|-h]
        --encap-mode                  Traffic encapsulation mode. (default is 'encap').
        --ip-family                   Configures the ipFamily for the KinD cluster.
        --feature-gates               A comma-separated list of key=value pairs that describe feature gates, e.g. AntreaProxy=true,Egress=false.
        --run                         Run only tests matching the regexp.
        --proxy-all                   Enables Antrea proxy with all Service support.
        --load-balancer-mode          LoadBalancer mode.
        --node-ipam                   Enables Antrea NodeIPAN.
        --multicast                   Enables Multicast.
        --flow-visibility             Only run flow visibility related e2e tests.
        --extra-network               Creates an extra network that worker Nodes will connect to. Cannot be specified with the hybrid mode.
        --extra-vlan                  Creates an subnet-based VLAN that worker Nodes will connect to.
        --deploy-external-server      Deploy a container running as an external server for the cluster.
        --skip                        A comma-separated list of keywords, with which tests should be skipped.
        --coverage                    Enables measure Antrea code coverage when run e2e tests on kind.
        --setup-only                  Only perform setting up the cluster and run test.
        --cleanup-only                Only perform cleaning up the cluster.
        --test-only                   Only run test on current cluster. Not set up/clean up the cluster.
        --help, -h                    Print this message and exit.
"

function print_usage {
    echoerr -n "$_usage"
}


THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TESTBED_CMD="$THIS_DIR/kind-setup.sh"
YML_CMD="$THIS_DIR/../../hack/generate-manifest.sh"
FLOWAGGREGATOR_YML_CMD="$THIS_DIR/../../hack/generate-manifest-flow-aggregator.sh"
FLOW_VISIBILITY_HELM_VALUES="$THIS_DIR/values-flow-exporter.yml"
CH_OPERATOR_YML="$THIS_DIR/../../build/yamls/clickhouse-operator-install-bundle.yml"
FLOW_VISIBILITY_CHART="$THIS_DIR/../../test/e2e/charts/flow-visibility"

function quit {
  result=$?
  if [[ "$setup_only" = true || "$test_only" = true ]]; then
    exit $result
  fi
  echoerr "Cleaning testbed"
  $TESTBED_CMD destroy kind
}

mode=""
ipfamily="v4"
feature_gates=""
proxy_all=false
load_balancer_mode=""
node_ipam=false
multicast=false
flow_visibility=false
extra_network=false
extra_vlan=false
deploy_external_server=false
coverage=false
skiplist=""
setup_only=false
cleanup_only=false
test_only=false
run=""
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --run)
    run="$2"
    shift 2
    ;;
    --feature-gates)
    feature_gates="$2"
    shift 2
    ;;
    --proxy-all)
    proxy_all=true
    shift
    ;;
    --load-balancer-mode)
    load_balancer_mode="$2"
    shift 2
    ;;
    --node-ipam)
    node_ipam=true
    shift
    ;;
    --multicast)
    multicast=true
    shift
    ;;
    --ip-family)
    ipfamily="$2"
    shift 2
    ;;
    --flow-visibility)
    flow_visibility=true
    shift
    ;;
    --encap-mode)
    mode="$2"
    shift 2
    ;;
    --extra-network)
    extra_network=true
    shift
    ;;
    --extra-vlan)
    extra_vlan=true
    shift
    ;;
    --deploy-external-server)
    deploy_external_server=true
    shift
    ;;
    --coverage)
    coverage=true
    shift
    ;;
    --skip)
    skiplist="$2"
    shift 2
    ;;
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

source $THIS_DIR/../../hack/verify-helm.sh

if [ -z "$HELM" ]; then
    HELM="$(verify_helm)"
elif ! $HELM version > /dev/null 2>&1; then
    echoerr "$HELM does not appear to be a valid helm binary"
    print_help
    exit 1
fi

if $extra_network && [[ "$mode" == "hybrid" ]]; then
    echoerr "--extra-network cannot be specified with hybrid mode"
    exit 1
fi

if [[ $cleanup_only == "true" ]];then
  $TESTBED_CMD destroy kind
  exit 0
fi

trap "quit" INT EXIT

manifest_args="$manifest_args --verbose-log"
if [ -n "$feature_gates" ]; then
  manifest_args="$manifest_args --feature-gates $feature_gates"
fi
if $proxy_all; then
    manifest_args="$manifest_args --proxy-all"
fi
if [ -n "$load_balancer_mode" ]; then
    manifest_args="$manifest_args --extra-helm-values antreaProxy.defaultLoadBalancerMode=$load_balancer_mode"
fi
if $node_ipam; then
    manifest_args="$manifest_args --extra-helm-values nodeIPAM.enable=true,nodeIPAM.clusterCIDRs={10.244.0.0/16}"
fi
if $multicast; then
    manifest_args="$manifest_args --multicast"
fi
if $flow_visibility; then
    manifest_args="$manifest_args --feature-gates FlowExporter=true,L7FlowExporter=true --extra-helm-values-file $FLOW_VISIBILITY_HELM_VALUES"
fi

COMMON_IMAGES_LIST=("registry.k8s.io/e2e-test-images/agnhost:2.29" \
                    "projects.registry.vmware.com/antrea/busybox"  \
                    "projects.registry.vmware.com/antrea/nginx:1.21.6-alpine" \
                    "projects.registry.vmware.com/antrea/toolbox:1.3-0")

FLOW_VISIBILITY_IMAGE_LIST=("projects.registry.vmware.com/antrea/ipfix-collector:v0.8.2" \
                            "projects.registry.vmware.com/antrea/clickhouse-operator:0.21.0" \
                            "projects.registry.vmware.com/antrea/metrics-exporter:0.21.0" \
                            "projects.registry.vmware.com/antrea/clickhouse-server:23.4")
if $proxy_all; then
    COMMON_IMAGES_LIST+=("registry.k8s.io/echoserver:1.10")
fi
if $flow_visibility; then
    COMMON_IMAGES_LIST+=("${FLOW_VISIBILITY_IMAGE_LIST[@]}")
fi
# Silence CLI suggestions.
export DOCKER_CLI_HINTS=false
for image in "${COMMON_IMAGES_LIST[@]}"; do
    for i in `seq 3`; do
        docker pull $image && break
        sleep 1
    done
done

# The Antrea images should not be pulled, as we want to use the local build.
if $coverage; then
    manifest_args="$manifest_args --coverage"
    COMMON_IMAGES_LIST+=("antrea/antrea-agent-ubuntu-coverage:latest" \
                         "antrea/antrea-controller-ubuntu-coverage:latest")
else
    COMMON_IMAGES_LIST+=("antrea/antrea-agent-ubuntu:latest" \
                         "antrea/antrea-controller-ubuntu:latest")
fi
if $flow_visibility; then
    if $coverage; then
        COMMON_IMAGES_LIST+=("antrea/flow-aggregator-coverage:latest")
    else
        COMMON_IMAGES_LIST+=("antrea/flow-aggregator:latest")
    fi
fi

printf -v COMMON_IMAGES "%s " "${COMMON_IMAGES_LIST[@]}"

vlan_args=""
if $extra_vlan; then
  vlan_args="$vlan_args --vlan-id 10"
  if [[ "$ipfamily" == "v4" ]]; then
    vlan_args="$vlan_args --vlan-subnets 172.100.10.1/24"
  elif [[ "$ipfamily" == "v6" ]]; then
    vlan_args="$vlan_args --vlan-subnets fd00:172:100:10::1/96"
  elif [[ "$ipfamily" == "dual" ]]; then
    vlan_args="$vlan_args --vlan-subnets 172.100.10.1/24,fd00:172:100:10::1/96"
  fi
fi

function setup_cluster {
  args=$1

  if [[ "$ipfamily" == "v6" ]]; then
    args="$args --ip-family ipv6 --pod-cidr fd00:10:244::/56"
  elif [[ "$ipfamily" == "dual" ]]; then
      args="$args --ip-family dual"
  elif [[ "$ipfamily" != "v4" ]]; then
    echoerr "invalid value for --ip-family \"$ipfamily\", expected \"v4\" or \"v6\""
    exit 1
  fi
  if $proxy_all; then
    args="$args --no-kube-proxy"
  fi
  if $node_ipam; then
    args="$args --no-kube-node-ipam"
  fi
  if $extra_network && [[ "$mode" != "hybrid" ]]; then
    args="$args --extra-networks \"20.20.30.0/24\""
  fi
  # Deploy an external server which could be used when testing Pod-to-External traffic.
  args="$args --deploy-external-server $vlan_args"

  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind $args"
}

function run_test {
  current_mode=$1
  coverage_args=""
  flow_visibility_args=""

  if $coverage; then
      $YML_CMD --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-coverage.yml
      $YML_CMD --ipsec $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-ipsec-coverage.yml
      timeout="80m"
      coverage_args="--coverage --coverage-dir $ANTREA_COV_DIR"
  else
      $YML_CMD --encap-mode $current_mode $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea.yml
      $YML_CMD --ipsec $manifest_args | docker exec -i kind-control-plane dd of=/root/antrea-ipsec.yml
      timeout="75m"
  fi

  if $flow_visibility; then
      timeout="30m"
      flow_visibility_args="-run=TestFlowAggregator --flow-visibility"
      if $coverage; then
          $FLOWAGGREGATOR_YML_CMD --coverage | docker exec -i kind-control-plane dd of=/root/flow-aggregator-coverage.yml
      else
          $FLOWAGGREGATOR_YML_CMD | docker exec -i kind-control-plane dd of=/root/flow-aggregator.yml
      fi
      $HELM template "$FLOW_VISIBILITY_CHART"  | docker exec -i kind-control-plane dd of=/root/flow-visibility.yml
      $HELM template "$FLOW_VISIBILITY_CHART" --set "secureConnection.enable=true" | docker exec -i kind-control-plane dd of=/root/flow-visibility-tls.yml

      curl -o $CH_OPERATOR_YML https://raw.githubusercontent.com/Altinity/clickhouse-operator/release-0.21.0/deploy/operator/clickhouse-operator-install-bundle.yaml
      sed -i -e "s|\"image\": \"clickhouse/clickhouse-server:22.3\"|\"image\": \"projects.registry.vmware.com/antrea/clickhouse-server:23.4\"|g" $CH_OPERATOR_YML
      sed -i -e "s|image: altinity/clickhouse-operator:0.21.0|image: projects.registry.vmware.com/antrea/clickhouse-operator:0.21.0|g" $CH_OPERATOR_YML
      sed -i -e "s|image: altinity/metrics-exporter:0.21.0|image: projects.registry.vmware.com/antrea/metrics-exporter:0.21.0|g" $CH_OPERATOR_YML
      cat $CH_OPERATOR_YML | docker exec -i kind-control-plane dd of=/root/clickhouse-operator-install-bundle.yml
  fi

  if $proxy_all; then
      apiserver=$(docker exec -i kind-control-plane kubectl get endpoints kubernetes --no-headers | awk '{print $2}')
      if $coverage; then
        docker exec -i kind-control-plane sed -i.bak -E "s/^[[:space:]]*[#]?kubeAPIServerOverride[[:space:]]*:[[:space:]]*[a-z\"]+[[:space:]]*$/    kubeAPIServerOverride: \"$apiserver\"/" /root/antrea-coverage.yml /root/antrea-ipsec-coverage.yml
      else
        docker exec -i kind-control-plane sed -i.bak -E "s/^[[:space:]]*[#]?kubeAPIServerOverride[[:space:]]*:[[:space:]]*[a-z\"]+[[:space:]]*$/    kubeAPIServerOverride: \"$apiserver\"/" /root/antrea.yml /root/antrea-ipsec.yml
      fi
  fi
  sleep 1

  RUN_OPT=""
  if [ -n "$run" ]; then
    RUN_OPT="-run $run"
  fi

  EXTRA_ARGS="$vlan_args --external-server-ips $(docker inspect external-server -f '{{.NetworkSettings.Networks.kind.IPAddress}},{{.NetworkSettings.Networks.kind.GlobalIPv6Address}}')"

  go test -v -timeout=$timeout $RUN_OPT antrea.io/antrea/test/e2e $flow_visibility_args -provider=kind --logs-export-dir=$ANTREA_LOG_DIR --skip-cases=$skiplist $coverage_args $EXTRA_ARGS
}

if [[ "$mode" == "" ]] || [[ "$mode" == "encap" ]]; then
  echo "======== Test encap mode =========="
  if [[ $test_only == "false" ]];then
    setup_cluster "--images \"$COMMON_IMAGES\""
  fi
  run_test encap
fi
if [[ "$mode" == "" ]] || [[ "$mode" == "noEncap" ]]; then
  echo "======== Test noencap mode =========="
  if [[ $test_only == "false" ]];then
    setup_cluster "--images \"$COMMON_IMAGES\""
  fi
  run_test noEncap
fi
if [[ "$mode" == "" ]] || [[ "$mode" == "hybrid" ]]; then
  echo "======== Test hybrid mode =========="
  if [[ $test_only == "false" ]];then
    setup_cluster "--subnets \"20.20.20.0/24\" --images \"$COMMON_IMAGES\""
  fi
  run_test hybrid
fi
exit 0

