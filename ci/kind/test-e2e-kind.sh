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
        --ip-family                   Configure the ipFamily for the KinD cluster.
        --feature-gates               A comma-separated list of key=value pairs that describe feature gates, e.g. AntreaProxy=true,Egress=false.
        --run                         Run only tests matching the regexp.
        --proxy-all                   Enable Antrea proxy with all Service support.
        --no-kube-proxy               Don't deploy kube-proxy.
        --load-balancer-mode          LoadBalancer mode.
        --node-ipam                   Enable Antrea NodeIPAM.
        --multicast                   Enable Multicast.
        --bgp-policy                  Enable Antrea BGPPolicy.
        --flow-visibility             Only run flow visibility related e2e tests.
        --networkpolicy-evaluation    Configure additional NetworkPolicy evaluation level when running e2e tests.
        --extra-network               Create an extra network that worker Nodes will connect to. Cannot be specified with the hybrid mode.
        --extra-vlan                  Create an subnet-based VLAN that worker Nodes will connect to.
        --skip                        A comma-separated list of keywords, with which tests should be skipped.
        --coverage                    Enable measure Antrea code coverage when running e2e tests on kind.
        --setup-only                  Only perform setting up the cluster and run test.
        --cleanup-only                Only perform cleaning up the cluster.
        --test-only                   Only run test on current cluster. Not set up/clean up the cluster.
        --antrea-controller-image     The Antrea controller image to use for the test. Default is antrea/antrea-controller-ubuntu.
        --antrea-agent-image          The Antrea agent image to use for the test. Default is antrea/antrea-agent-ubuntu.
        --antrea-image-tag            The Antrea image tag to use for the test. Default is latest.
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
no_kube_proxy=false
load_balancer_mode=""
node_ipam=false
multicast=false
bgp_policy=false
flow_visibility=false
np_evaluation=false
extra_network=false
extra_vlan=false
coverage=false
skiplist=""
setup_only=false
cleanup_only=false
test_only=false
run=""
flexible_ipam=false
antrea_controller_image="antrea/antrea-controller-ubuntu"
antrea_agent_image="antrea/antrea-agent-ubuntu"
use_non_default_images=false
antrea_image_tag="latest"
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
    --flexible-ipam)
    flexible_ipam=true
    shift
    ;;
    --no-kube-proxy)
    no_kube_proxy=true
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
    --bgp-policy)
    bgp_policy=true
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
    --networkpolicy-evaluation)
    np_evaluation=true
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
    --antrea-controller-image)
    antrea_controller_image="$2"
    use_non_default_images=true
    shift 2
    ;;
    --antrea-agent-image)
    antrea_agent_image="$2"
    use_non_default_images=true
    shift 2
    ;;
    --antrea-image-tag)
    antrea_image_tag="$2"
    shift 2
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

if $use_non_default_images && $coverage; then
    echoerr "Cannot use non-default images when coverage is enabled"
    exit 1
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
if $bgp_policy; then
    manifest_args="$manifest_args --feature-gates BGPPolicy=true"
fi
if $flow_visibility; then
    manifest_args="$manifest_args --feature-gates FlowExporter=true,L7FlowExporter=true --extra-helm-values-file $FLOW_VISIBILITY_HELM_VALUES"
fi
if $flexible_ipam; then
    manifest_args="$manifest_args --flexible-ipam"
fi

COMMON_IMAGES_LIST=("registry.k8s.io/e2e-test-images/agnhost:2.40" \
                    "antrea/nginx:1.21.6-alpine" \
                    "antrea/toolbox:1.5-1")

FLOW_VISIBILITY_IMAGE_LIST=("antrea/ipfix-collector:v0.12.0" \
                            "antrea/clickhouse-operator:0.21.0" \
                            "antrea/metrics-exporter:0.21.0" \
                            "antrea/clickhouse-server:23.4")
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
    COMMON_IMAGES_LIST+=("${antrea_controller_image}-coverage:${antrea_image_tag}" \
                         "${antrea_agent_image}-coverage:${antrea_image_tag}")
else
    COMMON_IMAGES_LIST+=("${antrea_controller_image}:${antrea_image_tag}" \
                         "${antrea_agent_image}:${antrea_image_tag}")
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
  if [[ "$ipfamily" == "v4" ]]; then
    vlan_args="$vlan_args --vlan-subnets 10=172.100.10.1/24"
  elif [[ "$ipfamily" == "v6" ]]; then
    vlan_args="$vlan_args --vlan-subnets 10=fd00:172:100:10::1/96"
  elif [[ "$ipfamily" == "dual" ]]; then
    vlan_args="$vlan_args --vlan-subnets 10=172.100.10.1/24,fd00:172:100:10::1/96"
  fi
fi

if $flexible_ipam; then
   vlan_args="$vlan_args --vlan-subnets 11=192.168.241.1/24 --vlan-subnets 12=192.168.242.1/24" 
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
  if $no_kube_proxy; then
    args="$args --no-kube-proxy"
  fi
  if $node_ipam; then
    args="$args --no-kube-node-ipam"
  fi
  if $extra_network && [[ "$mode" != "hybrid" ]]; then
    args="$args --extra-networks \"20.20.30.0/24\""
  fi
  # Deploy an external agnhost which could be used when testing Pod-to-External traffic.
  args="$args --deploy-external-agnhost $vlan_args"
  # Deploy an external FRR which could be used when testing BGPPolicy.
  if $bgp_policy; then
    args="$args --deploy-external-frr"
  fi
  if $flexible_ipam; then
    args="$args --flexible-ipam"
  fi
  echo "creating test bed with args $args"
  eval "timeout 600 $TESTBED_CMD create kind $args"
}

function run_test {
  current_mode=$1
  coverage_args=""
  flow_visibility_args=""

  if $use_non_default_images; then
    export AGENT_IMG_NAME=${antrea_agent_image}
    export CONTROLLER_IMG_NAME=${antrea_controller_image}
  fi
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
      sed -i -e "s|\"image\": \"clickhouse/clickhouse-server:22.3\"|\"image\": \"antrea/clickhouse-server:23.4\"|g" $CH_OPERATOR_YML
      sed -i -e "s|image: altinity/clickhouse-operator:0.21.0|image: antrea/clickhouse-operator:0.21.0|g" $CH_OPERATOR_YML
      sed -i -e "s|image: altinity/metrics-exporter:0.21.0|image: antrea/metrics-exporter:0.21.0|g" $CH_OPERATOR_YML
      cat $CH_OPERATOR_YML | docker exec -i kind-control-plane dd of=/root/clickhouse-operator-install-bundle.yml
  fi

  if $no_kube_proxy; then
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

  np_evaluation_flag=""
  if $np_evaluation; then
    np_evaluation_flag="--networkpolicy-evaluation"
  fi

  external_agnhost_cid=$(docker ps -f name="^antrea-external-agnhost" --format '{{.ID}}')
  external_agnhost_ips=$(docker inspect $external_agnhost_cid -f '{{.NetworkSettings.Networks.kind.IPAddress}},{{.NetworkSettings.Networks.kind.GlobalIPv6Address}}')
  EXTRA_ARGS="$vlan_args --external-agnhost-ips $external_agnhost_ips"

  if $bgp_policy; then
    external_frr_cid=$(docker ps -f name="^antrea-external-frr" --format '{{.ID}}')
    external_frr_ips=$(docker inspect $external_frr_cid -f '{{.NetworkSettings.Networks.kind.IPAddress}},{{.NetworkSettings.Networks.kind.GlobalIPv6Address}}')
    EXTRA_ARGS="$EXTRA_ARGS --external-frr-cid $external_frr_cid --external-frr-ips $external_frr_ips"
  fi

  if $flexible_ipam; then
     EXTRA_ARGS="$EXTRA_ARGS --antrea-ipam"
     timeout="100m"
  fi
 
  go test -v -timeout=$timeout $RUN_OPT antrea.io/antrea/test/e2e $flow_visibility_args -provider=kind --logs-export-dir=$ANTREA_LOG_DIR $np_evaluation_flag --skip-cases=$skiplist $coverage_args $EXTRA_ARGS

  if $coverage; then
    pushd $ANTREA_COV_DIR
    for dir in */; do 
      go tool covdata textfmt -i="${dir}" -o "${dir%?}_$(date +%Y-%m-%d_%H-%M-%S).cov.out"
      rm -rf "${dir}";
    done
    popd
  fi
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

