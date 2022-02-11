#!/usr/bin/env bash

# Copyright 2022 Antrea Authors.
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

set -eu

FAILURE=false
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/..

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>]

Setup Grafana, ClickHouse and Antrea Flow Aggregator to validate flow-aggregator.yml and flow-visibility.yml.

    --kubeconfig    Path to kubeconfig.

"

echoerr() {
  >&2 echo "$@"
}

print_usage() {
  echoerr "$_usage"
}


while [[ $# -gt 0 ]]
do
key="$1"
case $key in
    --kubeconfig)
    export KUBECONFIG="$2"
    shift 2
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

start_antrea() {
  echo "=== Starting Antrea ==="
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  kubectl rollout status --timeout=5m deployment/coredns -n kube-system
  kubectl rollout status --timeout=5m deployment.apps/antrea-controller -n kube-system
  kubectl rollout status --timeout=5m daemonset/antrea-agent -n kube-system
}

setup_flow_visibility() {
  echo "=== Starting Flow Visibility ==="
  # install ClickHouse operator
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/clickhouse-operator-install-bundle.yml
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/flow-visibility.yml
  echo "=== Waiting for ClickHouse and Grafana to be ready ==="
  sleep 15
  kubectl wait --for=condition=ready pod -l app=clickhouse-operator -n kube-system --timeout=600s
  kubectl wait --for=condition=ready pod -l app=clickhouse -n flow-visibility --timeout=600s
  kubectl wait --for=condition=ready pod -l app=grafana -n flow-visibility --timeout=600s
}

check_grafana() {
  echo "=== Check the installation of Grafana plugins ==="
  grafana_logs=$(kubectl logs -n flow-visibility $(kubectl -n flow-visibility get pod -l app=grafana -o jsonpath="{.items[0].metadata.name}"))
  if ( echo ${grafana_logs} | grep -q 'msg="Plugin registered" logger=plugin.manager pluginId=antreaflowvisibility-grafana-sankey-plugin' ); then
    echo "=== antreaflowvisibility-grafana-sankey-plugin installed correctly ==="
  else
    echo "=== antreaflowvisibility-grafana-sankey-plugin is NOT installed correctly ==="
    FAILURE=true
  fi
  if ( echo ${grafana_logs} | grep -q 'msg="Plugin registered" logger=plugin.manager pluginId=grafana-clickhouse-datasource' ); then
    echo "=== grafana-clickhouse-datasource installed correctly ==="
  else
    echo "=== grafana-clickhouse-datasource is NOT installed correctly ==="
    FAILURE=true
  fi
}

config_antrea() {
  echo "=== Stopping Antrea === "
  kubectl delete -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  echo "=== Enable Antrea Flow Exporter ==="
  sed -i -e "s/#  FlowExporter: false/  FlowExporter: true/g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
}

setup_flow_aggregator() {
  echo "=== Config Antrea Flow Aggregator ==="
  perl -i -p0e 's/      # Enable is the switch to enable exporting flow records to ClickHouse.\n      #enable: false/      # Enable is the switch to enable exporting flow records to ClickHouse.\n      enable: true/' ./build/yamls/flow-aggregator.yml
  echo "=== Start Antrea Flow Aggregator ==="
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/flow-aggregator.yml
  echo "=== Waiting for Antrea Flow Aggregator to be ready ==="
  kubectl wait --for=condition=ready pod -l app=flow-aggregator -n flow-aggregator --timeout=600s
}

# Antrea Flow Aggregator starts to insert flow records into ClickHouse database.
# This function will check if there are flow records inserted in desired table of database.
check_record() {
  echo "=== Wait for up to 5 minutes to receive flow records ==="
  for i in `seq 5`
  do
    sleep 60
    echo "=== Get flow record (try for 1m) ==="
    clickhouse_output=$(kubectl exec -it chi-clickhouse-clickhouse-0-0-0  -n flow-visibility -- clickhouse-client -h clickhouse-clickhouse.flow-visibility.svc -u clickhouse_operator --password clickhouse_operator_password --query="select count(*) from flows")
    # Remove all new line, return, tab from the output string, to allow integer comparison.
    row_number="${clickhouse_output//[$'\t\r\n ']}"
    echo $row_number
    if [ $row_number -gt 0 ]; then
      echo "=== Record is received correctly ==="
      break
    elif [ $i == 5 ]; then
      echo "=== Record is NOT received correctly ==="
      FAILURE=true
    fi
  done
}

start_antrea
setup_flow_visibility
check_grafana
config_antrea
start_antrea
setup_flow_aggregator
check_record

if ( ${FAILURE} == true ); then
  echo "=== TEST FAILURE !! ==="
  touch TEST_FAILURE
fi
