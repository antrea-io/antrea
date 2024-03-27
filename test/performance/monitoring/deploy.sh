#!/usr/bin/env bash
# Copyright 2024 Antrea Authors.
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

_usage="Usage: $0 [--help|-h]
        --destroy                     Destroy the deployed monitoring Pods
        --kubeconfig <path>           Path of cluster kubeconfig
        --localhost                   Enable port-forwarding to localhost for Grafana access"

WORKDIR=$(dirname "$0")

DESTROY=false
DEFAULT_WORKDIR=$(dirname "$0")
DEFAULT_KUBECONFIG_PATH=${HOME}/.kube/config
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
LOCALHOST=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --kubeconfig)
    KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --destroy)
    DESTROY=true
    shift
    ;;
    --localhost)
    LOCALHOST=true
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

export KUBECONFIG=${KUBECONFIG_PATH}

function deploy() {
    # ====== Install kube-state-metrics ======
    # TODO: modify the final yaml to deploy kube-state-metrics in a control plane Node.
    kubectl apply -f ${DEFAULT_WORKDIR}/kube-state-metrics/kube-state-metrics.yml

    kubectl apply -f ${DEFAULT_WORKDIR}/node_exporter/node-exporter.yml

    # ====== Install Prometheus ======
    kubectl apply -f ${DEFAULT_WORKDIR}/prometheus/prometheus.yml

    # ====== Install Grafana ======
    kubectl create configmap grafana-dashboards --from-file=${DEFAULT_WORKDIR}/grafana/dashboards/
    kubectl apply -f ${DEFAULT_WORKDIR}/grafana/grafana.yml

    kubectl rollout status --timeout=2m deploy/grafana -n default

    # Checking the port availability.
    echo "Trying to expose the Grafana Service via port 3100"
    set +e
    if lsof -i:3100 > /dev/null;then
      echo "The port 3100 is in use, you can expose the Grafana Service by running
'kubectl port-forward svc/grafana \$new_port:3000'. The default credential is 'admin/admin'"
    else
      # Do port-forward to access grafana from outside of K8s
      if [[ "$LOCALHOST" == true ]];then
        nohup kubectl port-forward svc/grafana 3100:3000 &
        echo "Please access grafana via http://localhost:3100 with admin/admin"
      else
        nohup kubectl port-forward --address 0.0.0.0 svc/grafana 3100:3000 &
        ip=$(hostname -I | awk '{print $1}')
        echo "Please access grafana via http://$ip:3100 with admin/admin"
      fi
    fi
    set -e
}

function destroy() {
    # ====== Delete kube-state-metrics ======
    kubectl delete -f ${DEFAULT_WORKDIR}/kube-state-metrics/kube-state-metrics.yml || true

    # ===== Delete node-exporter =====
    kubectl delete -f ${DEFAULT_WORKDIR}/node_exporter/node-exporter.yml || true

    # ====== Delete Prometheus ======
    kubectl delete -f ${DEFAULT_WORKDIR}/prometheus/prometheus-all-in-one.yml || true

    # ====== Delete Grafana ======
    kubectl delete configmap grafana-dashboards || true
    kubectl delete -f ${DEFAULT_WORKDIR}/grafana/grafana.yml || true
}

if [[ "$DESTROY" == true ]];then
  echo "Clean up deployment"
  destroy
  exit
fi

deploy
