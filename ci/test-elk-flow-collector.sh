set -eu

LOGSTASH_PORT=4739
LOGSTASH_IP="0.0.0.0"
LOGSTASH_PROTOCOL="udp"
FAILURE=false
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/..

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>]

Setup Elastic stack (elk) flow collector and Antrea Agent flow exporter to validate elk-flow-collector.yml.

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
    echo "kube"
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

setup_flow_collector() {
  echo "=== Starting Flow Collector ==="
  kubectl create namespace elk-flow-collector
  kubectl create configmap logstash-configmap -n elk-flow-collector --from-file=${GIT_CHECKOUT_DIR}/build/yamls/elk-flow-collector/logstash/
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/elk-flow-collector/elk-flow-collector.yml -n elk-flow-collector
  echo "=== Waiting for Elastic Stack to be ready ==="
  kubectl wait --for=condition=ready pod -l app=kibana -n elk-flow-collector --timeout=600s
  kubectl wait --for=condition=ready pod -l app=logstash -n elk-flow-collector --timeout=600s
  kubectl wait --for=condition=ready pod -l app=elasticsearch -n elk-flow-collector --timeout=600s
  # wait some time for logstash to connect to elasticsearch
  sleep 30s
  # get cluster-ip of logstash
  LOGSTASH_IP=$(kubectl get svc logstash -n elk-flow-collector -o jsonpath='{.spec.clusterIP}')
  if [ ${LOGSTASH_PROTOCOL} = "udp" ]; then
    nc -zvu ${LOGSTASH_IP} ${LOGSTASH_PORT}
  fi
  echo "=== Flow Collector is listening on ${LOGSTASH_IP}:${LOGSTASH_PORT} ==="
}

config_antrea() {
  echo "=== Stopping Antrea === "
  kubectl delete -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  echo "=== Configuring Antrea Flow Exporter Address ==="
  sed -i -e "s/#flowCollectorAddr.*/flowCollectorAddr: \"${LOGSTASH_IP}:${LOGSTASH_PORT}:${LOGSTASH_PROTOCOL}\"/g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  sed -i -e "s/#  FlowExporter: false/  FlowExporter: true/g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  sed -i -e "s/#enableTLSToFlowAggregator: true/enableTLSToFlowAggregator: false/g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
}

# Antrea agent flow exporter starts to send CoreDNS flow records.
# It will check if flow records with one of desired fields (soursePodName) are received correctly.
check_record() {
  echo "=== Wait for up to 5 minutes to receive data ==="
  for i in `seq 5`
  do
    sleep 1m
    echo "=== Get flow record (try for 1m) ==="
    # if the records are received in logstash and processed correctly, the logstash logs should show the formatted data, which have 'sourcePodName' field
    LOGSTASH_LOGS=$(kubectl logs -n elk-flow-collector $(kubectl -n elk-flow-collector get pod -l app=logstash -o jsonpath="{.items[0].metadata.name}"))
    if ( echo ${LOGSTASH_LOGS} | grep -q 'sourcePodName' ); then
      echo "=== Record is received correctly ==="
      break
    elif [ $i == 5 ]; then
      echo "=== Record is NOT received correctly ==="
      FAILURE=true
    fi
  done
}

start_antrea
setup_flow_collector
config_antrea
start_antrea
check_record

if ( ${FAILURE} == true ); then
  echo "=== TEST FAILURE !! ==="
  touch TEST_FAILURE
fi
