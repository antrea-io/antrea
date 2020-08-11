set -eu

LOGSTASH_PORT=4739
LOGSTASH_IP="0.0.0.0"
LOGSTASH_PROTOCOL="udp"
FAILURE=false

setup_flow_collector() {
  echo "=== Starting Flow Collector ==="
  kubectl create namespace antrea-flow-collector
  kubectl create configmap logstash-configmap -n antrea-flow-collector --from-file=${GIT_CHECKOUT_DIR}/build/yamls/flow-collector/logstash/
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/flow-collector/flow-collector.yml -n antrea-flow-collector
  echo "=== Waiting for Elastic Stack to be ready ==="
  kubectl wait --for=condition=ready pod -l app=elasticsearch -n antrea-flow-collector --timeout=600s
  kubectl wait --for=condition=ready pod -l app=kibana -n antrea-flow-collector
  kubectl wait --for=condition=ready pod -l app=logstash -n antrea-flow-collector --timeout=600s
  # get cluster-ip of logstash
  LOGSTASH_IP=$(kubectl get svc logstash -n antrea-flow-collector -o jsonpath='{.spec.clusterIP}')
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
  sed -i -e "s/#  AntreaProxy: false/  AntreaProxy: true/g" ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  echo "=== Restarting Antrea ==="
  kubectl apply -f ${GIT_CHECKOUT_DIR}/build/yamls/antrea.yml
  sleep 20
  kubectl wait --for=condition=ready pod -l app=antrea -n kube-system --timeout=300s
  echo "=== Antrea Agent flow exporter starts to send data ==="
}

# Antrea agent flow exporter starts to send CoreDNS flow records.
# It will check if flow records with one of desired fields (soursePodName) are received correctly.
check_record() {
  echo "=== Wait for 5 minutes to receive data ==="
  sleep 5m
   # if the records are received in logstash and processed correctly, the logstash logs should show the formatted data, which have 'sourcePodName' field
  LOGSTASH_LOGS=$(kubectl logs -n antrea-flow-collector $(kubectl -n antrea-flow-collector get pod -l app=logstash -o jsonpath="{.items[0].metadata.name}"))
  if ( echo ${LOGSTASH_LOGS} | grep -q 'sourcePodName' ); then
    echo "=== Record is received correctly ==="
  else
    echo "=== Record is NOT received correctly ==="
    FAILURE=true
  fi
}

cleanup() {
  echo "=== Removing Elastic Stack ==="
  kubectl delete -f ${GIT_CHECKOUT_DIR}/build/yamls/flow-collector/flow-collector.yml  -n antrea-flow-collector
  kubectl delete configmap logstash-configmap -n antrea-flow-collector
  kubectl delete namespace antrea-flow-collector
  echo "=== Elastic Stack has been removed ==="
}

setup_flow_collector
config_antrea
check_record
cleanup
if ( ${FAILURE} == true ); then
  exit 1
fi
