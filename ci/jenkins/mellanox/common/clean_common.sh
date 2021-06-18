#!/bin/bash -x

export LOGDIR=$WORKSPACE/logs
export ARTIFACTS=$WORKSPACE/artifacts

export KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}

source ./common/common_functions.sh

function delete_pods {
    kubectl delete pods --all
}

function stop_system_deployments {
    kubectl delete deployment -n kube-system --all
}

function stop_system_daemonset {
    for ds in $(kubectl -n kube-system get ds |grep kube|awk '{print $1}'); do
        kubectl -n kube-system delete ds $ds
    done
}

function stop_k8s {
    sudo kubeadm reset -f
    rm -rf $HOME/.kube/config
}

function asure_all_stoped {
    kill $(ps -ef |grep local-up-cluster.sh|grep $WORKSPACE|awk '{print $2}')
    kill $(pgrep sriovdp)
    kill $(ps -ef |grep kube |awk '{print $2}')
    kill -9 $(ps -ef |grep etcd|grep http|awk '{print $2}')
    ps -ef |egrep "kube|local-up-cluster|etcd"
}

function delete_all_docker_container {
    sudo docker stop $(sudo docker ps -q)
    sudo docker rm $(sudo docker ps -a -q)
}

function delete_all_docker_images {
    sudo docker rmi $(sudo docker images -q)
}

function delete_chache_files {
    #delete network cache
    rm -rf /var/lib/cni/networks

    [ -d /var/lib/cni/sriov ] && rm -rf /var/lib/cni/sriov/*
}

function clean_tmp_workspaces {
    number_of_all_logs=$(ls -tr /tmp/ | grep k8s | wc -l)
    number_of_logs_to_keep=10
    let number_of_logs_to_clean="$number_of_all_logs"-"$number_of_logs_to_keep"
    echo "number of all logs $number_of_all_logs."
    echo "number of logs to clean $number_of_logs_to_clean."
    
    if [ "$number_of_logs_to_clean" -le 0 ]; then
            echo "no logs to clean"
    else
        logs_to_clean=$(ls -tr /tmp/ | grep k8s | head -n "$number_of_logs_to_clean")
        echo "Cleaning $number_of_logs_to_clean logs, it is these dirs:"
        echo "$logs_to_clean"
        for log in $logs_to_clean; do
            echo "Removing /tmp/$log dir..."
            rm -rf /tmp/"$log"
        done
    fi
}

function unload_module {
    local module=$1
    sudo modprobe -r $module
    if [[ "$?" != "0" ]];then
       echo "ERROR: Failed to unload $module module!"
       return 1
    fi
}

function general_cleaning {
    stop_system_deployments

    stop_system_daemonset

    stop_k8s

    asure_all_stoped

    delete_chache_files

    delete_all_docker_container

    delete_all_docker_images

    clean_tmp_workspaces

    collect_services_logs

    delete_cnis_bins_and_confs
}

function collect_pods_logs {
    if [[ -f "${LOGDIR}/start-time.log" ]];then
        echo "Collecting all pods logs..."
        kubectl get pods -A -o wide > ${LOGDIR}/pods-last-state.log
	old_IFS=$IFS
	IFS=$'\n'
	for pod in $(kubectl get pods -A -o custom-columns=NAMESACE:.metadata.namespace,NAME:.metadata.name);do
            get_pod_log "$pod"
        done
    else
        echo ""
        echo "No \"${LOGDIR}/start-time.log\", assuming job did not start."
        echo ""
    fi
    IFS=$old_IFS
}

function collect_services_logs {
    if [[ -f "${LOGDIR}/start-time.log" ]];then
        echo "Collecting Services Logs..."
        get_service_log "kubelet"
        get_service_log "docker"
    else
        echo ""
        echo "No \"${LOGDIR}/start-time.log\", assuming job did not start."
        echo ""
    fi
}

function get_pod_log {
    pod_line="$1"
    pod_namespace="$(awk '{print $1}' <<< ${pod_line})"
    pod_name="$(awk '{print $2}' <<< ${pod_line})"

    echo "Collecting $pod_name logs..."

    kubectl logs -n "$pod_namespace" "$pod_name" > ${LOGDIR}/${pod_name}.log

    if [[ -f ${LOGDIR}/${pod_name}.log ]];then
        echo "Logs wrote to ${LOGDIR}/${pod_name}.log!"
        echo ""
    else
        echo "${LOGDIR}/${pod_name}.log was not found, writing logs failed!"
        echo ""
    fi
}

function get_service_log {
    service_name="$1"

    echo "Collecting $service_name logs..."

    sudo journalctl -o short-precise --since "$(cat ${LOGDIR}/start-time.log)" --unit $service_name > "${LOGDIR}/${service_name}.log"

    if [[ -f ${LOGDIR}/${service_name}.log ]];then
        echo "Logs wrote to ${LOGDIR}/${service_name}.log!"
        echo ""
    else
        echo "${LOGDIR}/${service_name}.log was not found, writing logs failed!"
        echo ""
    fi
}

function delete_cnis_bins_and_confs {
    rm -rf ${CNI_CONF_DIR}/*
    rm -rf ${CNI_BIN_DIR}/*
}
