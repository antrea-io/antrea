#!/bin/bash -x

export LOGDIR=$WORKSPACE/logs
export ARTIFACTS=$WORKSPACE/artifacts

export KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}

source ./common/clean_common.sh

function clean_antrea_runtime {
    sudo rm -rf /var/run/antrea/
}

function main {
    mkdir -p $WORKSPACE
    mkdir -p $LOGDIR
    mkdir -p $ARTIFACTS

    delete_pods

    collect_pods_logs

    general_cleaning

    clean_antrea_runtime
    
    cp /tmp/kube*.log $LOGDIR
    echo "All logs $LOGDIR"
    echo "All confs $ARTIFACTS"

}

main
