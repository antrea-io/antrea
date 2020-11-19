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

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

CLUSTER=""
DEFAULT_WORKDIR="/var/lib/jenkins"
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/.kube/config
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
MODE="report"
RUN_GARBAGE_COLLECTION=false
RUN_SETUP_ONLY=false
RUN_CLEANUP_ONLY=false
COVERAGE=false
RUN_TEST_ONLY=false
TESTCASE=""
CODECOV_TOKEN=""
SECRET_EXIST=false
TEST_FAILURE=false
CLUSTER_READY=false
DOCKER_REGISTRY=""

_usage="Usage: $0 [--cluster-name <VMCClusterNameToUse>] [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--log-mode <SonobuoyResultLogLevel>] [--testcase <e2e|conformance|all-features-conformance|whole-conformance|networkpolicy>]
                  [--garbage-collection] [--setup-only] [--cleanup-only] [--coverage] [--test-only] [--registry]

Setup a VMC cluster to run K8s e2e community tests (E2e, Conformance, all features Conformance, whole Conformance & Network Policy).

        --cluster-name           The cluster name to be used for the generated VMC cluster.
        --kubeconfig             Path to save kubeconfig of generated VMC cluster.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --log-mode               Use the flag to set either 'report', 'detail', or 'dump' level data for sonobouy results.
        --testcase               The testcase to run: e2e, conformance, all-features-conformance, whole-conformance or networkpolicy.
        --garbage-collection     Do garbage collection to clean up some unused testbeds.
        --setup-only             Only perform setting up the cluster and run test.
        --cleanup-only           Only perform cleaning up the cluster.
        --coverage               Run e2e with coverage.
        --test-only              Only run test on current cluster. Not set up/clean up the cluster.
        --codecov-token          Token used to upload coverage report(s) to Codecov.
        --registry               Using private registry to pull images."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --cluster-name)
    CLUSTER="$2"
    shift 2
    ;;
    --kubeconfig)
    KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --workdir)
    WORKDIR="$2"
    shift 2
    ;;
    --log-mode)
    MODE="$2"
    shift 2
    ;;
    --testcase)
    TESTCASE="$2"
    shift 2
    ;;
    --registry)
    DOCKER_REGISTRY="$2"
    shift 2
    ;;
    --garbage-collection)
    RUN_GARBAGE_COLLECTION=true
    shift
    ;;
    --setup-only)
    RUN_SETUP_ONLY=true
    shift
    ;;
    --cleanup-only)
    RUN_CLEANUP_ONLY=true
    shift
    ;;
    --coverage)
    COVERAGE=true
    shift
    ;;
    --test-only)
    RUN_TEST_ONLY=true
    shift
    ;;
    --codecov-token)
    CODECOV_TOKEN="$2"
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

if [[ "$WORKDIR" != "$DEFAULT_WORKDIR" && "$KUBECONFIG_PATH" == "$DEFAULT_KUBECONFIG_PATH" ]]; then
    KUBECONFIG_PATH=$WORKDIR/.kube/config
fi

function saveLogs() {
    echo "=== Truncate old logs ==="
    mkdir -p $WORKDIR/antrea_logs
    LOG_DIR=$WORKDIR/antrea_logs
    find ${LOG_DIR}/* -type d -mmin +10080 | xargs -r rm -rf

    CLUSTER_LOG_DIR="${LOG_DIR}/${CLUSTER}"
    echo "=== Saving capi logs ==="
    mkdir -p ${CLUSTER_LOG_DIR}/capi
    kubectl get -n capi-system pods -o name | awk '{print $1}' | while read capi_pod; do
        capi_pod_name=$(echo ${capi_pod} | cut -d'/' -f 2)
        kubectl logs ${capi_pod_name} -c manager -n capi-system > ${CLUSTER_LOG_DIR}/capi/${capi_pod_name} || true
    done

    echo "=== Saving capv logs ==="
    mkdir -p ${CLUSTER_LOG_DIR}/capv
    kubectl get -n capv-system pods -o name | awk '{print $1}' | while read capv_pod; do
        capv_pod_name=$(echo ${capv_pod} | cut -d'/' -f 2)
        kubectl logs ${capv_pod_name} -c manager -n capv-system > ${CLUSTER_LOG_DIR}/capv/${capv_pod_name} || true
    done

    echo "=== Saving cluster_api.yaml ==="
    mkdir -p ${CLUSTER_LOG_DIR}/cluster_api
    kubectl get cluster-api -A -o yaml > ${CLUSTER_LOG_DIR}/cluster_api/cluster_api.yaml || true
}

function setup_cluster() {
    export KUBECONFIG=$KUBECONFIG_PATH
    if [ -z $K8S_VERSION ]; then
      export K8S_VERSION=v1.18.2
    fi
    if [ -z $TEST_OS ]; then
      export TEST_OS=ubuntu-1804
    fi
    export OVA_TEMPLATE_NAME=${TEST_OS}-kube-${K8S_VERSION}
    rm -rf ${GIT_CHECKOUT_DIR}/jenkins || true

    echo '=== Generate key pair ==='
    mkdir -p ${GIT_CHECKOUT_DIR}/jenkins/key
    ssh-keygen -b 2048 -t rsa -f  "${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key" -q -N ""
    publickey="$(cat ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key.pub)"

    echo "=== namespace value substitution ==="
    mkdir -p ${GIT_CHECKOUT_DIR}/jenkins/out
    cp ${GIT_CHECKOUT_DIR}/ci/cluster-api/vsphere/templates/* ${GIT_CHECKOUT_DIR}/jenkins/out
    sed -i "s/CLUSTERNAMESPACE/${CLUSTER}/g" ${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml
    sed -i "s/K8SVERSION/${K8S_VERSION}/g" ${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml
    sed -i "s/OVATEMPLATENAME/${OVA_TEMPLATE_NAME}/g" ${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml
    sed -i "s/CLUSTERNAME/${CLUSTER}/g" ${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml
    sed -i "s|SSHAUTHORIZEDKEYS|${publickey}|g" ${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml
    sed -i "s/CLUSTERNAMESPACE/${CLUSTER}/g" ${GIT_CHECKOUT_DIR}/jenkins/out/namespace.yaml

    echo "=== network spec value substitution==="
    cluster_defaults=${WORKDIR}/utils/CLUSTERDEFAULTS
    while IFS= read -r line; do
        IFS='=' read -ra kv <<< "$line"
        sed -i "s|${kv[0]}|${kv[1]}|g" ${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml
    done < "$cluster_defaults"

    echo '=== Create a cluster in management cluster ==='
    kubectl apply -f "${GIT_CHECKOUT_DIR}/jenkins/out/namespace.yaml"
    kubectl apply -f "${GIT_CHECKOUT_DIR}/jenkins/out/cluster.yaml"

    echo '=== Wait for 10 min to get workload cluster secret ==='
    for t in {1..10}
    do
        sleep 1m
        echo '=== Get kubeconfig (try for 1m) ==='
        if kubectl get secret/${CLUSTER}-kubeconfig -n${CLUSTER} ; then
            kubectl get secret/${CLUSTER}-kubeconfig -n${CLUSTER} -o json \
            | jq -r .data.value \
            | base64 --decode \
            > "${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig"
            SECRET_EXIST=true
            break
        fi
    done

    if [[ "$SECRET_EXIST" == false ]]; then
        echo "=== Failed to get secret ==="
        saveLogs
        kubectl delete ns ${CLUSTER}
        exit 1
    else
        export KUBECONFIG="${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig"
        echo "=== Waiting for 10 minutes for all nodes to be up ==="

        set +e
        for t in {1..10}
        do
            sleep 1m
            echo "=== Get node (try for 1m) ==="
            mdNum="$(kubectl get node | grep -c ${CLUSTER}-md)"
            if [ "${mdNum}" == "2" ]; then
                echo "=== Setup workload cluster succeeded ==="
                CLUSTER_READY=true
                break
            fi
        done
        set -e

        if [[ "$CLUSTER_READY" == false ]]; then
            echo "=== Failed to bring up all the nodes ==="
            saveLogs
            KUBECONFIG=$KUBECONFIG_PATH kubectl delete ns ${CLUSTER}
            exit 1
        fi
    fi
}

function deliver_antrea {
    echo "====== Building Antrea for the Following Commit ======"
    git show --numstat

    export GO111MODULE=on
    export GOPATH=$WORKDIR/go
    export GOROOT=/usr/local/go
    export GOCACHE=${GIT_CHECKOUT_DIR}/../gocache
    export PATH=$GOROOT/bin:$PATH

    make clean -C $GIT_CHECKOUT_DIR
    docker images | grep "${JOB_NAME}" | awk '{print $3}' | xargs -r docker rmi -f || true > /dev/null
    # Clean up dangling images generated in previous builds. Recent ones must be excluded
    # because they might be being used in other builds running simultaneously.
    docker image prune -f --filter "until=1h" || true > /dev/null
    cd $GIT_CHECKOUT_DIR
    if [[ ${DOCKER_REGISTRY} != "" ]]; then
        docker pull ${DOCKER_REGISTRY}/antrea/antrea-ubuntu:latest
        docker tag ${DOCKER_REGISTRY}/antrea/antrea-ubuntu:latest antrea/antrea-ubuntu:latest
        docker pull ${DOCKER_REGISTRY}/antrea/golang:1.15
        docker tag ${DOCKER_REGISTRY}/antrea/golang:1.15 golang:1.15
    fi
    for i in `seq 2`
    do
        if [[ "$COVERAGE" == true ]]; then
            VERSION="$CLUSTER" DOCKER_REGISTRY="${DOCKER_REGISTRY}" make build-ubuntu-coverage && break
        else
            VERSION="$CLUSTER" DOCKER_REGISTRY="${DOCKER_REGISTRY}" make && break
        fi
    done
    cd ci/jenkins

    if [ "$?" -ne "0" ]; then
        echo "=== Antrea Image build failed ==="
        exit 1
    fi

    antrea_yml="antrea.yml"
    if [[ "$COVERAGE" == true ]]; then
        make manifest-coverage -C $GIT_CHECKOUT_DIR
        antrea_yml="antrea-coverage.yml"
    fi

    sed -i "s|#serviceCIDR: 10.96.0.0/12|serviceCIDR: 100.64.0.0/13|g" $GIT_CHECKOUT_DIR/build/yamls/$antrea_yml

    # Append antrea-prometheus.yml to antrea.yml
    echo "---" >> $GIT_CHECKOUT_DIR/build/yamls/$antrea_yml
    cat $GIT_CHECKOUT_DIR/build/yamls/antrea-prometheus.yml >> $GIT_CHECKOUT_DIR/build/yamls/$antrea_yml

    echo "====== Delivering Antrea to all the Nodes ======"
    export KUBECONFIG=${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig
    DOCKER_IMG_VERSION=$CLUSTER

    if [[ "$COVERAGE" == true ]]; then
        docker save -o antrea-ubuntu-coverage.tar antrea/antrea-ubuntu-coverage:${DOCKER_IMG_VERSION}
    else
        docker save -o antrea-ubuntu.tar antrea/antrea-ubuntu:${DOCKER_IMG_VERSION}
    fi

    kubectl get nodes -o wide --no-headers=true | awk '$3 == "master" {print $6}' | while read master_ip; do
        scp -q -o StrictHostKeyChecking=no -i ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key $GIT_CHECKOUT_DIR/build/yamls/*.yml capv@${master_ip}:~
    done

    kubectl get nodes -o wide --no-headers=true | awk '{print $6}' | while read IP; do
        antrea_image="antrea-ubuntu"
        if [[ "$COVERAGE" == true ]]; then
            antrea_image="antrea-ubuntu-coverage"
        fi
        ssh-keygen -f "/var/lib/jenkins/.ssh/known_hosts" -R ${IP}
        scp -o StrictHostKeyChecking=no -i ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key $antrea_image.tar capv@${IP}:/home/capv
        if [ $TEST_OS == 'centos-7' ]; then
            ssh -q -o StrictHostKeyChecking=no -i ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key -n capv@${IP} "sudo chmod 777 /run/containerd/containerd.sock"
            ssh -q -o StrictHostKeyChecking=no -i ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key -n capv@${IP} "sudo crictl images | grep $antrea_image | awk '{print \$3}' | xargs -r crictl rmi ; ctr -n=k8s.io images import /home/capv/$antrea_image.tar ; ctr -n=k8s.io images tag docker.io/antrea/$antrea_image:${DOCKER_IMG_VERSION} docker.io/antrea/$antrea_image:latest ; sudo crictl images | grep '<none>' | awk '{print \$3}' | xargs -r crictl rmi"
        else
            ssh -q -o StrictHostKeyChecking=no -i ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key -n capv@${IP} "sudo crictl images | grep $antrea_image | awk '{print \$3}' | xargs -r crictl rmi ; sudo ctr -n=k8s.io images import /home/capv/$antrea_image.tar ; sudo ctr -n=k8s.io images tag docker.io/antrea/$antrea_image:${DOCKER_IMG_VERSION} docker.io/antrea/$antrea_image:latest ; sudo crictl images | grep '<none>' | awk '{print \$3}' | xargs -r crictl rmi"
        fi
    done
}

function run_integration {
    VM_NAME="antrea-integration-0"
    export GOVC_URL=${GOVC_URL}
    export GOVC_USERNAME=${GOVC_USERNAME}
    export GOVC_PASSWORD=${GOVC_PASSWORD}
    VM_IP=$(govc vm.ip ${VM_NAME})
    govc snapshot.revert -vm.ip ${VM_IP} initial
    VM_IP=$(govc vm.ip ${VM_NAME}) # wait for VM to be on

    set -x
    echo "===== Run Integration test ====="
    if [[ ${DOCKER_REGISTRY} != "" ]]; then
        docker pull ${DOCKER_REGISTRY}/antrea/openvswitch:2.14.0
        docker tag ${DOCKER_REGISTRY}/antrea/openvswitch:2.14.0 antrea/openvswitch:2.14.0
    fi
    ssh -q -o StrictHostKeyChecking=no -i "${WORKDIR}/utils/key" -n jenkins@${VM_IP} "git clone ${ghprbAuthorRepoGitUrl} antrea && cd antrea && git checkout ${GIT_BRANCH} && DOCKER_REGISTRY=${DOCKER_REGISTRY} make docker-test-integration"
    if [[ "$COVERAGE" == true ]]; then
        ssh -q -o StrictHostKeyChecking=no -i "${WORKDIR}/utils/key" -n jenkins@${VM_IP} "curl -s https://codecov.io/bash | bash -s -- -c -t ${CODECOV_TOKEN} -F integration-tests -f '.coverage/coverage-integration.txt'"
    fi
}

function run_e2e {
    echo "====== Running Antrea E2E Tests ======"

    export GO111MODULE=on
    export GOPATH=$WORKDIR/go
    export GOROOT=/usr/local/go
    export GOCACHE=$WORKDIR/.cache/go-build
    export PATH=$GOROOT/bin:$PATH
    export KUBECONFIG=$GIT_CHECKOUT_DIR/jenkins/out/kubeconfig

    mkdir -p $GIT_CHECKOUT_DIR/test/e2e/infra/vagrant/playbook/kube
    cp -f $GIT_CHECKOUT_DIR/jenkins/out/kubeconfig $GIT_CHECKOUT_DIR/test/e2e/infra/vagrant/playbook/kube/config

    echo "=== Generate ssh-config ==="
    cp -f $GIT_CHECKOUT_DIR/ci/jenkins/ssh-config $GIT_CHECKOUT_DIR/test/e2e/infra/vagrant/ssh-config
    master_name="$(kubectl get nodes -o wide --no-headers=true | awk '$3 == "master" {print $1}')"
    master_ip="""$(kubectl get nodes -o wide --no-headers=true | awk '$3 == "master" {print $6}')"
    echo "=== Master node ip: ${master_ip} ==="
    sed -i "s/MASTERNODEIP/${master_ip}/g" $GIT_CHECKOUT_DIR/test/e2e/infra/vagrant/ssh-config
    echo "=== Move kubeconfig to master ==="
    ssh -q -o StrictHostKeyChecking=no -i $GIT_CHECKOUT_DIR/jenkins/key/antrea-ci-key -n capv@${master_ip} "if [ ! -d ".kube" ]; then mkdir .kube; fi"
    scp -q -o StrictHostKeyChecking=no -i $GIT_CHECKOUT_DIR/jenkins/key/antrea-ci-key $GIT_CHECKOUT_DIR/jenkins/out/kubeconfig capv@${master_ip}:~/.kube/config
    sed -i "s/CONTROLPLANENODE/${master_name}/g" $GIT_CHECKOUT_DIR/test/e2e/infra/vagrant/ssh-config
    echo "    IdentityFile ${GIT_CHECKOUT_DIR}/jenkins/key/antrea-ci-key" >> $GIT_CHECKOUT_DIR/test/e2e/infra/vagrant/ssh-config

    set +e
    mkdir -p ${GIT_CHECKOUT_DIR}/antrea-test-logs
    if [[ "$COVERAGE" == true ]]; then
        rm -rf ${GIT_CHECKOUT_DIR}/e2e-coverage
        mkdir -p ${GIT_CHECKOUT_DIR}/e2e-coverage
        go test -v -timeout=50m github.com/vmware-tanzu/antrea/test/e2e --logs-export-dir ${GIT_CHECKOUT_DIR}/antrea-test-logs --prometheus --coverage --coverage-dir ${GIT_CHECKOUT_DIR}/e2e-coverage
    else
        go test -v -timeout=50m github.com/vmware-tanzu/antrea/test/e2e --logs-export-dir ${GIT_CHECKOUT_DIR}/antrea-test-logs --prometheus
    fi

    test_rc=$?
    set -e

    if [[ "$test_rc" != "0" ]]; then
        echo "=== TEST FAILURE !!! ==="
        TEST_FAILURE=true
    else
        echo "=== TEST SUCCESS !!! ==="
    fi

    tar -zcf ${GIT_CHECKOUT_DIR}/antrea-test-logs.tar.gz ${GIT_CHECKOUT_DIR}/antrea-test-logs
    if [[ "$COVERAGE" == true ]]; then
        tar -zcf ${GIT_CHECKOUT_DIR}/e2e-coverage.tar.gz ${GIT_CHECKOUT_DIR}/e2e-coverage
        curl -s https://codecov.io/bash | bash -s -- -c -t ${CODECOV_TOKEN} -F e2e-tests -f '*antrea*' -s ${GIT_CHECKOUT_DIR}/e2e-coverage
    fi
}

function run_conformance {
    echo "====== Running Antrea Conformance Tests ======"

    export GO111MODULE=on
    export GOPATH=$WORKDIR/go
    export GOROOT=/usr/local/go
    export GOCACHE=$WORKDIR/.cache/go-build
    export PATH=$GOROOT/bin:$PATH
    export KUBECONFIG=$GIT_CHECKOUT_DIR/jenkins/out/kubeconfig

    antrea_yml="antrea.yml"
    if [[ "$COVERAGE" == true ]]; then
        antrea_yml="antrea-coverage.yml"
    fi

    if [[ "$TESTCASE" == "all-features-conformance" ]]; then
      if [[ "$COVERAGE" == true ]]; then
        $GIT_CHECKOUT_DIR/hack/generate-manifest.sh --mode dev --all-features --coverage > $GIT_CHECKOUT_DIR/build/yamls/antrea-all-coverage.yml
        antrea_yml="antrea-all-coverage.yml"
      else
        $GIT_CHECKOUT_DIR/hack/generate-manifest.sh --mode dev --all-features > $GIT_CHECKOUT_DIR/build/yamls/antrea-all.yml
        antrea_yml="antrea-all.yml"
      fi
    fi

    kubectl apply -f $GIT_CHECKOUT_DIR/build/yamls/$antrea_yml
    kubectl rollout restart deployment/coredns -n kube-system
    kubectl rollout status --timeout=5m deployment/coredns -n kube-system
    kubectl rollout status --timeout=5m deployment.apps/antrea-controller -n kube-system
    kubectl rollout status --timeout=5m daemonset/antrea-agent -n kube-system

    master_ip="$(kubectl get nodes -o wide --no-headers=true | awk '$3 == "master" {print $6}')"
    echo "=== Move kubeconfig to master ==="
    ssh -q -o StrictHostKeyChecking=no -i $GIT_CHECKOUT_DIR/jenkins/key/antrea-ci-key -n capv@${master_ip} "if [ ! -d ".kube" ]; then mkdir .kube; fi"
    scp -q -o StrictHostKeyChecking=no -i $GIT_CHECKOUT_DIR/jenkins/key/antrea-ci-key $GIT_CHECKOUT_DIR/jenkins/out/kubeconfig capv@${master_ip}:~/.kube/config

    if [[ "$TESTCASE" == "conformance" ]]; then
        ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-conformance --log-mode ${MODE} --kubeconfig ${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig > ${GIT_CHECKOUT_DIR}/vmc-test.log
    elif [[ "$TESTCASE" == "all-features-conformance" ]]; then
        ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-conformance --log-mode ${MODE} --kubeconfig ${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig > ${GIT_CHECKOUT_DIR}/vmc-test.log
    elif [[ "$TESTCASE" == "whole-conformance" ]]; then
        ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --kube-conformance-image-version v1.18.12 --e2e-whole-conformance --log-mode ${MODE} --kubeconfig ${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig > ${GIT_CHECKOUT_DIR}/vmc-test.log
    else
        ${GIT_CHECKOUT_DIR}/ci/run-k8s-e2e-tests.sh --e2e-network-policy --log-mode ${MODE} --kubeconfig ${GIT_CHECKOUT_DIR}/jenkins/out/kubeconfig > ${GIT_CHECKOUT_DIR}/vmc-test.log
    fi

    cat ${GIT_CHECKOUT_DIR}/vmc-test.log
    if grep -Fxq "Failed tests:" ${GIT_CHECKOUT_DIR}/vmc-test.log
    then
        echo "Failed cases exist."
        TEST_FAILURE=true
    else
        echo "All tests passed."
    fi

    if [[ "$COVERAGE" == true ]]; then
        rm -rf ${GIT_CHECKOUT_DIR}/conformance-coverage
        mkdir -p ${GIT_CHECKOUT_DIR}/conformance-coverage
        collect_coverage
        tar -zcf ${GIT_CHECKOUT_DIR}/$TESTCASE-coverage.tar.gz ${GIT_CHECKOUT_DIR}/conformance-coverage
        curl -s https://codecov.io/bash | bash -s -- -c -t ${CODECOV_TOKEN} -F e2e-tests -f '*antrea*' -s ${GIT_CHECKOUT_DIR}/conformance-coverage
    fi
}

function collect_coverage() {
        antrea_controller_pod_name="$(kubectl get pods --selector=app=antrea,component=antrea-controller -n kube-system --no-headers=true | awk '{ print $1 }')"
        controller_pid="$(kubectl exec -i $antrea_controller_pod_name -n kube-system -- pgrep antrea)"
        kubectl exec -i $antrea_controller_pod_name -n kube-system -- kill -SIGINT $controller_pid
        timestamp=$(date +%Y%m%d%H%M%S)
        kubectl cp kube-system/$antrea_controller_pod_name:antrea-controller.cov.out ${GIT_CHECKOUT_DIR}/conformance-coverage/$antrea_controller_pod_name-$timestamp

        antrea_agent_pod_names="$(kubectl get pods --selector=app=antrea,component=antrea-agent -n kube-system --no-headers=true | awk '{ print $1 }')"
        for agent in ${antrea_agent_pod_names}
        do
            agent_pid="$(kubectl exec -i $agent -n kube-system -- pgrep antrea)"
            kubectl exec -i $agent -c antrea-agent -n kube-system -- kill -SIGINT $agent_pid
            timestamp=$(date +%Y%m%d%H%M%S)
            kubectl cp kube-system/$agent:antrea-agent.cov.out -c antrea-agent ${GIT_CHECKOUT_DIR}/conformance-coverage/$agent-$timestamp
        done
}

function cleanup_cluster() {
    echo "=== Cleaning up VMC cluster ${CLUSTER} ==="
    export KUBECONFIG=$KUBECONFIG_PATH

    kubectl delete ns ${CLUSTER}
    rm -rf "${GIT_CHECKOUT_DIR}/jenkins"
    echo "=== Cleanup cluster ${CLUSTER} succeeded ==="
}

function garbage_collection() {
    echo "=== Auto cleanup starts ==="
    export KUBECONFIG=$KUBECONFIG_PATH

    kubectl get ns -l antrea-ci -o custom-columns=Name:.metadata.name,DATE:.metadata.creationTimestamp --no-headers=true | awk '{cmd="echo $(( $(date +%s) - $(date -d "$2" +%s) ))"; cmd | getline t ; print $1, t}' | awk '$1 ~ "matrix" && $2 > 14400 {print $1}' | while read cluster; do
        echo "=== Currently ${cluster} has been live for more than 4h ==="
        kubectl delete ns ${cluster}
        echo "=== Old namespace ${cluster} has been deleted !!! ==="
    done

    kubectl get ns -l antrea-ci -o custom-columns=Name:.metadata.name,DATE:.metadata.creationTimestamp --no-headers=true | awk '{cmd="echo $(( $(date +%s) - $(date -d "$2" +%s) ))"; cmd | getline t ; print $1, t}' | awk '$1 ~ "whole-conformance" && $2 > 7200 {print $1}' | while read cluster; do
        echo "=== Currently ${cluster} has been live for more than 2h ==="
        kubectl delete ns ${cluster}
        echo "=== Old namespace ${cluster} has been deleted !!! ==="
    done

    kubectl get ns -l antrea-ci -o custom-columns=Name:.metadata.name,DATE:.metadata.creationTimestamp --no-headers=true | awk '{cmd="echo $(( $(date +%s) - $(date -d "$2" +%s) ))"; cmd | getline t ; print $1, t}' | awk '$1 !~ "matrix" && $1 !~ "whole-conformance" && $2 > 3600 {print $1}' | while read cluster; do
        echo "=== Currently ${cluster} has been live for more than 1h ==="
        kubectl delete ns ${cluster}
        echo "=== Old namespace ${cluster} has been deleted !!! ==="
    done

    echo "=== Auto cleanup finished ==="
}


# ensures that the script can be run from anywhere
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
GIT_CHECKOUT_DIR=${THIS_DIR}/../..
pushd "$THIS_DIR" > /dev/null

if [[ "$RUN_GARBAGE_COLLECTION" == true ]]; then
    garbage_collection
    exit 0
fi

if [[ "$RUN_SETUP_ONLY" == true ]]; then
    setup_cluster
    deliver_antrea
    exit 0
fi

if [[ "$RUN_CLEANUP_ONLY" == true ]]; then
    cleanup_cluster
    exit 0
fi

if [[ "$TESTCASE" != "e2e" && "$TESTCASE" != "conformance" && "$TESTCASE" != "all-features-conformance" && "$TESTCASE" != "whole-conformance" && "$TESTCASE" != "networkpolicy" && "$TESTCASE" != "integration" ]]; then
    echoerr "testcase should be e2e, integration, conformance, whole-conformance or networkpolicy"
    exit 1
fi

if [[ "$TESTCASE" == "integration" ]]; then
    run_integration
elif [[ "$TESTCASE" == "e2e" ]]; then
    if [[ "$RUN_TEST_ONLY" == true ]]; then
        run_e2e
    else
        setup_cluster
        deliver_antrea
        run_e2e
        cleanup_cluster
    fi
else
    if [[ "$RUN_TEST_ONLY" == true ]]; then
        run_conformance
    else
        setup_cluster
        deliver_antrea
        run_conformance
        cleanup_cluster
    fi
fi

if [[ "$TEST_FAILURE" == true ]]; then
    exit 1
fi
