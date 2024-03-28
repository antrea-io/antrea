#!/usr/bin/env bash

# Copyright 2021 Antrea Authors
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

DEFAULT_WORKDIR="/var/lib/jenkins"
WORKDIR=$DEFAULT_WORKDIR
TESTCASE=""
TEST_FAILURE=false
DOCKER_REGISTRY=$(head -n1 "${WORKSPACE}/ci/docker-registry")
MULTICLUSTER_KUBECONFIG_PATH=$WORKDIR/.kube
LEADER_CLUSTER_CONFIG="--kubeconfig=$MULTICLUSTER_KUBECONFIG_PATH/leader"
EAST_CLUSTER_CONFIG="--kubeconfig=$MULTICLUSTER_KUBECONFIG_PATH/east"
WEST_CLUSTER_CONFIG="--kubeconfig=$MULTICLUSTER_KUBECONFIG_PATH/west"
CLUSTER_NAMES=("leader" "east" "west")
ENABLE_MC_GATEWAY=false
IS_CONTAINERD=false
CODECOV_TOKEN=""
COVERAGE=false
KIND=false
DEBUG=false
GOLANG_RELEASE_DIR=${WORKDIR}/golang-releases

multicluster_kubeconfigs=($EAST_CLUSTER_CONFIG $LEADER_CLUSTER_CONFIG $WEST_CLUSTER_CONFIG)
membercluster_kubeconfigs=($EAST_CLUSTER_CONFIG $WEST_CLUSTER_CONFIG)

CLEAN_STALE_IMAGES="docker system prune --force --all --filter until=48h"
PRINT_DOCKER_STATUS="docker system df -v"

CLEAN_STALE_IMAGES_CONTAINERD="crictl rmi --prune"
PRINT_CONTAINERD_STATUS="crictl ps --state Exited"

_usage="Usage: $0 [--kubeconfigs-path <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <e2e>] [--mc-gateway] [--codecov-token] [--coverage] [--kind] [--debug]

Run Antrea multi-cluster e2e tests on a remote (Jenkins) Linux Cluster Set.

        --kubeconfigs-path            Path of cluster set kubeconfigs.
        --workdir                     Home path for Go, antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase                    Antrea multi-cluster e2e test cases on a Linux cluster set.
        --registry                    The docker registry to use instead of dockerhub.
        --mc-gateway                  Enable Multicluster Gateway.
        --codecov-token               Token used to upload coverage report(s) to Codecov.
        --coverage                    Run e2e with coverage.
        --kind                        Run e2e on Kind clusters.
        --debug                       Do not clean up Kind clusters when --kind is set."

function print_usage {
    echoerr "$_usage"
}


while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --kubeconfigs-path)
    MULTICLUSTER_KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --workdir)
    WORKDIR="$2"
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
    --mc-gateway)
    ENABLE_MC_GATEWAY=true
    shift
    ;;
    --codecov-token)
    CODECOV_TOKEN="$2"
    shift 2
    ;;
    --coverage)
    COVERAGE=true
    shift
    ;;
    --kind)
    KIND=true
    shift
    ;;
    --debug)
    DEBUG=true
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

function clean_tmp() {
    echo "===== Clean up stale files & folders older than 7 days under /tmp ====="
    CLEAN_LIST=(
        "*codecov*"
        "kustomize-*"
        "*antrea*"
        "go-build*"
    )
    for item in "${CLEAN_LIST[@]}"; do
        find /tmp -name "${item}" -mtime +7 -exec rm -rf {} \; 2>&1 | grep -v "Permission denied" || true
    done
    find ${WORKDIR} -name "support-bundles*" -mtime +7 -exec rm -rf {} \; 2>&1 | grep -v "Permission denied" || true
}

function clean_images() {
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -E 'mc-controller|antrea-ubuntu' | xargs -r docker rmi -f || true
    # Clean up dangling images generated in previous builds.
    docker image prune -f --filter "until=24h" || true > /dev/null
    check_and_cleanup_docker_build_cache
}

function cleanup_multicluster_ns {
    ns=$1
    kubeconfig=$2

    kubectl delete ns "${ns}" --ignore-not-found=true ${kubeconfig} --timeout=30s || true
}

function cleanup_multicluster_controller {
    echo "====== Cleanup Multicluster Controller Installation ======"
    kubeconfig=$1
    for multicluster_yml in ${WORKSPACE}/multicluster/test/yamls/*.yml; do
        kubectl delete -f $multicluster_yml $kubeconfig --ignore-not-found=true  --timeout=30s || true
    done

    for multicluster_yml in ${WORKSPACE}/multicluster/build/yamls/*.yml; do
        kubectl delete -f $multicluster_yml $kubeconfig --ignore-not-found=true --timeout=30s || true
    done
}

function cleanup_multicluster_antrea {
    echo "====== Cleanup Antrea controller and agent ======"
    kubeconfig=$1
    kubectl delete -f build/yamls/antrea.yml --ignore-not-found=true ${kubeconfig} --timeout=30s || true
}

function clean_multicluster {
    if [[ ${KIND} == "true" ]]; then
        if [[ $DEBUG != "true" ]]; then
            echo "====== Cleanup Kind clusters ======"
            for name in ${CLUSTER_NAMES[*]}; do
                ./ci/kind/kind-setup.sh destroy ${name}
            done
        fi
    else
        echo "====== Cleanup Multicluster Antrea Installation in clusters ======"
        for kubeconfig in "${multicluster_kubeconfigs[@]}"
        do
            cleanup_multicluster_ns "antrea-multicluster-test" $kubeconfig
            cleanup_multicluster_ns "antrea-multicluster" $kubeconfig
            cleanup_multicluster_controller $kubeconfig
            cleanup_multicluster_antrea $kubeconfig
        done
    fi
}

function wait_for_antrea_multicluster_pods_ready {
    kubeconfig=$1
    kubectl apply -f build/yamls/antrea.yml "${kubeconfig}"
    kubectl rollout restart deployment/coredns -n kube-system "${kubeconfig}"
    kubectl rollout status deployment/coredns -n kube-system "${kubeconfig}"
    kubectl rollout status deployment.apps/antrea-controller -n kube-system "${kubeconfig}"
    kubectl rollout status daemonset/antrea-agent -n kube-system "${kubeconfig}"
}

function wait_for_multicluster_controller_ready {
    echo "====== Deploying Antrea Multicluster Leader Cluster with ${LEADER_CLUSTER_CONFIG} ======"
    leader_cluster_pod_cidr="10.244.0.0/20"
    export leader_cluster_pod_cidr
    perl -0777 -pi -e 's|    podCIDRs\:\n      - \"\"|    podCIDRs\:\n      - $ENV{leader_cluster_pod_cidr}|g' ./multicluster/test/yamls/leader-manifest.yml
    kubectl create ns antrea-multicluster  "${LEADER_CLUSTER_CONFIG}" || true
    kubectl apply -f ./multicluster/test/yamls/leader-manifest.yml "${LEADER_CLUSTER_CONFIG}"
    kubectl rollout status deployment/antrea-mc-controller -n antrea-multicluster "${LEADER_CLUSTER_CONFIG}" || true
    kubectl create -f ./multicluster/test/yamls/leader-access-token-secret.yml "${LEADER_CLUSTER_CONFIG}" || true
    kubectl get secret -n antrea-multicluster leader-access-token "${LEADER_CLUSTER_CONFIG}" -o yaml > ./multicluster/test/yamls/leader-access-token.yml

    sed -i '/uid:/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/resourceVersion/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/last-applied-configuration/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/type/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i '/creationTimestamp/d' ./multicluster/test/yamls/leader-access-token.yml
    sed -i 's/antrea-multicluster-member-access-sa/antrea-multicluster-controller/g' ./multicluster/test/yamls/leader-access-token.yml
    sed -i 's/antrea-multicluster/kube-system/g' ./multicluster/test/yamls/leader-access-token.yml
    echo "type: Opaque" >> ./multicluster/test/yamls/leader-access-token.yml

    member_cluster_pod_cidrs=("10.244.16.0/20" "10.244.32.0/20")
    for i in "${!membercluster_kubeconfigs[@]}";
    do
        pod_cidr=${member_cluster_pod_cidrs[$i]}
        export pod_cidr
        cp ./multicluster/test/yamls/member-manifest.yml ./multicluster/test/yamls/member-manifest-$i.yml
        perl -0777 -pi -e 's|    podCIDRs\:\n      - \"\"|    podCIDRs\:\n      - $ENV{pod_cidr}|g' ./multicluster/test/yamls/member-manifest-$i.yml

        config=${membercluster_kubeconfigs[$i]}
        echo "====== Deploying Antrea Multicluster Member Cluster with ${config} ======"
        kubectl apply -f ./multicluster/test/yamls/member-manifest-$i.yml ${config}
        kubectl rollout status deployment/antrea-mc-controller -n kube-system ${config}
        kubectl apply -f ./multicluster/test/yamls/leader-access-token.yml ${config}
    done

    echo "====== ClusterSet Initialization in Leader and Member Clusters ======"
    kubectl apply -f ./multicluster/test/yamls/east-member-cluster.yml "${EAST_CLUSTER_CONFIG}"
    kubectl apply -f ./multicluster/test/yamls/west-member-cluster.yml "${WEST_CLUSTER_CONFIG}"
    kubectl apply -f ./multicluster/test/yamls/clusterset.yml "${LEADER_CLUSTER_CONFIG}"
}

# We run the function in a subshell with "set -e" to ensure that it exits in
# case of error (e.g. integrity check), no matter the context in which the
# function is called.
function run_codecov { (set -e
    flag=$1
    file=$2
    dir=$3

    rm -f trustedkeys.gpg codecov
    # This is supposed to be a one-time step, but there should be no harm in
    # getting the key every time. It does not come from the codecov.io
    # website. Anyway, this is needed when the VM is re-created for every test.
    curl https://keybase.io/codecovsecurity/pgp_keys.asc | gpg --no-default-keyring --keyring trustedkeys.gpg --import
    curl -Os https://uploader.codecov.io/latest/linux/codecov
    curl -Os https://uploader.codecov.io/latest/linux/codecov.SHA256SUM
    curl -Os https://uploader.codecov.io/latest/linux/codecov.SHA256SUM.sig

    # Check that the sha256 matches the signature
    gpgv codecov.SHA256SUM.sig codecov.SHA256SUM
    # Then check the integrity of the codecov binary
    shasum -a 256 -c codecov.SHA256SUM

    chmod +x codecov
    ./codecov -c -t ${CODECOV_TOKEN} -F ${flag} -f ${file} -s ${dir} -C ${GIT_COMMIT} -r antrea-io/antrea

    rm -f trustedkeys.gpg codecov
)}

function modify_config {
  if [[ ${ENABLE_MC_GATEWAY} == "true" ]]; then
  cat > build/yamls/chart-values/antrea.yml << EOF
multicluster:
  enableGateway: true
  enableStretchedNetworkPolicy: true
  enablePodToPodConnectivity: true
featureGates: {
  Multicluster: true
}
EOF
  make manifest
  cd multicluster
  sed -i 's/enableStretchedNetworkPolicy: false/enableStretchedNetworkPolicy: true/g' config/default/configmap/controller_manager_config.yaml
  make manifests
  cd ..
  fi
}

function deliver_antrea_multicluster {
    echo "====== Building Antrea for the Following Commit ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export PATH=${GOROOT}/bin:$PATH

    git show --numstat
    make clean

    # Ensure that files in the Docker context have the correct permissions, or Docker caching cannot
    # be leveraged successfully
    chmod -R g-w build/images/ovs
    chmod -R g-w build/images/base

    DOCKER_REGISTRY="${DOCKER_REGISTRY}" ./hack/build-antrea-linux-all.sh --pull
    echo "====== Delivering Antrea to all Nodes ======"
    docker save -o ${WORKDIR}/antrea-ubuntu.tar antrea/antrea-agent-ubuntu:latest antrea/antrea-controller-ubuntu:latest


    if [[ ${KIND} == "true" ]]; then
        for name in ${CLUSTER_NAMES[*]}; do
            kind load docker-image antrea/antrea-agent-ubuntu:latest --name ${name}
            kind load docker-image antrea/antrea-controller-ubuntu:latest --name ${name}
        done
    else
        for kubeconfig in "${multicluster_kubeconfigs[@]}"
        do
            kubectl get nodes -o wide --no-headers=true ${kubeconfig}| awk '{print $6}' | while read IP; do
                 rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/antrea-ubuntu.tar jenkins@[${IP}]:${WORKDIR}/antrea-ubuntu.tar
                 if ${IS_CONTAINERD};then
                   ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; sudo ctr -n=k8s.io images import ${WORKDIR}/antrea-ubuntu.tar" || true
                 else
                   ssh -o StrictHostKeyChecking=no -n jenkins@${IP} "${CLEAN_STALE_IMAGES}; ${PRINT_DOCKER_STATUS}; docker load -i ${WORKDIR}/antrea-ubuntu.tar" || true
                 fi
            done
        done
    fi
}

function deliver_multicluster_controller {
    echo "====== Build Antrea Multiple Cluster Controller and YAMLs ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export PATH=${GOROOT}/bin:$PATH

    DEFAULT_IMAGE=antrea/antrea-mc-controller:latest
    if $COVERAGE;then
        export NO_PULL=1;make build-antrea-mc-controller-coverage
        DEFAULT_IMAGE=antrea/antrea-mc-controller-coverage:latest
        docker save "${DEFAULT_IMAGE}" -o "${WORKDIR}"/antrea-mcs.tar
        ./multicluster/hack/generate-manifest.sh -l antrea-multicluster -c > ./multicluster/test/yamls/leader-manifest.yml
        ./multicluster/hack/generate-manifest.sh -m -c > ./multicluster/test/yamls/member-manifest.yml
    else
        export NO_PULL=1;make build-antrea-mc-controller
        docker save "${DEFAULT_IMAGE}" -o "${WORKDIR}"/antrea-mcs.tar
        ./multicluster/hack/generate-manifest.sh -l antrea-multicluster > ./multicluster/test/yamls/leader-manifest.yml
        ./multicluster/hack/generate-manifest.sh -m > ./multicluster/test/yamls/member-manifest.yml
    fi

    if [[ ${KIND} == "true" ]]; then
        for name in ${CLUSTER_NAMES[*]}; do
            kind load docker-image ${DEFAULT_IMAGE} --name ${name}
        done
    else
        for kubeconfig in "${multicluster_kubeconfigs[@]}"
        do
            kubectl get nodes -o wide --no-headers=true "${kubeconfig}" | awk '{print $6}' | while read IP; do
                rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/antrea-mcs.tar jenkins@[${IP}]:${WORKDIR}/antrea-mcs.tar
                if ${IS_CONTAINERD};then
                  ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; sudo ctr -n=k8s.io images import ${WORKDIR}/antrea-mcs.tar" || true
                else
                  ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "${CLEAN_STALE_IMAGES}; ${PRINT_DOCKER_STATUS}; docker load -i ${WORKDIR}/antrea-mcs.tar" || true
                fi
            done
        done
    fi

    leader_ip=$(kubectl get nodes -o wide --no-headers=true ${LEADER_CLUSTER_CONFIG} | awk -v role1="master" -v role2="control-plane" '($3 ~ role1 || $3 ~ role2) {print $6}')
    sed -i "s|<LEADER_CLUSTER_IP>|${leader_ip}|" ./multicluster/test/yamls/east-member-cluster.yml
    sed -i "s|<LEADER_CLUSTER_IP>|${leader_ip}|" ./multicluster/test/yamls/west-member-cluster.yml
    if [[ ${KIND} == "true" ]]; then
        docker cp ./multicluster/test/yamls/test-acnp-copy-span-ns-isolation.yml leader-control-plane:/root/test-acnp-copy-span-ns-isolation.yml
        docker cp ./multicluster/test/yamls/test-acnp-cross-cluster-ns-isolation.yml leader-control-plane:/root/test-acnp-cross-cluster-ns-isolation.yml
    else
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" ./multicluster/test/yamls/test-acnp-copy-span-ns-isolation.yml jenkins@["${leader_ip}"]:"${WORKDIR}"/test-acnp-copy-span-ns-isolation.yml
        rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" ./multicluster/test/yamls/test-acnp-cross-cluster-ns-isolation.yml jenkins@["${leader_ip}"]:"${WORKDIR}"/test-acnp-cross-cluster-ns-isolation.yml
    fi

    for kubeconfig in "${membercluster_kubeconfigs[@]}"
    do
        # Remove the longest matched substring '*/' from a string like '--kubeconfig=/var/lib/jenkins/.kube/east'
        # to get the last element which is the cluster name.
        cluster=${kubeconfig##*/}
        if [[ ${KIND} == "true" ]]; then
            docker cp ./multicluster/test/yamls/test-${cluster}-serviceexport.yml ${cluster}-control-plane:/root/serviceexport.yml
        else
            ip=$(kubectl get nodes -o wide --no-headers=true ${kubeconfig} | awk -v role1="master" -v role2="control-plane" '($3 ~ role1 || $3 ~ role2) {print $6}')
            rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" ./multicluster/test/yamls/test-${cluster}-serviceexport.yml jenkins@["${ip}"]:"${WORKDIR}"/serviceexport.yml
        fi
    done
}

function run_multicluster_e2e {
    echo "====== Running Multicluster e2e Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=${GOLANG_RELEASE_DIR}/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    wait_for_antrea_multicluster_pods_ready "${LEADER_CLUSTER_CONFIG}"
    wait_for_antrea_multicluster_pods_ready "${EAST_CLUSTER_CONFIG}"
    wait_for_antrea_multicluster_pods_ready "${WEST_CLUSTER_CONFIG}"

    wait_for_multicluster_controller_ready

    docker pull "${DOCKER_REGISTRY}"/antrea/nginx:1.21.6-alpine
    docker save "${DOCKER_REGISTRY}"/antrea/nginx:1.21.6-alpine -o "${WORKDIR}"/nginx.tar

    # Use the same agnhost image which is defined as 'agnhostImage' in antrea/test/e2e/framework.go to
    # avoid pulling the image again when running Multi-cluster e2e tests.
    docker pull "registry.k8s.io/e2e-test-images/agnhost:2.29"
    docker save "registry.k8s.io/e2e-test-images/agnhost:2.29" -o "${WORKDIR}"/agnhost.tar

    if [[ ${KIND} == "true" ]]; then
        for name in ${CLUSTER_NAMES[*]}; do
            if [[ "${name}" == "leader" ]];then
                continue
            fi
            kind load docker-image "${DOCKER_REGISTRY}"/antrea/nginx:1.21.6-alpine --name ${name}
            kind load docker-image "registry.k8s.io/e2e-test-images/agnhost:2.29" --name ${name}
        done
    else
        for kubeconfig in "${membercluster_kubeconfigs[@]}"; do
            kubectl get nodes -o wide --no-headers=true "${kubeconfig}"| awk '{print $6}' | while read IP; do
                rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/nginx.tar jenkins@["${IP}"]:"${WORKDIR}"/nginx.tar
                rsync -avr --progress --inplace -e "ssh -o StrictHostKeyChecking=no" "${WORKDIR}"/agnhost.tar jenkins@["${IP}"]:"${WORKDIR}"/agnhost.tar
            if ${IS_CONTAINERD};then
                ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "${CLEAN_STALE_IMAGES_CONTAINERD}; ${PRINT_CONTAINERD_STATUS}; sudo ctr -n=k8s.io images import ${WORKDIR}/nginx.tar" || true
                ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "sudo ctr -n=k8s.io images import ${WORKDIR}/agnhost.tar" || true
            else
                ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "${CLEAN_STALE_IMAGES}; ${PRINT_DOCKER_STATUS}; docker load -i ${WORKDIR}/nginx.tar" || true
                ssh -o StrictHostKeyChecking=no -n jenkins@"${IP}" "docker load -i ${WORKDIR}/agnhost.tar" || true
            fi
            done
        done
    fi

    set +e
    CURRENT_DIR=`pwd`
    mkdir -p ${CURRENT_DIR}/antrea-multicluster-test-logs
    options=""
    if [[ ${ENABLE_MC_GATEWAY} == "true" ]]; then
        options="--mc-gateway"
    fi
    if [[ ${KIND} == "true" ]]; then
        options+=" --provider kind"
    fi

    set -x
    go test -v -timeout=15m antrea.io/antrea/multicluster/test/e2e --logs-export-dir `pwd`/antrea-multicluster-test-logs $options
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    set +x
    set -e

    tar -zcf antrea-test-logs.tar.gz antrea-multicluster-test-logs
}

function collect_coverage {
    COVERAGE_DIR=$1
    timestamp=$(date +%Y%m%d%H%M%S)
    echo "====== Collect Multicluster e2e Tests Coverage Files ======"
    for kubeconfig in "${multicluster_kubeconfigs[@]}"; do
      namespace="kube-system"
      if [[ ${kubeconfig} =~ "leader" ]];then
        namespace="antrea-multicluster"
      fi
      mc_controller_pod_name="$(kubectl get pods --selector=app=antrea,component=antrea-mc-controller -n ${namespace} --no-headers=true ${kubeconfig} | awk '{ print $1 }')"
      controller_pid="$(kubectl exec -i $mc_controller_pod_name -n ${namespace} ${kubeconfig} -- pgrep antrea)"
      kubectl exec -i $mc_controller_pod_name -n ${namespace} ${kubeconfig} -- kill -SIGINT $controller_pid
      kubectl cp ${namespace}/$mc_controller_pod_name:antrea-mc-controller.cov.out ${COVERAGE_DIR}/$mc_controller_pod_name-$timestamp ${kubeconfig}
    done
}

trap clean_multicluster EXIT
source $WORKSPACE/ci/jenkins/utils.sh
check_and_upgrade_golang
clean_tmp
clean_images

if [[ ${KIND} == "true" ]]; then
    # Preparing a ClusterSet contains three Kind clusters.
    SERVICE_CIDRS=("10.96.10.0/24" "10.96.20.0/24" "10.96.30.0/24")
    POD_CIDRS=("10.244.0.0/20" "10.244.16.0/20" "10.244.32.0/20")
    for i in {0..2}; do
        ./ci/kind/kind-setup.sh create ${CLUSTER_NAMES[$i]} --service-cidr ${SERVICE_CIDRS[$i]} --pod-cidr ${POD_CIDRS[$i]} --num-workers 1
    done

    for name in ${CLUSTER_NAMES[*]}; do
        kind get kubeconfig --name ${name} > ${MULTICLUSTER_KUBECONFIG_PATH}/${name}
        set +e
        kubectl taint node ${name}-control-plane --kubeconfig=${MULTICLUSTER_KUBECONFIG_PATH}/${name} node-role.kubernetes.io/master-
        kubectl taint node ${name}-control-plane --kubeconfig=${MULTICLUSTER_KUBECONFIG_PATH}/${name} node-role.kubernetes.io/control-plane-
        set -e
    done
fi

# We assume all clusters in one testing ClusterSet are using the same runtime,
# so check leader cluster only to set IS_CONTAINERD.
set +e
kubectl get nodes -o wide --no-headers=true ${LEADER_CLUSTER_CONFIG} | grep containerd
if [[ $? -eq 0 ]];then
    IS_CONTAINERD=true
fi
set -e

if [[ ${TESTCASE} =~ "e2e" ]]; then
    deliver_antrea_multicluster
    modify_config
    deliver_multicluster_controller
    run_multicluster_e2e
    if $COVERAGE;then
      CURRENT_DIR=`pwd`
      rm -rf mc-e2e-coverage
      mkdir -p mc-e2e-coverage
      collect_coverage ${CURRENT_DIR}/mc-e2e-coverage
      # Backup coverage files for later analysis
      set +e;find ${DEFAULT_WORKDIR}/mc-e2e-coverage -maxdepth 1 -mtime +1 -type f | xargs -n 1 rm;set -e; # Clean up backup files older than one day.
      cp -r mc-e2e-coverage ${DEFAULT_WORKDIR}
      run_codecov "e2e-tests" "*antrea-mc*" "${CURRENT_DIR}/mc-e2e-coverage"
    fi
fi

if [[ ${TEST_FAILURE} == true ]]; then
    exit 1
fi
