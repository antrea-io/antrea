#!/usr/bin/env bash

# Copyright 2022 Antrea Authors
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
DEFAULT_KUBECONFIG_PATH=$DEFAULT_WORKDIR/.kube/config
WORKDIR=$DEFAULT_WORKDIR
KUBECONFIG_PATH=$DEFAULT_KUBECONFIG_PATH
COVERAGE=false
CODECOV_TOKEN=""
DOCKER_REGISTRY=""

_usage="Usage: $0 [--kubeconfig <KubeconfigSavePath>] [--workdir <HomePath>]
                  [--testcase <unit|integration>]
                  [--coverage] [--codecov-token] [--registry]

Run unit and integration tests.

        --kubeconfig             Path of cluster kubeconfig.
        --workdir                Home path for Go, vSphere information and antrea_logs during cluster setup. Default is $WORKDIR.
        --testcase               The testcase to run: unit, integration tests.
        --coverage               Run unit and integration with coverage.
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
    --kubeconfig)
    KUBECONFIG_PATH="$2"
    shift 2
    ;;
    --workdir)
    WORKDIR="$2"
    shift 2
    ;;
    --registry)
    DOCKER_REGISTRY="$2"
    shift 2
    ;;
    --coverage)
    COVERAGE=true
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

# If DOCKER_REGISTRY is non null, we ensure that "make" commands never pull from docker.io.
NO_PULL=
if [[ ${DOCKER_REGISTRY} != "" ]]; then
    NO_PULL=1
fi
export NO_PULL

function run_codecov { (set -e
    flag=$1
    file=$2
    dir=$3
    remote=$4
    ip=$5

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

    if [[ $remote == true ]]; then
        ${SCP_WITH_UTILS_KEY} codecov jenkins@${ip}:~
        ${SSH_WITH_UTILS_KEY} -n jenkins@${ip} "cd antrea; ~/codecov -c -t ${CODECOV_TOKEN} -F ${flag} -f ${file} -C ${GIT_COMMIT} -r antrea-io/antrea"
    else
        ./codecov -c -t ${CODECOV_TOKEN} -F ${flag} -f ${file} -s ${dir} -C ${GIT_COMMIT} -r antrea-io/antrea
    fi
    rm -f trustedkeys.gpg codecov
)}

function run_integration {
    flag=$1
    VM_NAME="antrea-integration-0"
    export GOVC_INSECURE=1
    export GOVC_URL=${GOVC_URL}
    export GOVC_USERNAME=${GOVC_USERNAME}
    export GOVC_PASSWORD=${GOVC_PASSWORD}
    VM_IP=$(govc vm.ip ${VM_NAME})
    govc snapshot.revert -vm.ip ${VM_IP} initial
    VM_IP=$(govc vm.ip ${VM_NAME}) # wait for VM to be on

    set -x
    if [[ ${flag} == "multicluster" ]];then
      echo "===== Run Multi-cluster Integration tests ====="
      # umask ensures that files are cloned with the correct permissions so that Docker caching can be leveraged
      ${SSH_WITH_UTILS_KEY} -n jenkins@${VM_IP} "PATH=$PATH:/usr/local/go/bin && umask 0022 && git clone ${ghprbAuthorRepoGitUrl} antrea && cd antrea && git checkout ${GIT_BRANCH} && cd multicluster && NO_LOCAL=true make test-integration"
      if [[ "$COVERAGE" == true ]]; then
        run_codecov "mc-integration-tests" "coverage-integration.txt" "" true ${VM_IP}
      fi
    else
      echo "===== Run Integration tests ====="
      # umask ensures that files are cloned with the correct permissions so that Docker caching can be leveraged
      ${SSH_WITH_UTILS_KEY} -n jenkins@${VM_IP} "umask 0022 && git clone ${ghprbAuthorRepoGitUrl} antrea && cd antrea && git checkout ${GIT_BRANCH} && DOCKER_REGISTRY=${DOCKER_REGISTRY} ./build/images/ovs/build.sh --pull && NO_PULL=${NO_PULL} make docker-test-integration"
      if [[ "$COVERAGE" == true ]]; then
        run_codecov "integration-tests" "coverage-integration.txt" "" true ${VM_IP}
      fi
    fi
}

function run_unit {
    echo "====== Running Antrea UNIT Tests ======"
    export GO111MODULE=on
    export GOPATH=${WORKDIR}/go
    export GOROOT=/usr/local/go
    export GOCACHE=${WORKDIR}/.cache/go-build
    export PATH=$GOROOT/bin:$PATH

    mkdir -p "${WORKDIR}/.kube"
    mkdir -p "${WORKDIR}/.ssh"
    cp -f "${WORKDIR}/kube.conf" "${WORKDIR}/.kube/config"
    generate_ssh_config

    set +e
    mkdir -p `pwd`/antrea-test-logs
    set +e
    mkdir -p ${GIT_CHECKOUT_DIR}/antrea-test-logs
    if [[ "$COVERAGE" == true ]]; then
        rm -rf ${GIT_CHECKOUT_DIR}/unit-coverage
        mkdir -p ${GIT_CHECKOUT_DIR}/unit-coverag
        
    go test -v antrea.io/antrea --logs-export-dir `pwd`/antrea-test-logs --provider remote -timeout=100m --prometheus
    if [[ "$?" != "0" ]]; then
        TEST_FAILURE=true
    fi
    
    set -e
    tar -zcf antrea-test-logs.tar.gz antrea-test-logs
     tar -zcf ${GIT_CHECKOUT_DIR}/antrea-test-logs.tar.gz ${GIT_CHECKOUT_DIR}/antrea-test-logs
    if [[ "$COVERAGE" == true ]]; then
        tar -zcf ${GIT_CHECKOUT_DIR}/unit-coverage.tar.gz ${GIT_CHECKOUT_DIR}/unit-coverage
        run_codecov "unit-tests" "*.cov.out*" "${GIT_CHECKOUT_DIR}/unit-coverage" false ""
    fi
}

if [[ "$TESTCASE" == "integration" ]]; then
    run_integration
    exit 0
fi

if [[ "$TESTCASE" == "unit" ]]; then
    run_unit
    exit 0
fi