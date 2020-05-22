#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
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

_usage="Usage: $0 [--mode (dev|release)] [--kind] [--ipsec] [--keep] [--help|-h]
Generate a YAML manifest for Antrea using Kustomize and print it to stdout.
        --mode (dev|release)  Choose the configuration variant that you need (default is 'dev')
        --encap-mode          Traffic encapsulation mode. (default is 'encap')
        --kind                Generate a manifest appropriate for running Antrea in a Kind cluster
        --cloud               Generate a manifest appropriate for running Antrea in Public Cloud
        --ipsec               Generate a manifest with IPSec encryption of tunnel traffic enabled
        --np                  Generate a manifest with Namespaced Antrea NetworkPolicy CRDs enabled
        --keep                Debug flag which will preserve the generated kustomization.yml
        --help, -h            Print this message and exit

In 'release' mode, environment variables IMG_NAME and IMG_TAG must be set.

This tool uses kustomize (https://github.com/kubernetes-sigs/kustomize) to generate manifests for
Antrea. You can set the KUSTOMIZE environment variable to the path of the kustomize binary you want
us to use. Otherwise we will look for kustomize in your PATH and your GOPATH. If we cannot find
kustomize there, we will try to install it."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
KIND=false
IPSEC=false
NP=false
KEEP=false
ENCAP_MODE=""
CLOUD=""

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --mode)
    MODE="$2"
    shift 2
    ;;
    --encap-mode)
    ENCAP_MODE="$2"
    shift 2
    ;;
    --cloud)
    CLOUD="$2"
    shift 2
    ;;
    --kind)
    KIND=true
    shift
    ;;
    --ipsec)
    IPSEC=true
    shift
    ;;
    --np)
    NP=true
    shift
    ;;
    --keep)
    KEEP=true
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

if [ "$MODE" != "dev" ] && [ "$MODE" != "release" ]; then
    echoerr "--mode must be one of 'dev' or 'release'"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_NAME" ]; then
    echoerr "In 'release' mode, environment variable IMG_NAME must be set"
    print_help
    exit 1
fi

if [ "$MODE" == "release" ] && [ -z "$IMG_TAG" ]; then
    echoerr "In 'release' mode, environment variable IMG_TAG must be set"
    print_help
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/verify-kustomize.sh

if [ -z "$KUSTOMIZE" ]; then
    KUSTOMIZE="$(verify_kustomize)"
elif ! $KUSTOMIZE version > /dev/null 2>&1; then
    echoerr "$KUSTOMIZE does not appear to be a valid kustomize binary"
    print_help
    exit 1
fi

KUSTOMIZATION_DIR=$THIS_DIR/../build/yamls

TMP_DIR=$(mktemp -d $KUSTOMIZATION_DIR/overlays.XXXXXXXX)

pushd $TMP_DIR > /dev/null

BASE=../../base

# do all ConfigMap edits
mkdir configMap && cd configMap
# user is not expected to make changes directly to antrea-agent.conf but instead to the generated
# YAML manifest, so our regexs need not be too robust.
cp $KUSTOMIZATION_DIR/base/conf/antrea-agent.conf antrea-agent.conf
if $KIND; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*ovsDatapathType[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/ovsDatapathType: netdev/" antrea-agent.conf
fi

if $IPSEC; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*enableIPSecTunnel[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/enableIPSecTunnel: true/" antrea-agent.conf
    # change the tunnel type to GRE which works better with IPSec encryption than other types.
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*tunnelType[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/tunnelType: gre/" antrea-agent.conf
fi

if [[ $ENCAP_MODE != "" ]]; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*trafficEncapMode[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/trafficEncapMode: $ENCAP_MODE/" antrea-agent.conf
fi

# unfortunately 'kustomize edit add configmap' does not support specifying 'merge' as the behavior,
# which is why we use a template kustomization file.
sed -e "s/<CONF_FILE>/antrea-agent.conf/" ../../patches/kustomization.configMap.tpl.yml > kustomization.yml
$KUSTOMIZE edit add base $BASE
BASE=../configMap
cd ..

if $IPSEC; then
    mkdir ipsec && cd ipsec
    # we copy the patch files to avoid having to use the '--load-restrictor. flag when calling
    # 'kustomize build'. See https://github.com/kubernetes-sigs/kustomize/blob/master/docs/FAQ.md#security-file-foo-is-not-in-or-below-bar
    cp ../../patches/ipsec/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    # create a K8s Secret to save the PSK (pre-shared key) for IKE authentication.
    $KUSTOMIZE edit add resource ipsecSecret.yml
    # add a container to the Agent DaemonSet that runs the OVS IPSec and strongSwan daemons.
    $KUSTOMIZE edit add patch ipsecContainer.yml
    # add an environment variable to the antrea-agent container for passing the PSK to Agent.
    $KUSTOMIZE edit add patch pskEnv.yml
    BASE=../ipsec
    cd ..
fi

if $NP; then
    mkdir np && cd np
    cp ../../patches/np/*.yml .
    cp ../../base/security-crds.yml .
    cp ../../base/endpoint-crds.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    # add RBAC to antrea-controller for NP CRD access.
    $KUSTOMIZE edit add patch npRbac.yml
    # create NetworkPolicy related CRDs.
    $KUSTOMIZE edit add resource security-crds.yml
    # create ExternalEntity related CRDs.
    $KUSTOMIZE edit add resource endpoint-crds.yml
    BASE=../np
    cd ..
fi

if [[ $ENCAP_MODE == "networkPolicyOnly" ]] ; then
    mkdir chaining && cd chaining
    cp ../../patches/chaining/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    # change initContainer script and add antrea to CNI chain
    $KUSTOMIZE edit add patch installCni.yml
    BASE=../chaining
    cd ..
fi

if [[ $CLOUD == "GKE" ]]; then
    mkdir gke && cd gke
    cp ../../patches/gke/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch cniPath.yml
    BASE=../gke
    cd ..
fi

if [[ $CLOUD == "EKS" ]]; then
    mkdir eks && cd eks
    cp ../../patches/eks/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch eksEnv.yml
    BASE=../eks
    cd ..
fi

if $KIND; then
    mkdir kind && cd kind
    cp ../../patches/kind/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE

    # add tun device to antrea OVS container
    $KUSTOMIZE edit add patch tunDevice.yml
    # antrea-ovs should use start_ovs_netdev instead of start_ovs to ensure that the br_phy bridge
    # is created.
    $KUSTOMIZE edit add patch startOvs.yml
    # change initContainer script and remove SYS_MODULE capability
    $KUSTOMIZE edit add patch installCni.yml

    BASE=../kind
    cd ..
fi

mkdir $MODE && cd $MODE
touch kustomization.yml
$KUSTOMIZE edit add base $BASE
# ../../patches/$MODE may be empty so we use find and not simply cp
find ../../patches/$MODE -name \*.yml -exec cp {} . \;

if [ "$MODE" == "dev" ]; then
    $KUSTOMIZE edit set image antrea=antrea/antrea-ubuntu:latest
    $KUSTOMIZE edit add patch agentImagePullPolicy.yml
    $KUSTOMIZE edit add patch controllerImagePullPolicy.yml
    # only required because there is no good way at the moment to update the imagePullPolicy for all
    # containers. See https://github.com/kubernetes-sigs/kustomize/issues/1493
    if $IPSEC; then
        $KUSTOMIZE edit add patch agentIpsecImagePullPolicy.yml
    fi
fi

if [ "$MODE" == "release" ]; then
    $KUSTOMIZE edit set image antrea=$IMG_NAME:$IMG_TAG
fi

$KUSTOMIZE build

popd > /dev/null

if $KEEP; then
    echoerr "Kustomization file is at $TMP_DIR/$MODE/kustomization.yml"
else
    rm -rf $TMP_DIR
fi
