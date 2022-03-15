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

_usage="Usage: $0 [--mode (dev|release)] [--encap-mode] [--ipsec] [--no-proxy] [--no-np] [--keep] [--tun (geneve|vxlan|gre|stt)] [--verbose-log] [--help|-h]
Generate a YAML manifest for Antrea using Kustomize and print it to stdout.
        --mode (dev|release)          Choose the configuration variant that you need (default is 'dev')
        --encap-mode                  Traffic encapsulation mode. (default is 'encap')
        --cloud                       Generate a manifest appropriate for running Antrea in Public Cloud
        --ipsec                       Generate a manifest with IPsec encryption of tunnel traffic enabled
        --all-features                Generate a manifest with all alpha features enabled
        --no-proxy                    Generate a manifest with Antrea proxy disabled
        --proxy-all                   Generate a manifest with Antrea proxy with all Service support enabled
        --no-legacy-crd               Generate a manifest without legacy CRD mirroring support enabled
        --endpointslice               Generate a manifest with EndpointSlice support enabled
        --no-np                       Generate a manifest with Antrea-native policies disabled
        --keep                        Debug flag which will preserve the generated kustomization.yml
        --tun (geneve|vxlan|gre|stt)  Choose encap tunnel type from geneve, gre, stt and vxlan (default is geneve)
        --verbose-log                 Generate a manifest with increased log-level (level 4) for Antrea agent and controller.
                                      This option will work only in 'dev' mode.
        --on-delete                   Generate a manifest with antrea-agent's update strategy set to OnDelete.
                                      This option will work only in 'dev' mode.
        --coverage                    Generates a manifest which supports measuring code coverage of Antrea binaries.
        --simulator                   Generates a manifest with antrea-agent simulator included
        --custom-adm-controller       Generates a manifest with custom Antrea admission controller to validate/mutate resources.
        --hw-offload                  Generates a manifest with hw-offload enabled in the antrea-ovs container.
        --sriov                       Generates a manifest which enables use of Kubelet API for SR-IOV device info.
        --flexible-ipam               Generates a manifest with flexible IPAM enabled.
        --whereabouts                 Generates a manifest which enables whereabouts configuration for secondary network IPAM.
        --help, -h                    Print this message and exit
        --multicast                   Generates a manifest for multicast.
        --multicast-interfaces        Multicast interface names (default is empty)

In 'release' mode, environment variables IMG_NAME and IMG_TAG must be set.

In 'dev' mode, environment variable IMG_NAME can be set to use a custom image.

This tool uses kustomize (https://github.com/kubernetes-sigs/kustomize) to generate manifests for
Antrea. You can set the KUSTOMIZE environment variable to the path of the kustomize binary you want
us to use. Otherwise we will download the appropriate version of the kustomize binary and use
it (this is the recommended approach since different versions of kustomize may create different
output YAMLs)."

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 --help' for more information."
}

MODE="dev"
IPSEC=false
ALLFEATURES=false
PROXY=true
PROXY_ALL=false
LEGACY_CRD=true
ENDPOINTSLICE=false
NP=true
KEEP=false
ENCAP_MODE=""
CLOUD=""
TUN_TYPE="geneve"
VERBOSE_LOG=false
ON_DELETE=false
COVERAGE=false
K8S_115=false
SIMULATOR=false
CUSTOM_ADM_CONTROLLER=false
HW_OFFLOAD=false
SRIOV=false
WHEREABOUTS=false
FLEXIBLE_IPAM=false
MULTICAST=false
MULTICAST_INTERFACES=""

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
    # no-op
    shift
    ;;
    --ipsec)
    IPSEC=true
    shift
    ;;
    --all-features)
    ALLFEATURES=true
    shift
    ;;
    --no-proxy)
    PROXY=false
    shift
    ;;
    --proxy-all)
    PROXY=true
    PROXY_ALL=true
    shift
    ;;
    --no-legacy-crd)
    LEGACY_CRD=false
    shift
    ;;
    --endpointslice)
    PROXY=true
    ENDPOINTSLICE=true
    shift
    ;;
    --no-np)
    NP=false
    shift
    ;;
    --k8s-1.15)
    echoerr "The --k8s-1.15 flag is no longer supported"
    exit 1
    K8S_115=true
    shift
    ;;
    --keep)
    KEEP=true
    shift
    ;;
    --tun)
    TUN_TYPE="$2"
    shift 2
    ;;
    --verbose-log)
    VERBOSE_LOG=true
    shift
    ;;
    --on-delete)
    ON_DELETE=true
    shift
    ;;
    --coverage)
    COVERAGE=true
    shift
    ;;
    --simulator)
    SIMULATOR=true
    shift
    ;;
    --custom-adm-controller)
    CUSTOM_ADM_CONTROLLER=true
    shift
    ;;
    --hw-offload)
    HW_OFFLOAD=true
    shift
    ;;
    --sriov)
    SRIOV=true
    shift
    ;;   
    --flexible-ipam)
    FLEXIBLE_IPAM=true
    shift
    ;;
    --whereabouts)
    WHEREABOUTS=true
    shift
    ;;
    --multicast)
    MULTICAST=true
    shift
    ;;
    --multicast-interfaces)
    MULTICAST_INTERFACES="$2"
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

if [ "$PROXY" == false ] && [ "$ENDPOINTSLICE" == true ]; then
    echoerr "--endpointslice requires AntreaProxy, so it cannot be used with --no-proxy"
    print_help
    exit 1
fi

if [ "$PROXY" == false ] && [ "$PROXY_ALL" == true ]; then
    echoerr "--proxy-all requires AntreaProxy, so it cannot be used with --no-proxy"
    print_help
    exit 1
fi

if [ "$MODE" != "dev" ] && [ "$MODE" != "release" ]; then
    echoerr "--mode must be one of 'dev' or 'release'"
    print_help
    exit 1
fi

if [ "$TUN_TYPE" != "geneve" ] && [ "$TUN_TYPE" != "vxlan" ] && [ "$TUN_TYPE" != "gre" ] && [ "$TUN_TYPE" != "stt" ]; then
    echoerr "--tun must be one of 'geneve', 'gre', 'stt' or 'vxlan'"
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

if [ "$MODE" != "dev" ] && $VERBOSE_LOG; then
    echoerr "--verbose-log works only in 'dev' mode"
    print_help
    exit 1
fi

if [ "$MODE" != "dev" ] && $ON_DELETE; then
    echoerr "--on-delete works only in 'dev' mode"
    print_help
    exit 1
fi

if $COVERAGE && $VERBOSE_LOG; then
    echoerr "--coverage has enabled verbose log"
    VERBOSE_LOG=false
fi

if [[ "$ENCAP_MODE" != "" ]] && [[ "$ENCAP_MODE" != "encap" ]] && ! $PROXY; then
    echoerr "Cannot use '--no-proxy' when '--encap-mode' is not 'encap'"
    exit 1
fi

if [[ "$ENCAP_MODE" != "" ]] && [[ "$ENCAP_MODE" != "encap" ]] && $IPSEC; then
    echoerr "Encap mode '$ENCAP_MODE' does not make sense with IPsec"
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
# user is not expected to make changes directly to antrea-agent.conf and antrea-controller.conf,
# but instead to the generated YAML manifest, so our regexs need not be too robust.
cp $KUSTOMIZATION_DIR/base/conf/antrea-agent.conf antrea-agent.conf
cp $KUSTOMIZATION_DIR/base/conf/antrea-controller.conf antrea-controller.conf

if $IPSEC; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*trafficEncryptionMode[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/trafficEncryptionMode: ipsec/" antrea-agent.conf
    # change the tunnel type to GRE which works better with IPsec encryption than other types.
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*tunnelType[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/tunnelType: gre/" antrea-agent.conf
fi

if $FLEXIBLE_IPAM; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*AntreaIPAM[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  AntreaIPAM: true/" antrea-controller.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*AntreaIPAM[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  AntreaIPAM: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*enableBridgingMode[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/enableBridgingMode: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*trafficEncapMode[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/trafficEncapMode: noEncap/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*noSNAT[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/noSNAT: true/" antrea-agent.conf
fi

if $MULTICAST; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*trafficEncapMode[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/trafficEncapMode: noEncap/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*Multicast[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  Multicast: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*multicastInterfaces[[:space:]]*:[[:space:]]*\[([a-zA-Z0-9]*,[[:space:]]*)*[a-zA-Z0-9]*\][[:space:]]*$/multicastInterfaces: [$MULTICAST_INTERFACES]/" antrea-agent.conf
fi

if $ALLFEATURES; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*AntreaPolicy[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  AntreaPolicy: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*FlowExporter[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  FlowExporter: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*NetworkPolicyStats[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  NetworkPolicyStats: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*EndpointSlice[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  EndpointSlice: true/" antrea-agent.conf
    sed -i.bak -E "s/^[[:space:]]*#proxyAll[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  proxyAll: true/" antrea-agent.conf
fi

if ! $PROXY; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*AntreaProxy[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  AntreaProxy: false/" antrea-agent.conf
fi

if $PROXY_ALL; then
     sed -i.bak -E "s/^[[:space:]]*#proxyAll[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  proxyAll: true/" antrea-agent.conf
fi

if ! $LEGACY_CRD; then
    sed -i.bak -E "s/^#legacyCRDMirroring[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/legacyCRDMirroring: false/" antrea-controller.conf
fi

if $ENDPOINTSLICE; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*EndpointSlice[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  EndpointSlice: true/" antrea-agent.conf
fi

if ! $NP; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*AntreaPolicy[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  AntreaPolicy: false/" antrea-controller.conf
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*AntreaPolicy[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/  AntreaPolicy: false/" antrea-agent.conf
fi

if [[ $ENCAP_MODE != "" ]]; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*trafficEncapMode[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/trafficEncapMode: $ENCAP_MODE/" antrea-agent.conf
fi

if [[ $TUN_TYPE != "geneve" ]]; then
    sed -i.bak -E "s/^[[:space:]]*#[[:space:]]*tunnelType[[:space:]]*:[[:space:]]*[a-z]+[[:space:]]*$/tunnelType: $TUN_TYPE/" antrea-agent.conf
fi

if [[ $CLOUD != "" ]]; then
    # Delete the serviceCIDR parameter for the cloud (AKS, EKS, GKE) deployment yamls, because
    # AntreaProxy is always enabled for the cloud managed K8s clusters, and the serviceCIDR
    # parameter is not needed in this case.
    # delete all blank lines after "#serviceCIDR:"
    sed -i.bak '/#serviceCIDR:/,/^$/{/^$/d;}' antrea-agent.conf
    # delete lines from "# ClusterIP CIDR range for Services" to "#serviceCIDR:"
    sed -i.bak '/# ClusterIP CIDR range for Services/,/#serviceCIDR:/d' antrea-agent.conf
fi

# unfortunately 'kustomize edit add configmap' does not support specifying 'merge' as the behavior,
# which is why we use a template kustomization file.
sed -e "s/<AGENT_CONF_FILE>/antrea-agent.conf/; s/<CONTROLLER_CONF_FILE>/antrea-controller.conf/" ../../patches/kustomization.configMap.tpl.yml > kustomization.yml
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
    # add a container to the Agent DaemonSet that runs the OVS IPsec and strongSwan daemons.
    $KUSTOMIZE edit add patch --path ipsecContainer.yml
    # add an environment variable to the antrea-agent container for passing the PSK to Agent.
    $KUSTOMIZE edit add patch --path pskEnv.yml
    BASE=../ipsec
    cd ..
fi

if $COVERAGE; then
    mkdir coverage && cd coverage
    cp ../../patches/coverage/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    # this runs antrea-controller via the instrumented binary.
    $KUSTOMIZE edit add patch --path startControllerCov.yml
    # this runs antrea-agent via the instrumented binary.
    $KUSTOMIZE edit add patch --path startAgentCov.yml
    BASE=../coverage
    cd ..
fi 

if [[ $ENCAP_MODE == "networkPolicyOnly" ]] ; then
    mkdir chaining && cd chaining
    cp ../../patches/chaining/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    # change initContainer script and add antrea to CNI chain
    $KUSTOMIZE edit add patch --path installCni.yml
    BASE=../chaining
    cd ..
fi

if [[ $CLOUD == "GKE" ]]; then
    mkdir gke && cd gke
    cp ../../patches/gke/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch --path cniPath.yml
    BASE=../gke
    cd ..
fi

if [[ $CLOUD == "EKS" ]]; then
    mkdir eks && cd eks
    cp ../../patches/eks/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch --path eksEnv.yml
    BASE=../eks
    cd ..
fi

if $SIMULATOR; then
    mkdir simulator && cd simulator
    cp ../../patches/simulator/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch --path agentNodeAffinity.yml
    $KUSTOMIZE edit add patch --path controllerNodeAffinity.yml
    $KUSTOMIZE edit add resource antrea-agent-simulator.yml
    BASE=../simulator
    cd ..
fi

if $CUSTOM_ADM_CONTROLLER; then
    mkdir admissioncontroller && cd admissioncontroller
    cp ../../patches/admissioncontroller/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add resource webhook.yml
    BASE=../admissioncontroller
    cd ..
fi

if $HW_OFFLOAD; then
    mkdir hwoffload && cd hwoffload
    cp ../../patches/hwoffload/hwOffload.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch --path hwOffload.yml
    BASE=../hwoffload
    cd ..
fi

if $SRIOV; then
    mkdir sriov && cd sriov
    cp ../../patches/sriov/sriov.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch --path sriov.yml
    BASE=../sriov
    cd ..
fi

if $WHEREABOUTS; then
    mkdir whereabouts && cd whereabouts
    cp ../../patches/whereabouts/*.yml .
    touch kustomization.yml
    $KUSTOMIZE edit add base $BASE
    $KUSTOMIZE edit add patch --path whereabouts.yml
    $KUSTOMIZE edit add resource whereabouts-rbac.yml
    BASE=../whereabouts
    cd ..
fi

mkdir $MODE && cd $MODE
touch kustomization.yml
$KUSTOMIZE edit add base $BASE
# ../../patches/$MODE may be empty so we use find and not simply cp
find ../../patches/$MODE -name \*.yml -exec cp {} . \;

if [ "$MODE" == "dev" ]; then
    if [[ -z "$IMG_NAME" ]]; then
        if $COVERAGE; then
            IMG_NAME="antrea/antrea-ubuntu-coverage:latest"
        else
            IMG_NAME="projects.registry.vmware.com/antrea/antrea-ubuntu:latest"
        fi
    fi

    $KUSTOMIZE edit set image antrea=$IMG_NAME

    $KUSTOMIZE edit add patch --path agentImagePullPolicy.yml
    $KUSTOMIZE edit add patch --path controllerImagePullPolicy.yml
    if $VERBOSE_LOG; then
        $KUSTOMIZE edit add patch --path agentVerboseLog.yml
        $KUSTOMIZE edit add patch --path controllerVerboseLog.yml
    fi

    # only required because there is no good way at the moment to update the imagePullPolicy for all
    # containers. See https://github.com/kubernetes-sigs/kustomize/issues/1493
    if $IPSEC; then
        $KUSTOMIZE edit add patch --path agentIpsecImagePullPolicy.yml
    fi

    if $ON_DELETE; then
        $KUSTOMIZE edit add patch --path onDeleteUpdateStrategy.yml
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
