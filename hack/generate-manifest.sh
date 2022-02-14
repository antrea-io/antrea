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
Generate a YAML manifest for Antrea using Helm and print it to stdout.
        --mode (dev|release)          Choose the configuration variant that you need (default is 'dev')
        --encap-mode                  Traffic encapsulation mode. (default is 'encap')
        --cloud                       Generate a manifest appropriate for running Antrea in Public Cloud
        --ipsec                       Generate a manifest with IPsec encryption of tunnel traffic enabled
        --all-features                Generate a manifest with all alpha features enabled
        --no-proxy                    Generate a manifest with Antrea proxy disabled
        --proxy-all                   Generate a manifest with Antrea proxy with all Service support enabled
        --endpointslice               Generate a manifest with EndpointSlice support enabled
        --flow-exporter               Generate a manifest with FlowExporter support enabled
        --no-np                       Generate a manifest with Antrea-native policies disabled
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

This tool uses Helm 3 (https://helm.sh/) to generate manifests for Antrea. You can set the HELM
environment variable to the path of the helm binary you want us to use. Otherwise we will download
the appropriate version of the helm binary and use it (this is the recommended approach since
different versions of helm may create different output YAMLs)."

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
ENDPOINTSLICE=false
FLOW_EXPORTER=false
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
    --endpointslice)
    PROXY=true
    ENDPOINTSLICE=true
    shift
    ;;
    --flow-exporter)
    FLOW_EXPORTER=true
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

source $THIS_DIR/verify-helm.sh

if [ -z "$HELM" ]; then
    HELM="$(verify_helm)"
elif ! $HELM version > /dev/null 2>&1; then
    echoerr "$HELM does not appear to be a valid helm binary"
    print_help
    exit 1
fi

TMP_DIR=$(mktemp -d $THIS_DIR/../build/yamls/chart-values.XXXXXXXX)
HELM_VALUES=()
HELM_VALUES_FILES=()

if $IPSEC; then
    HELM_VALUES+=("trafficEncryptionMode=ipsec" "tunnelType=gre")
fi

if $FLEXIBLE_IPAM; then
    HELM_VALUES+=("featureGates.AntreaIPAM=true" "enableBridgingMode=true" "trafficEncapMode=noEncap" "noSNAT=true")
fi

if $MULTICAST; then
    HELM_VALUES+=("trafficEncapMode=noEncap" "featureGates.Multicast=true" "multicastInterfaces={$MULTICAST_INTERFACES}")
fi

if $ALLFEATURES; then
    HELM_VALUES+=("featureGates.FlowExporter=true" "featureGates.EndpointSlice=true" "antreaProxy.proxyAll=true")
fi

if ! $PROXY; then
    HELM_VALUES+=("featureGates.AntreaProxy=false")
fi

if $PROXY_ALL; then
    HELM_VALUES+=("antreaProxy.proxyAll=true")
fi

if $ENDPOINTSLICE; then
    HELM_VALUES+=("featureGates.EndpointSlice=true")
fi

if $FLOW_EXPORTER; then
    HELM_VALUES+=("featureGates.FlowExporter=true")
fi

if ! $NP; then
    HELM_VALUES+=("featureGates.AntreaPolicy=false")
fi

if [[ $ENCAP_MODE != "" ]]; then
    HELM_VALUES+=("trafficEncapMode=$ENCAP_MODE")
fi

if [[ $TUN_TYPE != "geneve" ]]; then
    HELM_VALUES+=("tunnelType=$TUN_TYPE")
fi

if $COVERAGE; then
    HELM_VALUES+=("testing.coverage=true")
fi 

if [[ $CLOUD == "GKE" ]]; then
    HELM_VALUES+=("cni.hostBinPath=/home/kubernetes/bin")
fi

if [[ $CLOUD == "EKS" ]]; then
    HELM_VALUES+=("agent.antreaAgent.extraEnv.ANTREA_CLOUD_EKS=true")
fi

if $SIMULATOR; then
    HELM_VALUES+=("testing.simulator.enable=true")
fi

if $CUSTOM_ADM_CONTROLLER; then
    HELM_VALUES+=("webhooks.labelsMutator.enable=true")
fi

if $HW_OFFLOAD; then
    HELM_VALUES+=("ovs.hwOffload=true")
fi

if $SRIOV; then
    cat << EOF > $TMP_DIR/sriov.yml
agent:
  antreaAgent:
    extraVolumeMounts:
    - mountPath: /var/lib/kubelet
      name: host-kubelet
      readOnly: true
  extraVolumes:
  - hostPath:
      path: /var/lib/kubelet
    name: host-kubelet
EOF
    HELM_VALUES_FILES+=("$TMP_DIR/sriov.yml")
fi

if $WHEREABOUTS; then
    HELM_VALUES+=("whereabouts.enable=true")
fi

if [ "$MODE" == "dev" ]; then
    if [[ -z "$IMG_NAME" ]]; then
        if $COVERAGE; then
            HELM_VALUES+=("image.repository=antrea/antrea-ubuntu-coverage")
        fi
    else
        HELM_VALUES+=("image.repository=$IMG_NAME")
    fi

    if $VERBOSE_LOG; then
        HELM_VALUES+=("logVerbosity=4")
    fi

    if $ON_DELETE; then
        HELM_VALUES+=("agent.updateStrategy.type=OnDelete")
    fi
fi

if [ "$MODE" == "release" ]; then
    HELM_VALUES+=("image.repository=$IMG_NAME,image.tag=$IMG_TAG")
fi

delim=""
HELM_VALUES_OPTION=""
for v in "${HELM_VALUES[@]}"; do
    HELM_VALUES_OPTION="$HELM_VALUES_OPTION$delim$v"
    delim=","
done
if [ "$HELM_VALUES_OPTION" != "" ]; then
    HELM_VALUES_OPTION="--set $HELM_VALUES_OPTION"
fi

HELM_VALUES_FILES_OPTION=""
for v in "${HELM_VALUES_FILES[@]}"; do
    HELM_VALUES_FILES_OPTION="$HELM_VALUES_FILES_OPTION -f $v"
done

ANTREA_CHART="$THIS_DIR/../build/charts/antrea"
# Suppress potential Helm warnings about invalid permissions for Kubeconfig file
# by throwing away related warnings.
$HELM template \
      --namespace kube-system \
      $HELM_VALUES_OPTION \
      $HELM_VALUES_FILES_OPTION \
      "$ANTREA_CHART" \
      2> >(grep -v 'This is insecure' >&2)

rm -rf $TMP_DIR
