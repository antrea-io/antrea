#!/usr/bin/env bash

# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Define your aliases for OF tables here.
declare -a TABLE_ALIAS_LIST=(
    0
    arps arpr
    class
    spoof ipv6 ipclass
    snatct ct cts
    preclass nmark affinit slb epdnat dnat
    eanp enp enpd enpm
    l3f emark ttl
    smark snatctcom
    l2f
    inclass inanp innp innpd innpm
    ctcom
    vlan output
    ml3f
)

declare -A TABLE_ALIAS_MAP=(
  [0]="PipelineRootClassifier"
  [arps]="ARPSpoofGuard" [arpr]="ARPResponder"
  [class]="Classifier"
  [spoof]="SpoofGuard" [ipv6]="IPv6" [ipclass]="PipelineIPClassifier"
  [snatct]="SNATConntrack" [ct]="Conntrack" [cts]="ConntrackState"
  [preclass]="PreRoutingClassifier" [nmark]="NodePortMark" [affinit]="SessionAffinity" [slb]="ServiceLB" [epdnat]="EndpointDNAT" [dnat]="DNAT"
  [eanp]="AntreaPolicyEgressRule" [enp]="EgressRule" [enpd]="EgressDefault" [enpm]="EgressMetric"
  [l3f]="L3Forwarding" [emark]="EgressMark" [ttl]="L3DecTTL"
  [smark]="ServiceMark" [snatctcom]="SNATConntrackCommit"
  [l2f]="L2ForwardingCalc"
  [inclass]="IngressSecurityClassifier" [inanp]="AntreaPolicyIngressRule" [innp]="IngressRule" [innpd]="IngressDefault" [innpm]="IngressMetric"
  [ctcom]="ConntrackCommit"
  [vlan]="VLAN" [output]="Output"
  [ml3f]="Multicast"
)

# Define your aliases for the unique information to choose an Antrea Agent Pod here.
declare -A AGENT_ALIAS_MAP=(
  # [foo1]="Antrea Agent Pod name"
  # [foo2]="K8s Node name where an Antrea Agent running"
  # [foo3]="K8s Node external IP where an Antrea Agent running"
)

function print_aliases {
    printf "All aliases for OF tables are listed below. You can customize your own aliaes for OF tables.\n"
    for ALIAS in "${TABLE_ALIAS_LIST[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${TABLE_ALIAS_MAP[$ALIAS]}"
    done

    printf "\nAll aliases for Antrea Agent Pod are listed below, You can customize your own alias for some frequently used Antrea Agent Pods.\n"
    for ALIAS in "${!AGENT_ALIAS_MAP[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${AGENT_ALIAS_MAP[$ALIAS]}"
    done
}

_usage="Usage: $0 [arg 1] [arg 2] [--watch|--no-watch] [--no-stat|--stat] [--no-names|--names] [--exclude-ipv4|--exclude-ipv6] [--help|-h]
Dump flows from an Antrea Agent OVS.
       arg 1              String to match an Antrea Agent Pod, such as Pod name, Node name, Node external IP or an alias. The argument is required
       arg 2              String to match an OF table, such as table name, table ID or an alias. The argument is required
       --watch            Output flows with watching (enabled by default)
       --no-watch         Output flows without watching
       --stat             Show statistics for output flows (enabled by default)
       --no-stat          Don't show statistics for output flows
       --names            Show table names for output flows (enabled by default)
       --no-names         Don't show table names for output flows
       --exclude-ipv6     Don't show flows about IPv6 (enabled by default)
       --exclude-ipv4     Don't show flows about IPv4
       --no-exclude       Show all flows
       --help, -h         Print this message and exit

$(print_aliases)
"

function echoerr {
    >&2 echo "$@"
}

function print_usage {
    echoerr "$_usage"
}

if [[ $# -lt 2 ]]; then
    print_usage
    exit 0
fi

WATCH=true
STAT=true
NAMES=true
EXCLUDE_IPV4=false
EXCLUDE_IPV6=true

AGENT_INFO=$1
AGENT=$1
if [ "${AGENT_ALIAS_MAP[$AGENT_INFO]}" ]; then
    AGENT=${AGENT_ALIAS_MAP[$AGENT_INFO]}
fi
AGENT_NUM=$(kubectl get pods -o wide -n kube-system --no-headers | grep "antrea-agent-" | grep -c "$AGENT")
if [ "$AGENT_NUM" -gt 1 ]; then
    echoerr "Multiple Antrea Agent Pods are matched as the following. Please provide the unique information for only one Antrea Agent Pod"
    kubectl get pods -o wide -n kube-system --no-headers | grep antrea-agent- | grep "$AGENT"
    exit 1
elif [ "$AGENT_NUM" -eq 0 ]; then
    echoerr "No Antrea Agent Pod is matched. Please provide the unique information for only one Antrea Agent Pod"
    exit 1
fi

TABLE_INFO=$2
TABLE=$2
TABLE_ARG=""
if [ "$TABLE_INFO" ] && [ "${TABLE_ALIAS_MAP[$TABLE_INFO]}" ]; then
    TABLE=${TABLE_ALIAS_MAP[$TABLE_INFO]}
fi
if [ "$TABLE" ] && [[ $TABLE != "all" ]]; then
    TABLE_ARG="table=$TABLE"
fi

while [[ $# -gt 2 ]];
do
    key="$3"
    case $key in
        --watch)
            shift
            ;;
        --no-watch)
            WATCH=false
            shift
            ;;
        --stat)
            shift
            ;;
        --no-stat)
            STAT=false
            shift
            ;;
        --names)
            shift
            ;;
        --no-names)
            NAMES=false
            shift
            ;;
        --exclude-ipv4)
            EXCLUDE_IPV4=true
            EXCLUDE_IPV6=false
            shift
            ;;
        --exclude-ipv6)
            EXCLUDE_IPV4=false
            EXCLUDE_IPV6=true
            shift
            ;;
        --no-exclude)
            EXCLUDE_IPV4=false
            EXCLUDE_IPV6=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)    # unknown option
            echoerr "Unknown option $key"
            exit 1
            ;;
    esac
done

PROTO_ARG=""
if [ "$EXCLUDE_IPV4" == true ]; then
    PROTO_ARG="$PROTO_ARG | grep -v -E \"ip[, ]\""
fi
if [ "$EXCLUDE_IPV6" == true ]; then
    PROTO_ARG="$PROTO_ARG | grep -v -E \"ipv6[, ]\""
fi

STAT_ARG=""
if [ "$STAT" == false ]; then
   STAT_ARG="--no-stat"
fi

NAMES_ARG=""
if [ "$NAMES" == true ]; then
    NAMES_ARG="--names"
elif [ "$NAMES" == false ]; then
    if [ "$TABLE" -gt 0 ] 2>/dev/null; then
        NAMES_ARG="--no-names"
    else
        echoerr "When --no-names is used, only table ID can be used to dump flows from an table"
        exit 1
    fi
fi

WATCH_ARG="bash -c"
if [ "$WATCH" == true ]; then
    WATCH_ARG="watch -n1"
fi

AGENT_POD=$(kubectl get pods -o wide -n kube-system --no-headers | grep "antrea-agent-" | grep "$AGENT" | awk '{print $1}')
kubectl exec -it -n kube-system $AGENT_POD -c antrea-ovs -- $WATCH_ARG "ovs-ofctl dump-flows br-int $TABLE_ARG $STAT_ARG $NAMES_ARG $PROTO_ARG"
