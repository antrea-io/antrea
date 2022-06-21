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

function usage() {
    echo "Usage: provision.sh [--ip-family <v4|v6>] [-h|--help]
    Provisions the Vagrant VMs.
    --ip-family <v4|v6|dual>                Deploy IPv4, IPv6 or dual-stack Kubernetes cluster.
    --kube-proxy-mode <iptables|ipvs|none>  Which mode to use for kube-proxy (default is iptables).
                                            Setting to 'none' will skip deploying kube-proxy."
}

K8S_IP_FAMILY="v4"
K8S_NODE_LARGE=false
KUBE_PROXY_MODE="iptables"
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --ip-family)
    K8S_IP_FAMILY="$2"
    shift 2
    ;;
    --kube-proxy-mode)
    KUBE_PROXY_MODE="$2"
    shift 2
    ;;
    -h|--help)
    usage
    exit 0
    ;;
    *)
    usage
    exit 1
esac
done

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR

export K8S_IP_FAMILY
export KUBE_PROXY_MODE

# A few important considerations for IPv6 clusters:
# * there is no assumption that the host machine supports IPv6.
# * the network used by K8s is an IPv6 network, but the Nodes still access the
#   Internet over IPv4.
# * Pods are IPv6-only and cannot access the Internet.
# * a dummy default IPv6 route is required on the Nodes for ClusterIP to work
#   with kube-proxy and for Antrea to access the K8s apiserver. This is because
#   there is a route lookup before the traffic goes through DNAT in the iptables
#   OUTPUT chain.
# * with the default CoreDNS configuration, DNS conformance tests fail. This is
#   because non-cluster local DNS queries should be forwarded to the upstream
#   nameservers for the Node, but the CoreDNS Pods (like all other Pods) only
#   support IPv6, meaning that these nameservers are not accessible. To
#   workaround this issue, we run a socat proxy on the control-plane Node which
#   forwards IPv6 DNS queries to the default DNS resolver over IPv4. We modify
#   the CoreDNS configuration to forward all non-cluster local DNS queries to
#   the socat proxy, listening on antrea-gw0 on the control-plane Node.

# With --provision we ensure that we provision the VM again even if it already
# exists and was already provisioned. Our Ansible playbook ensures that we only
# run tasks that need to be run.
time vagrant up --provision
echo "Writing Vagrant ssh config to file"
vagrant ssh-config > ssh-config

chmod 0600 "$THIS_DIR/playbook/kube/config"
# TODO: use Kubeconfig contexts to add new cluster to existing Kubeconfig file
echo "******************************"
echo "Kubeconfig file written to $THIS_DIR/playbook/kube/config"
echo "To use kubectl, you can run the following:"
echo "$ export KUBECONFIG=$THIS_DIR/playbook/kube/config"
echo "******************************"
