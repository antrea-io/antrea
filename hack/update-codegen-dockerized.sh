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

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

GOPATH=`go env GOPATH`
ANTREA_PKG="antrea.io/antrea"
# Cannot use "antrea.io/antrea" because of name resolution in protoc. Without
# this, we get the error:
# antrea.io/antrea/pkg/apis/controlplane/v1beta1/generated.proto:281:12: "antrea.io.antrea.pkg.apis.stats.v1alpha1.RuleTrafficStats" is resolved to "antrea.io.antrea.io.antrea.pkg.apis.stats.v1alpha1.RuleTrafficStats", which is not defined. The innermost scope is searched first in name resolution. Consider using a leading '.'(i.e., ".antrea.io.antrea.pkg.apis.stats.v1alpha1.RuleTrafficStats") to start from the outermost scope.
#
# When resolving "antrea.io.antrea.pkg.apis.stats.v1alpha1.RuleTrafficStats",
# protoc will look at the package name of the current .proto starting from the
# last one, and stop when it finds a match for "antrea". It will stop at
# "antrea.io.antrea" which is wrong. Ideally, the code generator would use a
# leading dot.
#
# This seems to be a pretty common issue with the Kubernetes code generator,
# notably for APIs under sigs.k8s.io. For example:
# https://github.com/kubernetes-sigs/gateway-api/issues/11
ANTREA_PROTO_PKG="antrea_io.antrea"

MOCKGEN_TARGETS=(
  "pkg/agent/cniserver SriovNet testing"
  "pkg/agent/cniserver/ipam IPAMDriver testing"
  "pkg/agent/flowexporter/connections ConnTrackDumper,NetFilterConnTrack testing"
  "pkg/agent/interfacestore InterfaceStore testing"
  "pkg/agent/memberlist Interface testing"
  "pkg/agent/memberlist Memberlist ."
  "pkg/agent/multicast RouteInterface testing"
  "pkg/agent/types McastNetworkPolicyController testing"
  "pkg/agent/nodeportlocal/portcache LocalPortOpener testing"
  "pkg/agent/nodeportlocal/rules PodPortRules testing"
  "pkg/agent/openflow Client testing"
  "pkg/agent/openflow/operations OFEntryOperations testing"
  "pkg/agent/proxy Proxier testing"
  "pkg/agent/querier AgentQuerier testing"
  "pkg/agent/route Interface testing"
  "pkg/agent/ipassigner IPAssigner testing"
  "pkg/agent/secondarynetwork/podwatch InterfaceConfigurator,IPAMAllocator testing"
  "pkg/agent/servicecidr Interface testing"
  "pkg/agent/util/ipset Interface testing"
  "pkg/agent/util/iptables Interface testing mock_iptables_linux.go" # Must specify linux.go suffix, otherwise compilation would fail on windows platform as source file has linux build tag.
  "pkg/agent/util/netlink Interface testing mock_netlink_linux.go"
  "pkg/agent/wireguard Interface testing mock_wireguard.go"
  "pkg/antctl AntctlClient ."
  "pkg/controller/networkpolicy EndpointQuerier,PolicyRuleQuerier testing"
  "pkg/controller/querier ControllerQuerier testing"
  "pkg/flowaggregator/exporter Interface testing"
  "pkg/ipfix IPFIXExportingProcess,IPFIXRegistry,IPFIXCollectingProcess,IPFIXAggregationProcess testing"
  "pkg/ovs/openflow Bridge,Table,Flow,Action,CTAction,FlowBuilder,Group,BucketBuilder,PacketOutBuilder,Meter,MeterBandBuilder testing"
  "pkg/ovs/ovsconfig OVSBridgeClient testing"
  "pkg/ovs/ovsctl OVSCtlClient testing"
  "pkg/ovs/ovsctl OVSOfctlRunner,OVSAppctlRunner ."
  "pkg/querier AgentNetworkPolicyInfoQuerier,AgentMulticastInfoQuerier,EgressQuerier testing"
  "pkg/flowaggregator/querier FlowAggregatorQuerier testing"
  "pkg/flowaggregator/s3uploader S3UploaderAPI testing"
  "pkg/util/podstore Interface testing"
  "third_party/proxy Provider testing"
)

source hack/update-codegen-common.sh

if [[ "$#" -eq 1 && $1 == "mockgen" ]]; then
  generate_mocks
  reset_year_change
  exit 0
fi

function generate_antrea_client_code {
  # Generate protobuf code for CNI gRPC service with protoc.
  protoc --go_out=. --go-grpc_out=. pkg/apis/cni/v1beta1/cni.proto

  # Generate clientset and apis code with K8s codegen tools.
  $GOPATH/bin/client-gen \
    --clientset-name versioned \
    --input-base "${ANTREA_PKG}/pkg/apis/" \
    --input "controlplane/v1beta2" \
    --input "system/v1beta1" \
    --input "crd/v1alpha1" \
    --input "crd/v1alpha2" \
    --input "crd/v1alpha3" \
    --input "crd/v1beta1" \
    --input "stats/v1alpha1" \
    --output-package "${ANTREA_PKG}/pkg/client/clientset" \
    --plural-exceptions "NetworkPolicyStats:NetworkPolicyStats" \
    --plural-exceptions "AntreaNetworkPolicyStats:AntreaNetworkPolicyStats" \
    --plural-exceptions "AntreaClusterNetworkPolicyStats:AntreaClusterNetworkPolicyStats" \
    --plural-exceptions "ClusterGroupMembers:ClusterGroupMembers" \
    --plural-exceptions "GroupMembers:GroupMembers" \
    --go-header-file hack/boilerplate/license_header.go.txt

  # Generate listers with K8s codegen tools.
  $GOPATH/bin/lister-gen \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha2" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha3" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1beta1" \
    --output-package "${ANTREA_PKG}/pkg/client/listers" \
    --go-header-file hack/boilerplate/license_header.go.txt

  # Generate informers with K8s codegen tools.
  $GOPATH/bin/informer-gen \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha2" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha3" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1beta1" \
    --versioned-clientset-package "${ANTREA_PKG}/pkg/client/clientset/versioned" \
    --listers-package "${ANTREA_PKG}/pkg/client/listers" \
    --output-package "${ANTREA_PKG}/pkg/client/informers" \
    --go-header-file hack/boilerplate/license_header.go.txt

  $GOPATH/bin/deepcopy-gen \
    --input-dirs "${ANTREA_PKG}/pkg/apis/controlplane" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/controlplane/v1beta2" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/system/v1beta1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha2" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1alpha3" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1beta1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/stats" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/stats/v1alpha1" \
    -O zz_generated.deepcopy \
    --go-header-file hack/boilerplate/license_header.go.txt

  $GOPATH/bin/conversion-gen  \
    --input-dirs "${ANTREA_PKG}/pkg/apis/controlplane/v1beta2,${ANTREA_PKG}/pkg/apis/controlplane/" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/stats/v1alpha1,${ANTREA_PKG}/pkg/apis/stats/" \
    -O zz_generated.conversion \
    --go-header-file hack/boilerplate/license_header.go.txt

  $GOPATH/bin/openapi-gen  \
    --input-dirs "${ANTREA_PKG}/pkg/apis/controlplane/v1beta2" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/system/v1beta1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/stats/v1alpha1" \
    --input-dirs "${ANTREA_PKG}/pkg/apis/crd/v1beta1" \
    --input-dirs "k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/util/intstr" \
    --input-dirs "k8s.io/api/core/v1" \
    --output-package "${ANTREA_PKG}/pkg/apiserver/openapi" \
    -O zz_generated.openapi \
    --go-header-file hack/boilerplate/license_header.go.txt
}

generate_antrea_client_code
generate_mocks

# Download vendored modules to the vendor directory so it's easier to
# specify the search path of required protobuf files.
go mod vendor
# In Go 1.14, vendoring changed (see release notes at
# https://golang.org/doc/go1.14), and the presence of a go.mod file specifying
# go 1.14 or higher causes the go command to default to -mod=vendor when a
# top-level vendor directory is present in the module. This causes the
# go-to-protobuf command below to complain about missing packages under vendor/,
# which were not downloaded by "go mod vendor". We can workaround this easily by
# renaming the vendor directory.
mv vendor /tmp/includes
PACKAGES="${ANTREA_PKG}/pkg/apis/stats/v1alpha1=${ANTREA_PROTO_PKG}.pkg.apis.stats.v1alpha1,\
${ANTREA_PKG}/pkg/apis/controlplane/v1beta2=${ANTREA_PROTO_PKG}.pkg.apis.controlplane.v1beta2"
$GOPATH/bin/go-to-protobuf \
  --proto-import /tmp/includes \
  --packages "${PACKAGES}" \
  --go-header-file hack/boilerplate/license_header.go.txt
rm -rf /tmp/includes

reset_year_change
