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

# We make a temporary working copy of the source repository using git clone. The
# copy is in the container's writable layer, which is much faster than a bind
# mount on non-Linux hosts (Docker Desktop, Colima).
ANTREA_SRC_PATH=$(pwd)
ANTREA_CODEGEN_PATH=/go/src/antrea.io/antrea
git clone ${ANTREA_SRC_PATH} ${ANTREA_CODEGEN_PATH}
pushd ${ANTREA_CODEGEN_PATH}

trap "popd; rm -rf ${ANTREA_CODEGEN_PATH}" EXIT

# Copy generated code back into the source repository, which was cloned at the
# beginning of this script to make a temporary working copy.
function copy_generated_code_to_source {
  git ls-files --modified --others --exclude-standard | while read file; do
      if [ -e $file ]; then
          mkdir -p $(dirname ${ANTREA_SRC_PATH}/$file)
          cp $file ${ANTREA_SRC_PATH}/$file
      else
          rm ${ANTREA_SRC_PATH}/$file
      fi
  done
}

source hack/update-codegen-common.sh

MOCKGEN_TARGETS=(
  "pkg/agent/bgp Interface testing"
  "pkg/agent/cniserver SriovNet testing"
  "pkg/agent/cniserver/ipam IPAMDriver testing"
  "pkg/agent/flowexporter/connections ConnTrackDumper,NetFilterConnTrack,DenyConnectionStoreUpdater testing"
  "pkg/agent/flowexporter/exporter Interface testing"
  "pkg/agent/interfacestore InterfaceStore testing"
  "pkg/agent/memberlist Interface testing"
  "pkg/agent/memberlist Memberlist ."
  "pkg/agent/multicast RouteInterface testing"
  "pkg/agent/types McastNetworkPolicyController,CNIDeleteChecker testing"
  "pkg/agent/monitortool PacketListener testing"
  "pkg/agent/nodeportlocal/portcache LocalPortOpener testing"
  "pkg/agent/nodeportlocal/rules PodPortRules testing"
  "pkg/agent/openflow Client testing"
  "pkg/agent/openflow/operations OFEntryOperations testing"
  "pkg/agent/proxy ProxyQuerier testing"
  "pkg/agent/querier AgentQuerier testing"
  "pkg/agent/route Interface testing"
  "pkg/agent/ipassigner IPAssigner testing"
  "pkg/agent/secondarynetwork/podwatch InterfaceConfigurator,IPAMAllocator testing"
  "pkg/agent/servicecidr Interface testing"
  "pkg/agent/util/ipset Interface testing"
  "pkg/agent/util/iptables Interface testing mock_iptables_linux.go" # Must specify linux.go suffix, otherwise compilation would fail on windows platform as source file has linux build tag.
  "pkg/agent/util/netlink Interface testing mock_netlink_linux.go"
  "pkg/agent/wireguard Interface testing mock_wireguard.go"
  "pkg/agent/util/winnet Interface testing mock_net_windows.go"
  "pkg/antctl AntctlClient ."
  "pkg/controller/networkpolicy EndpointQuerier,PolicyRuleQuerier testing"
  "pkg/controller/querier ControllerQuerier testing"
  "pkg/flowaggregator/certificate Provider testing"
  "pkg/flowaggregator/collector Interface testing"
  "pkg/flowaggregator/exporter Interface testing"
  "pkg/ipfix IPFIXExportingProcess,IPFIXBufferedExporter,IPFIXRegistry testing"
  "pkg/ovs/openflow Bridge,Table,Flow,Action,CTAction,FlowBuilder,Group,BucketBuilder,PacketOutBuilder,Meter,MeterBandBuilder testing"
  "pkg/ovs/ovsconfig OVSBridgeClient testing"
  "pkg/ovs/ovsctl OVSCtlClient testing"
  "pkg/ovs/ovsctl OVSOfctlRunner,OVSAppctlRunner ."
  "pkg/querier AgentNetworkPolicyInfoQuerier,AgentMulticastInfoQuerier,EgressQuerier,AgentBGPPolicyInfoQuerier testing"
  "pkg/flowaggregator/intermediate AggregationProcess testing"
  "pkg/flowaggregator/querier FlowAggregatorQuerier testing"
  "pkg/flowaggregator/s3uploader S3UploaderAPI testing"
  "pkg/util/objectstore NodeStore,PodStore,ServiceStore testing"
  "third_party/proxy Provider testing"
)

if [[ "$#" -eq 1 && $1 == "mockgen" ]]; then
  # Remove all files generated by MockGen.
  git grep --files-with-matches -e 'Code generated by MockGen\. DO NOT EDIT' pkg | xargs rm
  generate_mocks
  reset_year_change
  copy_generated_code_to_source
  exit 0
fi

# Remove all generated files.
git grep --files-with-matches -e 'Code generated by .* DO NOT EDIT' pkg | xargs rm
git grep --files-with-matches -e 'This file was autogenerated by go-to-protobuf' pkg | xargs rm

function generate_antrea_client_code {
  # Generate protobuf code for CNI gRPC service with protoc.
  protoc --go_out=. --go-grpc_out=. pkg/apis/cni/v1beta1/cni.proto

  # Generate protobuf code for Flow message and FlowExportService.
  protoc --go_out=. --go-grpc_out=. pkg/apis/flow/v1alpha1/flow.proto pkg/apis/flow/v1alpha1/service.proto

  # Generate clientset and apis code with K8s codegen tools.
  $GOPATH/bin/client-gen \
    --clientset-name versioned \
    --input-base "${ANTREA_PKG}/pkg/apis/" \
    --input "controlplane/v1beta2" \
    --input "system/v1beta1" \
    --input "crd/v1alpha1" \
    --input "crd/v1alpha2" \
    --input "crd/v1beta1" \
    --input "stats/v1alpha1" \
    --output-dir "pkg/client/clientset" \
    --output-pkg "${ANTREA_PKG}/pkg/client/clientset" \
    --plural-exceptions "NetworkPolicyStats:NetworkPolicyStats" \
    --plural-exceptions "AntreaNetworkPolicyStats:AntreaNetworkPolicyStats" \
    --plural-exceptions "AntreaClusterNetworkPolicyStats:AntreaClusterNetworkPolicyStats" \
    --plural-exceptions "ClusterGroupMembers:ClusterGroupMembers" \
    --plural-exceptions "GroupMembers:GroupMembers" \
    --plural-exceptions "NodeLatencyStats:NodeLatencyStats" \
    --go-header-file hack/boilerplate/license_header.go.txt

  # Generate listers with K8s codegen tools.
  $GOPATH/bin/lister-gen \
    --output-dir "pkg/client/listers" \
    --output-pkg "${ANTREA_PKG}/pkg/client/listers" \
    --go-header-file hack/boilerplate/license_header.go.txt \
    "${ANTREA_PKG}/pkg/apis/crd/v1alpha1" \
    "${ANTREA_PKG}/pkg/apis/crd/v1alpha2" \
    "${ANTREA_PKG}/pkg/apis/crd/v1beta1"

  # Generate informers with K8s codegen tools.
  $GOPATH/bin/informer-gen \
    --versioned-clientset-package "${ANTREA_PKG}/pkg/client/clientset/versioned" \
    --listers-package "${ANTREA_PKG}/pkg/client/listers" \
    --output-dir "pkg/client/informers" \
    --output-pkg "${ANTREA_PKG}/pkg/client/informers" \
    --go-header-file hack/boilerplate/license_header.go.txt \
    "${ANTREA_PKG}/pkg/apis/crd/v1alpha1" \
    "${ANTREA_PKG}/pkg/apis/crd/v1alpha2" \
    "${ANTREA_PKG}/pkg/apis/crd/v1beta1"

  $GOPATH/bin/deepcopy-gen \
    --output-file zz_generated.deepcopy.go \
    --go-header-file hack/boilerplate/license_header.go.txt \
     "${ANTREA_PKG}/pkg/apis/controlplane" \
     "${ANTREA_PKG}/pkg/apis/controlplane/v1beta2" \
     "${ANTREA_PKG}/pkg/apis/system/v1beta1" \
     "${ANTREA_PKG}/pkg/apis/crd/v1alpha1" \
     "${ANTREA_PKG}/pkg/apis/crd/v1alpha2" \
     "${ANTREA_PKG}/pkg/apis/crd/v1beta1" \
     "${ANTREA_PKG}/pkg/apis/stats" \
     "${ANTREA_PKG}/pkg/apis/stats/v1alpha1" \
     "${ANTREA_PKG}/pkg/agent/interfacestore"

  $GOPATH/bin/conversion-gen  \
    --output-file zz_generated.conversion.go \
    --go-header-file hack/boilerplate/license_header.go.txt \
    "${ANTREA_PKG}/pkg/apis/controlplane/v1beta2" \
    "${ANTREA_PKG}/pkg/apis/controlplane" \
    "${ANTREA_PKG}/pkg/apis/stats/v1alpha1"

  $GOPATH/bin/openapi-gen  \
    --output-dir "pkg/apiserver/openapi" \
    --output-pkg "${ANTREA_PKG}/pkg/apiserver/openapi" \
    --output-file zz_generated.openapi.go \
    --go-header-file hack/boilerplate/license_header.go.txt \
     "${ANTREA_PKG}/pkg/apis/controlplane/v1beta2" \
     "${ANTREA_PKG}/pkg/apis/system/v1beta1" \
     "${ANTREA_PKG}/pkg/apis/stats/v1alpha1" \
     "${ANTREA_PKG}/pkg/apis/crd/v1beta1" \
     "k8s.io/apimachinery/pkg/apis/meta/v1" \
     "k8s.io/apimachinery/pkg/runtime" \
     "k8s.io/apimachinery/pkg/util/intstr" \
     "k8s.io/apimachinery/pkg/version" \
     "k8s.io/api/core/v1"
}

generate_antrea_client_code
generate_mocks

# Download vendored modules to the vendor directory so it's easier to
# specify the search path of required protobuf files.
# Explicitly set GOFLAGS to ignore vendor, since GOFLAGS=-mod=vendor breaks
# dependency resolution while rebuilding vendor.
export GOFLAGS="-mod=mod"
go mod vendor
PACKAGES="${ANTREA_PKG}/pkg/apis/stats/v1alpha1=${ANTREA_PROTO_PKG}.pkg.apis.stats.v1alpha1,\
${ANTREA_PKG}/pkg/apis/controlplane/v1beta2=${ANTREA_PROTO_PKG}.pkg.apis.controlplane.v1beta2"
# Ask go-to-protobuf not to generate apimachinery types ("-" sign before the
# package name), as we only want to generate our own types. The command fails
# without this, as there is no /go/src/k8s.io folder.
$GOPATH/bin/go-to-protobuf \
  --output-dir="/go/src" \
  --proto-import vendor \
  --packages "${PACKAGES}" \
  --apimachinery-packages "-k8s.io/apimachinery/pkg/util/intstr,-k8s.io/apimachinery/pkg/api/resource,-k8s.io/apimachinery/pkg/runtime/schema,-k8s.io/apimachinery/pkg/runtime,-k8s.io/apimachinery/pkg/apis/meta/v1,-k8s.io/apimachinery/pkg/apis/meta/v1beta1,-k8s.io/apimachinery/pkg/apis/testapigroup/v1" \
  --go-header-file hack/boilerplate/license_header.go.txt

rm -rf vendor

reset_year_change
copy_generated_code_to_source
