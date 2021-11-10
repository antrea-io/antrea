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

set -o errexit
set -o nounset
set -o pipefail

GOPATH=`go env GOPATH`
ANTREA_PKG="antrea.io/antrea"

cd multicluster
rm -rf pkg/client/{clientset,informers,listers}

$GOPATH/bin/client-gen \
  --clientset-name versioned \
  --input-base "${ANTREA_PKG}/multicluster/apis" \
  --input "multicluster/v1alpha1" \
  --output-package "${ANTREA_PKG}/multicluster/pkg/client/clientset" \
  --go-header-file hack/boilerplate.go.txt

# Generate listers with K8s codegen tools.
$GOPATH/bin/lister-gen \
  --input-dirs "${ANTREA_PKG}/multicluster/apis/multicluster/v1alpha1" \
  --output-package "${ANTREA_PKG}/multicluster/pkg/client/listers" \
  --go-header-file hack/boilerplate.go.txt


# Generate informers with K8s codegen tools.
$GOPATH/bin/informer-gen \
  --input-dirs "${ANTREA_PKG}/multicluster/apis/multicluster/v1alpha1" \
  --versioned-clientset-package "${ANTREA_PKG}/multicluster/pkg/client/clientset/versioned" \
  --listers-package "${ANTREA_PKG}/multicluster/pkg/client/listers" \
  --output-package "${ANTREA_PKG}/multicluster/pkg/client/informers" \
  --go-header-file hack/boilerplate.go.txt
