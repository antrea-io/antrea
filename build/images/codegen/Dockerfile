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

ARG GO_VERSION
FROM ubuntu:22.04 as protoc

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates unzip

RUN PROTOBUF_VERSION=3.0.2; ZIPNAME="protoc-${PROTOBUF_VERSION}-linux-x86_64.zip"; \
  mkdir /tmp/protoc && cd /tmp/protoc && \
  wget "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}/${ZIPNAME}" && \
  unzip "${ZIPNAME}" && \
  chmod -R +rX /tmp/protoc


FROM golang:${GO_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on the golang image, which includes codegen tools."

ENV GO111MODULE=on

ARG K8S_VERSION=1.24.0
# The k8s.io/kube-openapi repo does not have tag, using a workable commit hash.
# We use the version that is referenced in the Kubernetes go.mod (for the
# correct K8s version).
ARG KUBEOPENAPI_VERSION=v0.0.0-20220328201542-3ee0da9b0b42

RUN go install k8s.io/code-generator/cmd/client-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/deepcopy-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/conversion-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/lister-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/informer-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/kube-openapi/cmd/openapi-gen@$KUBEOPENAPI_VERSION && \
    go install k8s.io/code-generator/cmd/go-to-protobuf@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo@kubernetes-$K8S_VERSION && \
    go install github.com/golang/mock/mockgen@v1.4.4 && \
    go install github.com/golang/protobuf/protoc-gen-go@v1.5.2 && \
    go install golang.org/x/tools/cmd/goimports@latest && \
    go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.9.0

COPY --from=protoc /tmp/protoc/bin /usr/local/bin
COPY --from=protoc /tmp/protoc/include /usr/local/include

