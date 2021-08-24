ARG GO_VERSION
FROM ubuntu:20.04 as protoc

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

ARG K8S_VERSION=1.21.0
# The k8s.io/kube-openapi repo does not have tag, using a workable commit hash.
ARG KUBEOPENAPI_VERSION=v0.0.0-20210305164622-f622666832c1

RUN go get k8s.io/code-generator/cmd/client-gen@kubernetes-$K8S_VERSION && \
    go get k8s.io/code-generator/cmd/deepcopy-gen@kubernetes-$K8S_VERSION && \
    go get k8s.io/code-generator/cmd/conversion-gen@kubernetes-$K8S_VERSION && \
    go get k8s.io/code-generator/cmd/lister-gen@kubernetes-$K8S_VERSION && \
    go get k8s.io/code-generator/cmd/informer-gen@kubernetes-$K8S_VERSION && \
    go get k8s.io/kube-openapi/cmd/openapi-gen@$KUBEOPENAPI_VERSION && \
    go get k8s.io/code-generator/cmd/go-to-protobuf@kubernetes-$K8S_VERSION && \
    go get k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo@kubernetes-$K8S_VERSION && \
    go get github.com/golang/mock/mockgen@v1.4.4 && \
    go get github.com/golang/protobuf/protoc-gen-go@v1.3.2 && \
    go get golang.org/x/tools/cmd/goimports

COPY --from=protoc /tmp/protoc/bin /usr/local/bin
COPY --from=protoc /tmp/protoc/include /usr/local/include

