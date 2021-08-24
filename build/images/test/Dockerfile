ARG OVS_VERSION
FROM antrea/openvswitch:${OVS_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image for antrea integration tests."

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iptables ipset make wget gcc libc6-dev ca-certificates git && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ARG GO_VERSION
ENV GOPATH /go

RUN wget -q -O - https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar xz -C /usr/local/ && \
    export PATH="/usr/local/go/bin:$PATH" && \
    mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

ENV PATH $GOPATH/bin:/usr/local/go/bin/:$PATH

WORKDIR $GOPATH

COPY build/images/scripts/* /usr/local/bin/
COPY build/images/test/test-integration /usr/local/bin/
