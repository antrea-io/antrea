FROM golang:1.13

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image for antrea integration tests."

RUN apt-get update && \
    apt-get install -y --no-install-recommends openvswitch-switch iproute2 iptables && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

COPY build/images/scripts/* /usr/local/bin/
COPY build/images/test/test-integration /usr/local/bin/