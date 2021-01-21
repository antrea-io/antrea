FROM ubuntu:20.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which is used for performance tests."

RUN apt-get update && \
    apt-get install -y --no-install-recommends apache2-utils iperf3 && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*
ENTRYPOINT "iperf3" "-s"
