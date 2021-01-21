FROM ubuntu:20.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which includes ethtool, ip tools and iptables."

RUN apt-get update && \
    apt-get install -y --no-install-recommends ethtool iproute2 iptables && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*
