FROM ubuntu:18.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which includes ethtool and ip tools."

RUN apt-get update && \
    apt-get install -y --no-install-recommends ethtool iproute2 && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*
