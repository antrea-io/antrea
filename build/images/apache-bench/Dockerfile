FROM ubuntu:18.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which includes the ApacheBench tool."

RUN apt-get update && \
    apt-get install -y --no-install-recommends apache2-utils && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*
