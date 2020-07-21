FROM ubuntu:18.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which contains a simple IPFIX collector to run flow exporter tests"

WORKDIR /ipfix

ADD https://svwh.dl.sourceforge.net/project/libipfix/libipfix/libipfix-impd4e_110224.tgz .

RUN apt-get update && \
    apt-get install -y --no-install-recommends libc6-dev build-essential libpcap0.8-dev && \
    tar -xvf libipfix-* && rm libipfix-* && \
    cd libipfix_* && ./configure && make && make install && ldconfig && \
    cp collector/ipfix_collector /usr/local/bin && \
    cd .. && \
    rm -rf libipfix_* && \
    apt-get remove -y build-essential && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ENTRYPOINT "ipfix_collector"