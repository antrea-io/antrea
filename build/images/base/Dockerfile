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

ARG BUILD_TAG
FROM ubuntu:22.04 as cni-binaries

ARG CNI_BINARIES_VERSION
ARG WHEREABOUTS_VERSION=v0.5.4

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates

# Leading dot is required for the tar command below
ENV CNI_PLUGINS="./host-local ./loopback ./portmap ./bandwidth"

# Download containernetworking plugin binaries for the correct architecture
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
         amd64) pluginsArch='amd64' ;; \
	 armhf) pluginsArch='arm' ;; \
	 arm64) pluginsArch='arm64' ;; \
         *) pluginsArch=''; echo >&2; echo >&2 "unsupported architecture '$dpkgArch'"; echo >&2 ; exit 1 ;; \
    esac; \
    mkdir -p /opt/cni/bin; \
    wget -q -O - https://github.com/containernetworking/plugins/releases/download/$CNI_BINARIES_VERSION/cni-plugins-linux-${pluginsArch}-$CNI_BINARIES_VERSION.tgz | tar xz -C /opt/cni/bin $CNI_PLUGINS; \
    wget -q -O /opt/cni/bin/whereabouts https://github.com/k8snetworkplumbingwg/whereabouts/releases/download/$WHEREABOUTS_VERSION/whereabouts-${pluginsArch} && chmod +x /opt/cni/bin/whereabouts

FROM ubuntu:22.04 as suricata-builder

ARG SURICATA_VERSION

ENV SURICATA_DEPS build-essential \
                  pkg-config \
                  libpcre3-dev \
                  libpcap-dev \
                  libcap-ng-dev \
                  libnspr4-dev \
                  libyaml-dev \
                  libmagic-dev \
                  libjansson-dev \
                  libevent-dev \
                  libnfnetlink-dev \
                  libnetfilter-queue-dev \
                  libnetfilter-log-dev \
                  libnet1-dev \
                  liblz4-dev \
                  libnss3-dev \
                  python3-dev \
                  zlib1g-dev \
                  rustc cargo

ENV SURICATA_RUNTIME_DEPS libpcre3 \
                          libpcap0.8 \
                          libcap-ng0 \
                          libnspr4 \
                          libyaml-0-2 \
                          libmagic1 \
                          libjansson4 \
                          libevent-2.1-7 \
                          libevent-pthreads-2.1-7 \
                          libnfnetlink0 \
                          libnetfilter-queue1 \
                          libnetfilter-log1 \
                          libnet1 \
                          liblz4-1 \
                          libnss3 \
                          python3 \
                          python3-simplejson \
                          zlib1g

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl $SURICATA_DEPS $SURICATA_RUNTIME_DEPS && \
    curl -OL https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz && \
    tar zxf suricata-${SURICATA_VERSION}.tar.gz && \
    cd suricata-${SURICATA_VERSION} && \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-shared --disable-gccmarch-native --enable-nfqueue && \
    make -j$(nproc) && \
    make install-strip install-conf DESTDIR=/fakeroot && \
    cd - && \
    rm -rf suricata-${SURICATA_VERSION} suricata-${SURICATA_VERSION}.tar.gz && \
    apt-get remove -y $SURICATA_DEPS && apt-get autoremove -y --purge && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    echo $SURICATA_RUNTIME_DEPS > /suricata-runtime-deps.txt

# Something about the Docker mounts won't let us copy /var/run in the next stage.
RUN rm -rf /fakeroot/var/run

FROM antrea/openvswitch:${BUILD_TAG}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="An Ubuntu based Docker base image for Antrea."

USER root

# See https://github.com/kubernetes-sigs/iptables-wrappers
# /iptables-wrapper-installer.sh will have permissions of 600.
# --chmod=700 doesn't work with older versions of Docker and requires DOCKER_BUILDKIT=1, so we use
# chmod in the RUN command below instead.
ADD https://raw.githubusercontent.com/kubernetes-sigs/iptables-wrappers/9e6ce59c864623ea71a6f7d59c35fcb13a919b87/iptables-wrapper-installer.sh /iptables-wrapper-installer.sh

COPY --from=suricata-builder /suricata-runtime-deps.txt /suricata-runtime-deps.txt

RUN apt-get update && apt-get install -y --no-install-recommends ipset jq inotify-tools && \
    apt-get install -y --no-install-recommends `cat /suricata-runtime-deps.txt` && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    chmod +x /iptables-wrapper-installer.sh && \
    /iptables-wrapper-installer.sh

COPY --from=suricata-builder /fakeroot /

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
