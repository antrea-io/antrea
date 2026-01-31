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

FROM ubuntu:24.04 AS cni-binaries

ARG CNI_BINARIES_VERSION

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
    wget -q -O - https://github.com/containernetworking/plugins/releases/download/$CNI_BINARIES_VERSION/cni-plugins-linux-${pluginsArch}-$CNI_BINARIES_VERSION.tgz | tar xz -C /opt/cni/bin $CNI_PLUGINS

FROM golang:${GO_VERSION} AS iptables-wrapper

ARG IPTABLES_WRAPPER_SHA=c6b9b2d4ee8701f3d476768ab8732d1b85ec7fef

# Can be updated to "git clone --depth 1 --revision ${IPTABLES_WRAPPER_SHA}" when Git 2.49+ is included in the golang image.
RUN git clone https://github.com/kubernetes-sigs/iptables-wrappers.git /iptables-wrappers && \
    cd /iptables-wrappers && git checkout ${IPTABLES_WRAPPER_SHA} && \
    make build

FROM antrea-openvswitch

ARG SURICATA_VERSION

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="An Ubuntu based Docker base image for Antrea."

USER root

COPY --from=iptables-wrapper /iptables-wrappers/iptables-wrapper-installer.sh /
COPY --from=iptables-wrapper /iptables-wrappers/bin/iptables-wrapper /

RUN apt-get update && apt-get install -y --no-install-recommends ipset jq inotify-tools gpg-agent software-properties-common && \
    add-apt-repository ppa:oisf/suricata-${SURICATA_VERSION} && apt-get update && apt-get install -y suricata && \
    apt-get remove -y gpg-agent software-properties-common && apt-get autoremove -y && rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    /iptables-wrapper-installer.sh

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
