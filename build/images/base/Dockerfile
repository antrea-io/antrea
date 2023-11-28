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

FROM antrea/openvswitch:${BUILD_TAG}

ARG SURICATA_VERSION

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="An Ubuntu based Docker base image for Antrea."

USER root

# See https://github.com/kubernetes-sigs/iptables-wrappers
# /iptables-wrapper-installer.sh will have permissions of 600.
# --chmod=700 doesn't work with older versions of Docker and requires DOCKER_BUILDKIT=1, so we use
# chmod in the RUN command below instead.
ADD https://raw.githubusercontent.com/kubernetes-sigs/iptables-wrappers/9e6ce59c864623ea71a6f7d59c35fcb13a919b87/iptables-wrapper-installer.sh /iptables-wrapper-installer.sh

RUN apt-get update && apt-get install -y --no-install-recommends ipset jq inotify-tools gpg-agent software-properties-common && \
    add-apt-repository ppa:oisf/suricata-${SURICATA_VERSION} && apt-get update && apt-get install -y suricata && \
    apt-get remove -y gpg-agent software-properties-common && apt-get autoremove -y && rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    chmod +x /iptables-wrapper-installer.sh && \
    /iptables-wrapper-installer.sh

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
