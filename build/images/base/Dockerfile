ARG OVS_VERSION
FROM ubuntu:20.04 as cni-binaries

ARG CNI_BINARIES_VERSION
ARG WHEREABOUTS_VERSION=v0.5.1

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

FROM antrea/openvswitch:${OVS_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="An Ubuntu based Docker base image for Antrea."

USER root

# See https://github.com/kubernetes-sigs/iptables-wrappers
# /iptables-wrapper-installer.sh will have permissions of 600.
# --chmod=700 doesn't work with older versions of Docker and requires DOCKER_BUILDKIT=1, so we use
# chmod in the RUN command below instead.
ADD https://raw.githubusercontent.com/kubernetes-sigs/iptables-wrappers/9e6ce59c864623ea71a6f7d59c35fcb13a919b87/iptables-wrapper-installer.sh /iptables-wrapper-installer.sh

RUN apt-get update && apt-get install -y --no-install-recommends ipset jq && \
    rm -rf /var/lib/apt/lists/* && \
    chmod +x /iptables-wrapper-installer.sh && \
    /iptables-wrapper-installer.sh

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
