ARG OVS_VERSION
FROM ubuntu:20.04 as cni-binaries

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


FROM antrea/openvswitch:${OVS_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="Takes care of building the Antrea binaries as part of building the image."

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    ipset \
    jq \
 && rm -rf /var/lib/apt/lists/*

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
