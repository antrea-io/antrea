FROM ubuntu:20.04 as cni-binary

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker which runs the dhcp daemon from the containernetworking project."

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates

# Leading dot is required for the tar command below
ENV CNI_PLUGINS="./dhcp"

RUN mkdir -p /opt/cni/bin && \
    wget -q -O - https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz | tar xz -C /opt/cni/bin $CNI_PLUGINS

FROM ubuntu:20.04

COPY --from=cni-binary /opt/cni/bin/* /usr/local/bin

ENTRYPOINT ["dhcp", "daemon"]
