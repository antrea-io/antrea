FROM ubuntu:18.04 as ovs-debs

# Some patches may not apply cleanly if another version is provided.
ARG OVS_VERSION=2.11.1

# Install dependencies for building OVS deb packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget curl git ca-certificates build-essential fakeroot graphviz \
            bzip2 autoconf automake debhelper dh-autoreconf libssl-dev libtool openssl procps \
            python-all python-twisted-conch python-zopeinterface python-six libunbound-dev

COPY apply-patches.sh /

# Download OVS source code and build debs
RUN wget -q -O - https://www.openvswitch.org/releases/openvswitch-$OVS_VERSION.tar.gz  | tar xz -C /tmp && \
    rm -rf openvswitch-$OVS_VERSION.tar.gz && \
    cd /tmp/openvswitch* && \
    /apply-patches.sh && \
    DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary && \
    cd /tmp && mkdir ovs-debs && \
    mv libopenvswitch_*.deb openvswitch-common_*.deb openvswitch-switch_*.deb python-openvswitch_*.deb \
       openvswitch-ipsec_*.deb ovs-debs/ && \
    cd / && rm -rf /tmp/openvswitch*


FROM ubuntu:18.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which includes Open vSwitch built from source."

COPY --from=ovs-debs /tmp/ovs-debs/* /tmp/ovs-debs/
COPY charon-logging.conf /tmp

# We clean-up apt cache after installing packages to reduce the size of the
# final image
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables libstrongswan-standard-plugins && \
    (dpkg -i /tmp/ovs-debs/*.deb || apt-get -f -y --no-install-recommends install) && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    sed -i "/^.*filelog.*{/r /tmp/charon-logging.conf" /etc/strongswan.d/charon-logging.conf && \
    rm -rf /tmp/*
