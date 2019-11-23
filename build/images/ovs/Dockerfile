FROM ubuntu:18.04 as ovs-debs

ARG OVS_VERSION=2.11.1

# Install dependencies for building OVS deb packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates build-essential fakeroot graphviz \
            bzip2 autoconf automake debhelper dh-autoreconf libssl-dev libtool openssl procps \
            python-all python-twisted-conch python-zopeinterface python-six libunbound-dev

# Download OVS source code and build debs
RUN wget -q -O - https://www.openvswitch.org/releases/openvswitch-$OVS_VERSION.tar.gz  | tar xz -C /tmp && \
    rm -rf openvswitch-$OVS_VERSION.tar.gz && \
    cd /tmp/openvswitch* && DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary && \
    cd /tmp && mkdir ovs-debs && \
    mv libopenvswitch_*.deb openvswitch-common_*.deb openvswitch-switch_*.deb python-openvswitch_*.deb \
       openvswitch-ipsec_*.deb ovs-debs/ && \
    cd / && rm -rf /tmp/openvswitch*


FROM ubuntu:18.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 18.04 which includes Open vSwitch built from source."

COPY --from=ovs-debs /tmp/ovs-debs/* /tmp/ovs-debs/

# We clean-up apt cache after installing packages to reduce the size of the
# final image
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables libstrongswan-standard-plugins && \
    (dpkg -i /tmp/ovs-debs/*.deb || apt-get -f -y --no-install-recommends install) && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    rm -rf /tmp/ovs-debs && \
    CHARON_FILELOG_CONFIG="\ \ \ \ \ \ \ \ /var/log/strongswan/charon.log {\n\ \ \ \ \ \ \ \ }" && \
    sed -i "/^.*filelog.*{/a $CHARON_FILELOG_CONFIG" /etc/strongswan.d/charon-logging.conf
