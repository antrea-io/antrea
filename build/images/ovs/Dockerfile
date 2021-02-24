FROM ubuntu:20.04 as ovs-debs

# Some patches may not apply cleanly if another version is provided.
ARG OVS_VERSION=2.14.0

# Install dependencies for building OVS deb packages
# We only install python3 packages and we only support building OVS >= 2.13.0.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends wget curl git ca-certificates build-essential fakeroot graphviz \
            bzip2 autoconf automake debhelper dh-python dh-autoreconf libssl-dev libtool openssl procps \
            python3-all python3-twisted python3-zope.interface python3-sphinx \
            libunbound-dev

# Install DPDK for enable ovs-dpdk support.
RUN DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends bison bc flex libelf-dev linux-source-5.4.0 libnuma-dev python3-pip && \
    pip3 install meson ninja && \
    cd /usr/src && tar xjf linux-source-5.4.0.tar.bz2 && \
    cd /usr/src/linux-source-5.4.0 && make defconfig modules_prepare && \
    wget -q -O - https://fast.dpdk.org/rel/dpdk-19.11.2.tar.gz | tar xz -C /usr/src && \
    cd /usr/src/dpdk-stable-19.11.2 && \
    export DPDK_DIR=/usr/src/dpdk-stable-19.11.2 && \
    export DPDK_TARGET=x86_64-native-linuxapp-gcc && \
    export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET && \
    export NFF_GO_NO_MLX_DRIVERS=1 && \
    export NFF_GO_NO_BPF_SUPPORT=1 && \
    echo "CONFIG_RTE_BUILD_SHARED_LIB=y" >> $DPDK_DIR/config/common_base && \
    make RTE_KERNELDIR=/usr/src/linux-source-5.4.0 install T=$DPDK_TARGET DESTDIR=install

COPY apply-patches.sh /
COPY ovs-dpdk.patch /

# Download OVS source code and build debs
RUN wget -q -O - https://www.openvswitch.org/releases/openvswitch-$OVS_VERSION.tar.gz  | tar xz -C /tmp && \
    cd /tmp/openvswitch* && \
    patch -p0 < /ovs-dpdk.patch && \
    /apply-patches.sh && \
    export LD_LIBRARY_PATH=/usr/src/dpdk-stable-19.11.2/x86_64-native-linuxapp-gcc/lib && \
    DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary && \
    cd /tmp && mkdir ovs-debs && \
    mv libopenvswitch_*.deb openvswitch-common_*.deb openvswitch-switch_*.deb python*-openvswitch_*.deb \
       openvswitch-ipsec_*.deb ovs-debs/ && \
    cd / && rm -rf /tmp/openvswitch*


FROM ubuntu:20.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Ubuntu 20.04 which includes Open vSwitch built from source."

COPY --from=ovs-debs /tmp/ovs-debs/* /tmp/ovs-debs/
COPY charon-logging.conf /tmp

# Install OVS debs, iptables, logrotate, and strongSwan; update the OVS
# logrotate config file; update the strongSwan logging config.
# We clean-up apt cache after installing packages to reduce the size of the
# final image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables logrotate libstrongswan-standard-plugins && \
    (dpkg -i /tmp/ovs-debs/*.deb || apt-get -f -y --no-install-recommends install) && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    sed -i "/rotate /a\    #size 100M" /etc/logrotate.d/openvswitch-switch && \
    sed -i "/^.*filelog.*{/r /tmp/charon-logging.conf" /etc/strongswan.d/charon-logging.conf && \
    rm -rf /tmp/*
