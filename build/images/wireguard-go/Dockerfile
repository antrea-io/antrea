ARG GO_VERSION
ARG WIREGUARD_GO_VERSION

FROM golang:${GO_VERSION} as builder

RUN git clone https://git.zx2c4.com/wireguard-go && \
    cd wireguard-go && \
    git checkout ${WIREGUARD_GO_VERSION} && \
    make && \ 
    make install

RUN git clone https://git.zx2c4.com/wireguard-tools && \
    cd wireguard-tools && \
    cd src && \
    make && \
    make install

FROM ubuntu:20.04
COPY --from=builder /usr/bin/wireguard-go /usr/bin/wg /usr/bin/
