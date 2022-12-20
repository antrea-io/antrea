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

FROM ubuntu:22.04
COPY --from=builder /usr/bin/wireguard-go /usr/bin/wg /usr/bin/
