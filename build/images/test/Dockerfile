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
FROM antrea/openvswitch:${BUILD_TAG}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image for Antrea integration tests."

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iptables ipset jq make wget gcc libc6-dev ca-certificates git && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

ARG GO_VERSION
ENV GOPATH /go

RUN GO_ARCHIVE=$(wget -q -O - "https://go.dev/dl/?mode=json&include=all" | jq --arg version_prefix "go${GO_VERSION}." -r '. | map(select(. | .version | startswith($version_prefix))) | first | .files[] | select(.os == "linux" and .arch == "amd64" and .kind == "archive").filename') && \
    wget -q -O - https://go.dev/dl/${GO_ARCHIVE} | tar xz -C /usr/local/ && \
    export PATH="/usr/local/go/bin:$PATH" && \
    mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

WORKDIR $GOPATH

COPY build/images/scripts/* /usr/local/bin/
COPY build/images/test/test-integration /usr/local/bin/
