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
FROM golang:${GO_VERSION} AS flow-aggregator-build

WORKDIR /antrea

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download

COPY . /antrea

# Build antctl first in order to share an extra layer with other Antrea Docker images.
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build/ \
    make antctl-linux && mv bin/antctl-linux bin/antctl

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build/ \
    make flow-aggregator

# Chose this base image so that a shell is available for users to exec into the container, run antctl and run tools like pprof easily
FROM ubuntu:24.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="The docker image for the flow aggregator"

# install ca-certificates
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=flow-aggregator-build /antrea/bin/flow-aggregator /
COPY --from=flow-aggregator-build /antrea/bin/antctl /usr/local/bin/

ENTRYPOINT ["/flow-aggregator"]
