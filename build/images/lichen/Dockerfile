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
FROM golang:${GO_VERSION} as install

ARG LICHEN_VERSION=v0.1.7

RUN GO111MODULE=on GOBIN=/lichen/ go install github.com/uw-labs/lichen@$LICHEN_VERSION

ADD https://raw.githubusercontent.com/uw-labs/lichen/$LICHEN_VERSION/LICENSE /lichen/LICENSE

# lichen invokes go at runtime
FROM golang:${GO_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image which includes lichen (https://github.com/uw-labs/lichen)"

WORKDIR /lichen

# Includes a copy of the MIT license
COPY --from=install /lichen /lichen

ENTRYPOINT ["/lichen/lichen"]
