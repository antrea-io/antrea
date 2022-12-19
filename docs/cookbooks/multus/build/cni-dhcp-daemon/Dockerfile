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

FROM ubuntu:22.04 as cni-binary

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker which runs the dhcp daemon from the containernetworking project."

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates

# Leading dot is required for the tar command below
ENV CNI_PLUGINS="./dhcp"

RUN mkdir -p /opt/cni/bin && \
    wget -q -O - https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz | tar xz -C /opt/cni/bin $CNI_PLUGINS

FROM ubuntu:22.04

COPY --from=cni-binary /opt/cni/bin/* /usr/local/bin

ENTRYPOINT ["dhcp", "daemon"]
