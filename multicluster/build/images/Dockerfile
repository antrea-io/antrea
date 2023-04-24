# Copyright 2023 Antrea Authors
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

FROM gcr.io/distroless/static:nonroot

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="The Docker image to deploy the Antrea Multi-cluster Controller."

USER root

COPY multicluster/bin/antrea-mc-controller /
