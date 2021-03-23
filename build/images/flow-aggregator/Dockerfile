ARG OVS_VERSION
FROM golang:1.15 as flow-aggregator-build

WORKDIR /antrea

COPY . /antrea

RUN make flow-aggregator

FROM antrea/base-ubuntu:${OVS_VERSION}

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="The docker image for the flow aggregator"

USER root

COPY --from=flow-aggregator-build /antrea/bin/flow-aggregator /usr/local/bin/
