ARG GO_VERSION
FROM golang:${GO_VERSION} as flow-aggregator-build

WORKDIR /antrea

COPY . /antrea

RUN make flow-aggregator antctl-linux
RUN mv bin/antctl-linux bin/antctl

# Chose this base image so that a shell is available for users to exec into the container, run antctl and run tools like pprof easily
FROM ubuntu:20.04

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="The docker image for the flow aggregator"

COPY --from=flow-aggregator-build /antrea/bin/flow-aggregator /
COPY --from=flow-aggregator-build /antrea/bin/antctl /usr/local/bin/

ENTRYPOINT ["/flow-aggregator"]
