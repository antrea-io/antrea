FROM golang:1.15 as flow-aggregator-build

WORKDIR /antrea

COPY . /antrea

# Make sure the flow-aggregator binary is statically linked.
RUN CGO_ENABLED=0 make flow-aggregator

FROM scratch

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="The docker image for the flow aggregator"

ENV USER root

COPY --from=flow-aggregator-build /antrea/bin/flow-aggregator /

ENTRYPOINT ["/flow-aggregator"]
