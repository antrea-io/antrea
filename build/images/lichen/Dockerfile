FROM golang:1.15 as install

ARG LICHEN_VERSION=v0.1.3

RUN GO111MODULE=on GOBIN=/lichen/ go get github.com/uw-labs/lichen@$LICHEN_VERSION

ADD https://raw.githubusercontent.com/uw-labs/lichen/$LICHEN_VERSION/LICENSE /lichen/LICENSE

# lichen invokes go at runtime
FROM golang:1.15

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image which includes lichen (https://github.com/uw-labs/lichen)"

WORKDIR /lichen

# Includes a copy of the MIT license
COPY --from=install /lichen /lichen

ENTRYPOINT ["/lichen/lichen"]
