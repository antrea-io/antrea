FROM ubuntu:20.04 as install

WORKDIR /

ADD https://github.com/mitchellh/golicense/releases/download/v0.2.0/golicense_0.2.0_linux_x86_64.tar.gz /golicense.tar.gz

WORKDIR /golicense

RUN tar -xzvf /golicense.tar.gz

FROM gcr.io/distroless/base

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image which includes golicense (https://github.com/mitchellh/golicense)"

# Includes a copy of the MIT license
COPY --from=install /golicense /golicense

ENTRYPOINT ["/golicense/golicense"]
