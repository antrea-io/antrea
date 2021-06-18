FROM python:rc-alpine3.10

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="A Docker image based on Alpine used for netpol tests"

# TODO: remove wget and python, these are no longer needed. We keep them for now
# to avoid breaking CI tests.
RUN apk add --no-cache ca-certificates wget nmap-ncat socat && update-ca-certificates
