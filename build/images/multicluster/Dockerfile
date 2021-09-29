ARG GO_VERSION

FROM golang:${GO_VERSION} as builder
WORKDIR /antrea

COPY go.mod /antrea/go.mod

RUN go mod download

COPY . /antrea

RUN cd multicluster && make build

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /antrea/multicluster/bin/manager /
