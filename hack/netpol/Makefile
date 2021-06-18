# TODO: use kustomize if the code stays in the Antrea repo for a long time.
VERSION ?= alpha7

.PHONY: all
all: build

.PHONY: build
build:
	docker build -t antrea/netpol:$(VERSION) .
	docker tag antrea/netpol:$(VERSION) antrea/netpol:latest

# requires permission to the Docker repo
# we push a new image every time the main branch is updated
.PHONY: push
push: build
	docker push antrea/netpol:latest

# automated as well, if the version is not incremented manually when there is a
# change to the netpol code, the Dockerhub image will be overwritten.
.PHONY: push-release
push-release: build
	docker push antrea/netpol:$(VERSION)

.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.32.1

.PHONY: golangci
golangci: .golangci-bin
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml

.PHONY: golangci-fix
golangci-fix: .golangci-bin
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml --fix
