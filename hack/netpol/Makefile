# TODO: use kustomize if the code stays in the Antrea repo for a long time.
VERSION ?= alpha6

.PHONY: all
all: build

.PHONY: build
build:
	docker build -t antrea/netpol:$(VERSION) .
	docker tag antrea/netpol:$(VERSION) antrea/netpol:latest

# requires permission to the Docker repo
# we push a new image every time the master branch is updated
.PHONY: push
push: build
	docker push antrea/netpol:latest

# automated as well, if the version is not incremented manually when there is a
# change to the netpol code, the Dockerhub image will be overwritten.
.PHONY: push-release
push-release: build
	docker push antrea/netpol:$(VERSION)
