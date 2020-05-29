SHELL              := /bin/bash
# go options
GO                 ?= go
LDFLAGS            :=
GOFLAGS            :=
BINDIR             ?= $(CURDIR)/bin
GO_FILES           := $(shell find . -type d -name '.cache' -prune -o -type f -name '*.go' -print)
GOPATH             ?= $$($(GO) env GOPATH)
DOCKER_CACHE       := $(CURDIR)/.cache
ANTCTL_BINARY_NAME ?= antctl

.PHONY: all
all: build

include versioning.mk

LDFLAGS += $(VERSION_LDFLAGS)

UNAME_S := $(shell uname -s)
USERID  := $(shell id -u)
GRPID   := $(shell id -g)

.PHONY: bin
bin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/...

.PHONY: antrea-agent
antrea-agent:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-agent

.PHONY: antrea-controller
antrea-controller:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-controller


.PHONY: antrea-cni
antrea-cni:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-cni

.PHONY: antctl-ubuntu
antctl-ubuntu:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antctl

.PHONY: antrea-octant-plugin
antrea-octant-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-octant-plugin

.PHONY: windows-bin
windows-bin:
	@mkdir -p $(BINDIR)
	GOOS=windows $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-cni \
		github.com/vmware-tanzu/antrea/cmd/antrea-agent

.PHONY: test-unit test-integration
ifeq ($(UNAME_S),Linux)
test-unit: .linux-test-unit
test-integration: .linux-test-integration
else
test-unit:
	$(error Cannot use target 'test-unit' on a non-Linux OS, but you can run unit tests with 'docker-test-unit')
test-integration:
	$(error Cannot use target 'test-integration' on a non-Linux OS, but you can run integration tests with 'docker-test-integration')
endif

.PHONY: build
build: build-ubuntu

.PHONY: test
test: golangci
test: build
test: docker-test-unit
test: docker-test-integration

$(DOCKER_CACHE):
	@mkdir -p $@/gopath
	@mkdir -p $@/gocache

# Since the WORKDIR is mounted from host, the $(id -u):$(id -g) user can access it.
# Inside the docker, the user is nameless and does not have a home directory. This is ok for our use case.
DOCKER_ENV := \
	@docker run --rm -u $$(id -u):$$(id -g) \
		-e "GOCACHE=/tmp/gocache" \
		-e "GOPATH=/tmp/gopath" \
		-w /usr/src/github.com/vmware-tanzu/antrea \
		-v $(DOCKER_CACHE)/gopath:/tmp/gopath \
		-v $(DOCKER_CACHE)/gocache:/tmp/gocache \
		-v $(CURDIR):/usr/src/github.com/vmware-tanzu/antrea \
		golang:1.13

.PHONY: docker-bin
docker-bin: $(DOCKER_CACHE)
	$(DOCKER_ENV) make bin
	@chmod -R 0755 $<

.PHONY: docker-windows-bin
docker-windows-bin: $(DOCKER_CACHE)
	$(DOCKER_ENV) make windows-bin

.PHONY: docker-test-unit
docker-test-unit: $(DOCKER_CACHE)
	@$(DOCKER_ENV) make test-unit
	@chmod -R 0755 $<

.PHONY: docker-test-integration
docker-test-integration:
	@echo "===> Building Antrea Integration Test Docker image <==="
	@docker build -t antrea/test -f build/images/test/Dockerfile .
	@docker run --privileged --rm \
		-e "GOCACHE=/tmp/gocache" \
		-e "GOPATH=/tmp/gopath" \
		-e "INCONTAINER=true" \
		-w /usr/src/github.com/vmware-tanzu/antrea \
		-v $(DOCKER_CACHE)/gopath:/tmp/gopath \
		-v $(DOCKER_CACHE)/gocache:/tmp/gocache \
		-v $(CURDIR):/usr/src/github.com/vmware-tanzu/antrea:ro \
		antrea/test test-integration $(USERID) $(GRPID)

.PHONY: docker-tidy
docker-tidy: $(DOCKER_CACHE)
	@rm -f go.sum
	@$(DOCKER_ENV) $(GO) mod tidy
	@chmod -R 0755 $<
	@chmod 0644 go.sum

ANTCTL_BINARIES := antctl-darwin antctl-linux antctl-windows
$(ANTCTL_BINARIES): antctl-%:
	@GOOS=$* $(GO) build -o $(BINDIR)/$@ $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antctl
	@if [[ $@ != *windows ]]; then \
	  chmod 0755 $(BINDIR)/$@; \
	else \
	  mv $(BINDIR)/$@ $(BINDIR)/$@.exe; \
	fi

.PHONY: antctl
antctl: $(ANTCTL_BINARIES)

.PHONY: antctl-release
antctl-release:
	@$(GO) build -o $(BINDIR)/$(ANTCTL_BINARY_NAME) $(GOFLAGS) -ldflags '-s -w $(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antctl

.PHONY: .linux-test-unit
.linux-test-unit:
	@echo
	@echo "==> Running unit tests <=="
	$(GO) test -race -cover github.com/vmware-tanzu/antrea/pkg/...

.PHONY: tidy
tidy:
	@rm -f go.sum
	@$(GO) mod tidy

.PHONY: .linux-test-integration
.linux-test-integration:
	@echo
	@echo "==> Running integration tests <=="
	@echo "SOME TESTS WILL FAIL IF NOT RUN AS ROOT!"
	$(GO) test github.com/vmware-tanzu/antrea/test/integration/...

test-tidy:
	@echo
	@echo "===> Checking go.mod tidiness <==="
	@GO=$(GO) $(CURDIR)/hack/tidy-check.sh

.PHONY: fmt
fmt:
	@echo
	@echo "===> Formatting Go files <==="
	@gofmt -s -l -w $(GO_FILES)

.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.21.0

.PHONY: golangci
golangci: .golangci-bin
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml

.PHONY: golangci-fix
golangci-fix: .golangci-bin
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml --fix

.PHONY: lint
lint: .golangci-bin
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci-golint.yml

.PHONY: clean
clean:
	@rm -rf $(BINDIR)
	@rm -rf $(DOCKER_CACHE)
	@rm -rf .golangci-bin

.PHONY: codegen
codegen:
	@echo "===> Updating generated code <==="
	$(CURDIR)/hack/update-codegen.sh

### Docker images ###

.PHONY: ubuntu
ubuntu:
	@echo "===> Building antrea/antrea-ubuntu Docker image <==="
	docker build -t antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.ubuntu .
	docker tag antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) antrea/antrea-ubuntu

# Build bins in a golang container, and build the antrea-ubuntu Docker image.
.PHONY: build-ubuntu
build-ubuntu:
	@echo "===> Building Antrea bins and antrea/antrea-ubuntu Docker image <==="
	docker build -t antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.ubuntu .
	docker tag antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) antrea/antrea-ubuntu

.PHONY: build-windows
build-windows:
	@echo "===> Building Antrea bins and antrea/antrea-windows Docker image <==="
	docker build -t antrea/antrea-windows:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.windows .
	docker tag antrea/antrea-windows:$(DOCKER_IMG_VERSION) antrea/antrea-windows

.PHONY: manifest
manifest:
	@echo "===> Generating dev manifest for Antrea <==="
	$(CURDIR)/hack/generate-manifest.sh --mode dev > build/yamls/antrea.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --ipsec > build/yamls/antrea-ipsec.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --cloud EKS --encap-mode networkPolicyOnly > build/yamls/antrea-eks.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --cloud GKE --encap-mode noEncap > build/yamls/antrea-gke.yml
	$(CURDIR)/hack/generate-manifest-octant.sh --mode dev > build/yamls/antrea-octant.yml
	$(CURDIR)/hack/generate-manifest-windows.sh --mode dev > build/yamls/antrea-windows.yml

.PHONY: octant-antrea-ubuntu
octant-antrea-ubuntu:
	@echo "===> Building antrea/octant-antrea-ubuntu Docker image <==="
	docker build -t antrea/octant-antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.octant.ubuntu .
	docker tag antrea/octant-antrea-ubuntu:$(DOCKER_IMG_VERSION) antrea/octant-antrea-ubuntu

.PHONY: verify-spelling
verify-spelling:
	@echo "===> Verifying spellings <==="
	$(CURDIR)/hack/verify-spelling.sh
