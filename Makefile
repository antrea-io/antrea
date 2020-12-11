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

.PHONY: antrea-agent-instr-binary
antrea-agent-instr-binary:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) test -tags testbincover -covermode count -coverpkg=github.com/vmware-tanzu/antrea/pkg/... -c -o $(BINDIR)/antrea-agent-coverage $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-agent

.PHONY: antrea-controller
antrea-controller:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-controller

.PHONY: .coverage
.coverage:
	mkdir -p $(CURDIR)/.coverage

.PHONY: antrea-controller-instr-binary
antrea-controller-instr-binary:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) test -tags testbincover -covermode count -coverpkg=github.com/vmware-tanzu/antrea/pkg/... -c -o $(BINDIR)/antrea-controller-coverage $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-controller

.PHONY: antrea-cni
antrea-cni:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-cni

.PHONY: antctl-ubuntu
antctl-ubuntu:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antctl

.PHONY: antctl-instr-binary
antctl-instr-binary:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) test -tags testbincover -covermode count -coverpkg=github.com/vmware-tanzu/antrea/pkg/... -c -o $(BINDIR)/antctl-coverage $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antctl

.PHONY: windows-bin
windows-bin:
	@mkdir -p $(BINDIR)
	GOOS=windows $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/antrea-cni \
		github.com/vmware-tanzu/antrea/cmd/antrea-agent

.PHONY: flow-aggregator
flow-aggregator:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/flow-aggregator

.PHONY: test-unit test-integration
ifeq ($(UNAME_S),Linux)
test-unit: .linux-test-unit
test-integration: .linux-test-integration
else ifneq (,$(findstring MSYS_NT-,$(UNAME_S)))
test-unit: .windows-test-unit
test-integration:
	$(error Cannot use target 'test-integration' on Windows, but you can run integration tests with 'docker-test-integration')
else
test-unit:
	$(error Cannot use target 'test-unit' on OS $(UNAME_S), but you can run unit tests with 'docker-test-unit')
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
		golang:1.15

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
docker-test-integration: .coverage
	@echo "===> Building Antrea Integration Test Docker image <==="
ifneq ($(DOCKER_REGISTRY),"")
	docker build -t antrea/test -f build/images/test/Dockerfile .
else
	docker build --pull -t antrea/test -f build/images/test/Dockerfile .
endif
	@docker run --privileged --rm \
		-e "GOCACHE=/tmp/gocache" \
		-e "GOPATH=/tmp/gopath" \
		-e "INCONTAINER=true" \
		-w /usr/src/github.com/vmware-tanzu/antrea \
		-v $(DOCKER_CACHE)/gopath:/tmp/gopath \
		-v $(DOCKER_CACHE)/gocache:/tmp/gocache \
		-v $(CURDIR)/.coverage:/usr/src/github.com/vmware-tanzu/antrea/.coverage \
		-v $(CURDIR):/usr/src/github.com/vmware-tanzu/antrea:ro \
		-v /lib/modules:/lib/modules \
		antrea/test test-integration $(USERID) $(GRPID)

.PHONY: docker-tidy
docker-tidy: $(DOCKER_CACHE)
	@rm -f go.sum
	@$(DOCKER_ENV) $(GO) mod tidy
	@rm -f plugins/octant/go.sum
	@$(DOCKER_ENV) bash -c "cd plugins/octant && $(GO) mod tidy"
	@chmod -R 0755 $<
	@chmod 0644 go.sum plugins/octant/go.sum

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
.linux-test-unit: .coverage
	@echo
	@echo "==> Running unit tests <=="
	$(GO) test -race -coverprofile=.coverage/coverage-unit.txt -covermode=atomic -cover github.com/vmware-tanzu/antrea/cmd/... github.com/vmware-tanzu/antrea/pkg/...

.PHONY: .windows-test-unit
.windows-test-unit:
	@echo
	@echo "==> Running unit tests <=="
	$(GO) test -race github.com/vmware-tanzu/antrea/cmd/... github.com/vmware-tanzu/antrea/pkg/...

.PHONY: tidy
tidy:
	@rm -f go.sum
	@$(GO) mod tidy
	@rm -f plugins/octant/go.sum
	@cd plugins/octant && $(GO) mod tidy

.PHONY: .linux-test-integration
.linux-test-integration: .coverage
	@echo
	@echo "==> Running integration tests <=="
	@echo "SOME TESTS WILL FAIL IF NOT RUN AS ROOT!"
	$(GO) test -coverpkg=github.com/vmware-tanzu/antrea/pkg/... -coverprofile=.coverage/coverage-integration.txt -covermode=atomic -cover github.com/vmware-tanzu/antrea/test/integration/...

test-tidy:
	@echo
	@echo "===> Checking go.mod tidiness <==="
	@GO=$(GO) $(CURDIR)/hack/tidy-check.sh
	@echo "===> Checking octant plugins go.mod tidiness <==="
	@GO=$(GO) $(CURDIR)/hack/tidy-check.sh plugins/octant

.PHONY: fmt
fmt:
	@echo
	@echo "===> Formatting Go files <==="
	@gofmt -s -l -w $(GO_FILES)

.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.32.1

.PHONY: golangci
golangci: .golangci-bin
	@echo "===> Running golangci for linux <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml
	@echo "===> Running golangci for windows <==="
	@GOOS=windows .golangci-bin/golangci-lint run -c .golangci.yml

.PHONY: golangci-fix
golangci-fix: .golangci-bin
	@echo "===> Running golangci-fix for linux <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml --fix
	@echo "===> Running golangci-fix for windows <==="
	@GOOS=windows .golangci-bin/golangci-lint run -c .golangci.yml --fix

.PHONY: lint
lint: .golangci-bin
	@echo "===> Running lint for linux <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci-golint.yml
	@echo "===> Running lint for windows <==="
	@GOOS=windows .golangci-bin/golangci-lint run -c .golangci-golint.yml

.PHONY: clean
clean:
	@rm -rf $(BINDIR)
	@rm -rf $(DOCKER_CACHE)
	@rm -rf .golangci-bin
	@rm -rf .coverage

.PHONY: codegen
codegen:
	@echo "===> Updating generated code <==="
	$(CURDIR)/hack/update-codegen.sh

### Docker images ###

.PHONY: ubuntu
ubuntu:
	@echo "===> Building antrea/antrea-ubuntu Docker image <==="
	docker build --pull -t antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.ubuntu .
	docker tag antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) antrea/antrea-ubuntu
	docker tag antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/antrea-ubuntu

# Build bins in a golang container, and build the antrea-ubuntu Docker image.
.PHONY: build-ubuntu
build-ubuntu:
	@echo "===> Building Antrea bins and antrea/antrea-ubuntu Docker image <==="
ifneq ($(DOCKER_REGISTRY),"")
	docker build -t antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.ubuntu .
else
	docker build --pull -t antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.ubuntu .
endif
	docker tag antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) antrea/antrea-ubuntu
	docker tag antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/antrea-ubuntu

.PHONY: build-windows
build-windows:
	@echo "===> Building Antrea bins and antrea/antrea-windows Docker image <==="
ifneq ($(DOCKER_REGISTRY),"")
	docker build -t antrea/antrea-windows:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.windows .
else
	docker build --pull -t antrea/antrea-windows:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.windows .
endif
	docker tag antrea/antrea-windows:$(DOCKER_IMG_VERSION) antrea/antrea-windows
	docker tag antrea/antrea-windows:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/antrea-windows

.PHONY: build-ubuntu-coverage
build-ubuntu-coverage:
	@echo "===> Building Antrea bins and antrea/antrea-ubuntu-coverage Docker image <==="
ifneq ($(DOCKER_REGISTRY),"")
	docker build -t antrea/antrea-ubuntu-coverage:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.coverage .
else
	docker build --pull -t antrea/antrea-ubuntu-coverage:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.build.coverage .
endif
	docker tag antrea/antrea-ubuntu-coverage:$(DOCKER_IMG_VERSION) antrea/antrea-ubuntu-coverage
	docker tag antrea/antrea-ubuntu-coverage:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/antrea-ubuntu-coverage

.PHONY: manifest
manifest:
	@echo "===> Generating dev manifest for Antrea <==="
	$(CURDIR)/hack/generate-manifest.sh --mode dev > build/yamls/antrea.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --ipsec > build/yamls/antrea-ipsec.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --cloud EKS --encap-mode networkPolicyOnly > build/yamls/antrea-eks.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --cloud GKE --encap-mode noEncap > build/yamls/antrea-gke.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --cloud AKS --encap-mode networkPolicyOnly > build/yamls/antrea-aks.yml
	$(CURDIR)/hack/generate-manifest-octant.sh --mode dev > build/yamls/antrea-octant.yml
	$(CURDIR)/hack/generate-manifest-windows.sh --mode dev > build/yamls/antrea-windows.yml
	$(CURDIR)/hack/generate-manifest-flow-aggregator.sh --mode dev > build/yamls/flow-aggregator.yml

.PHONY: manifest-coverage
manifest-coverage:
	$(CURDIR)/hack/generate-manifest.sh --mode dev --coverage > build/yamls/antrea-coverage.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --ipsec --coverage > build/yamls/antrea-ipsec-coverage.yml

.PHONY: octant-antrea-ubuntu
octant-antrea-ubuntu:
	@echo "===> Building antrea/octant-antrea-ubuntu Docker image <==="
	docker build --pull -t antrea/octant-antrea-ubuntu:$(DOCKER_IMG_VERSION) -f build/images/Dockerfile.octant.ubuntu .
	docker tag antrea/octant-antrea-ubuntu:$(DOCKER_IMG_VERSION) antrea/octant-antrea-ubuntu
	docker tag antrea/octant-antrea-ubuntu:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/octant-antrea-ubuntu

.PHONY: flow-aggregator-ubuntu
flow-aggregator-ubuntu:
	@echo "===> Building antrea/flow-aggregator Docker image <==="
ifneq ($(DOCKER_REGISTRY),"")
	docker build -t antrea/flow-aggregator:$(DOCKER_IMG_VERSION) -f build/images/flow-aggregator/Dockerfile .
else
	docker build --pull -t antrea/flow-aggregator:$(DOCKER_IMG_VERSION) -f build/images/flow-aggregator/Dockerfile .
endif
	docker tag antrea/flow-aggregator:$(DOCKER_IMG_VERSION) antrea/flow-aggregator
	docker tag antrea/flow-aggregator:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/flow-aggregator
	docker tag antrea/flow-aggregator:$(DOCKER_IMG_VERSION) projects.registry.vmware.com/antrea/flow-aggregator:$(DOCKER_IMG_VERSION)

.PHONY: verify
verify:
	@echo "===> Verifying spellings <==="
	$(CURDIR)/hack/verify-spelling.sh
	@echo "===> Verifying Table of Contents <==="
	$(CURDIR)/hack/verify-toc.sh
	@echo "===> Verifying documentation formatting for website <==="
	$(CURDIR)/hack/verify-docs-for-website.sh

.PHONY: toc
toc:
	@echo "===> Generating Table of Contents for Antrea docs <==="
	$(CURDIR)/hack/update-toc.sh

.PHONE: markdownlint
markdownlint:
	@echo "===> Running markdownlint <==="
	markdownlint -c .markdownlint-config.yml -i CHANGELOG.md -i hack/netpol -i CODE_OF_CONDUCT.md .

.PHONE: markdownlint-fix
markdownlint-fix:
	@echo "===> Running markdownlint <==="
	markdownlint --fix -c .markdownlint-config.yml -i CHANGELOG.md -i hack/netpol -i CODE_OF_CONDUCT.md .

.PHONY: spelling-fix
spelling-fix:
	@echo "===> Updating incorrect spellings <==="
	$(CURDIR)/hack/update-spelling.sh
