# go options
GO              ?= go
LDFLAGS         :=
GOFLAGS         :=
BINDIR          := $(CURDIR)/bin
GO_FILES        := $(shell find . -type d -name '.cache' -prune -o -type f -name '*.go' -print)
GOPATH          ?= $$($(GO) env GOPATH)
DOCKER_CACHE    := $(CURDIR)/.cache

.PHONY: all
all: build

include versioning.mk

LDFLAGS += $(VERSION_LDFLAGS)

UNAME_S := $(shell uname -s)
.PHONY: bin test-unit test-integration

ifeq ($(UNAME_S),Linux)
bin: .linux-bin
test-unit: .linux-test-unit
test-integration: .linux-test-integration
else
bin:
	$(error Cannot use target 'bin' on a non-Linux OS, but you can build Antrea with 'docker-bin')
test-unit:
	$(error Cannot use target 'test-unit' on a non-Linux OS, but you can run unit tests with 'docker-test-unit')
test-integration:
	$(error Cannot use target 'test-integration' on a non-Linux OS)
endif

.PHONY: build
build: build-ubuntu

.PHONY: test
test: build
test: test-unit
test: test-fmt

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

.PHONY: docker-test-unit
docker-test-unit: $(DOCKER_CACHE)
	@$(DOCKER_ENV) make test-unit
	@chmod -R 0755 $<

.PHONY: docker-tidy
docker-tidy: $(DOCKER_CACHE)
	@rm -f go.sum
	@$(DOCKER_ENV) $(GO) mod tidy
	@chmod -R 0755 $<
	@chmod 0644 go.sum

.PHONY: .linux-bin
.linux-bin:
	GOBIN=$(BINDIR) $(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/...

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

test-fmt:
	@echo
	@echo "===> Checking format of Go files <==="
	@test -z "$$(gofmt -s -l -d $(GO_FILES) | tee /dev/stderr)"

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

.PHONY: .linter
.linter:
	@if ! PATH=$$PATH:$(GOPATH)/bin command -v golint > /dev/null; then \
	  echo "===> Installing Golint <==="; \
	  $(GO) get -u golang.org/x/lint/golint; \
	fi

.PHONY: lint
lint: export GOOS=linux
lint: .linter
	@PATH=$$PATH:$(GOPATH)/bin golint ./cmd/... ./pkg/...

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
	docker build -t antrea/antrea-ubuntu -f build/images/Dockerfile.ubuntu .
	docker tag antrea/antrea-ubuntu antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION)

# Build bins in a golang container, and build the antrea-ubuntu Docker image.
.PHONY: build-ubuntu
build-ubuntu:
	@echo "===> Building Antrea bins and antrea/antrea-ubuntu Docker image <==="
	docker build -t antrea/antrea-ubuntu -f build/images/Dockerfile.build.ubuntu .
	docker tag antrea/antrea-ubuntu antrea/antrea-ubuntu:$(DOCKER_IMG_VERSION)

.PHONY: manifest
manifest:
	@echo "===> Generating dev manifest for Antrea <==="
	$(CURDIR)/hack/generate-manifest.sh --mode dev > build/yamls/antrea.yml
	$(CURDIR)/hack/generate-manifest.sh --mode dev --ipsec > build/yamls/antrea-ipsec.yml

.PHONY: octant-antrea-ubuntu
octant-antrea-ubuntu:
	@echo "===> Building octant-antrea-ubuntu Docker image <==="
	docker build -t octant-antrea-ubuntu -f build/images/Dockerfile.octant.ubuntu .
	docker tag octant-antrea-ubuntu octant-antrea-ubuntu:$(DOCKER_IMG_VERSION)
