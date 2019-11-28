# go options
GO              ?= go
LDFLAGS         :=
GOFLAGS         :=
BINDIR          := $(CURDIR)/bin
GO_FILES        := $(shell find . -type d -name '.cache' -prune -o -type f -name '*.go' -print)
GOPATH          ?= $$(go env GOPATH)
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
		golang:1.12

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
	@$(DOCKER_ENV) go mod tidy
	@chmod -R 0755 $<
	@chmod 0644 go.sum

.PHONY: .linux-bin
.linux-bin:
	GOBIN=$(BINDIR) $(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/...

.PHONY: .linux-test-unit
.linux-test-unit:
	@echo
	@echo "==> Running unit tests <=="
	$(GO) test -cover github.com/vmware-tanzu/antrea/pkg/...

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

.PHONY: lint
lint:
	golint $$(go list ./...)

.PHONY: clean
clean:
	@rm -rf $(BINDIR)
	@rm -rf $(DOCKER_CACHE)
	@rm -f .mockgen .protoc

# Install a specific version of gomock to avoid generating different source code
# for the mocks every time a new version of gomock is released. If a new version
# of gomock is desired, this file should be updated.
.mockgen:
	@echo "===> Installing Mockgen <==="
	@go get github.com/golang/mock/gomock@1.3.1
	@go install github.com/golang/mock/mockgen
	@touch .mockgen

.PHONY: mocks
mocks: .mockgen
	@echo "===> Re-generating mocks with Mockgen <==="
	PATH=$$PATH:$(GOPATH)/bin $(GO) generate ./...

# Install a specific version of k8s.io/code-generator to
# generate monitoring CRDs client and deepcopy
.PHONY: crd-gen
crd-gen:
	@echo "===> Re-generating CRD client and deepcopy with code-generator <==="
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
