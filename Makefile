# go options
GO          ?= go
LDFLAGS     :=
GOFLAGS     :=
BINDIR      := $(CURDIR)/bin
GO_FILES := $(shell find . -name '*.go')
GOPATH      ?= $$(go env GOPATH)

.PHONY: all
all: bin build

include versioning.mk

LDFLAGS += $(VERSION_LDFLAGS)

.PHONY: bin
bin:
	GOBIN=$(BINDIR) $(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' github.com/vmware-tanzu/antrea/cmd/...

.PHONY: build
build: bin
build: ubuntu

.PHONY: test
test: build
test: test-unit
test: test-fmt

.PHONY: test-unit
test-unit:
	@echo
	@echo "==> Running unit tests <=="
	$(GO) test -cover github.com/vmware-tanzu/antrea/pkg/...

.PHONY: test-integration
test-integration:
	@echo
	@echo "==> Running integration tests <=="
	@echo "SOME TESTS WILL FAIL IF NOT RUN AS ROOT!"
	$(GO) test github.com/vmware-tanzu/antrea/test/integration/...

test-fmt:
	@echo
	@echo "===> Checking format of Go files <==="
	@test -z "$$(gofmt -s -l -d $(GO_FILES) | tee /dev/stderr)"

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
	@echo "===> Building antrea-ubuntu Docker image <==="
	docker build -t antrea-ubuntu -f build/images/Dockerfile.ubuntu .
	docker tag antrea-ubuntu antrea-ubuntu:$(DOCKER_IMG_VERSION)
