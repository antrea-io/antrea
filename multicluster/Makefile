# For controller-gen, float value is not allowed by default as it is considered dangerous
# See https://github.com/kubernetes-sigs/controller-tools/issues/245
# However the ResourceExport/Import refers to ACNP type definition and the priority field in ACNP spec is type float64.
# Hence, before any ACNP spec bumps that changes the priorty field to a different type,
# the allowDangerousTypes flag is needed for CRD manifests to generate correctly.
CRD_OPTIONS ?= "crd:allowDangerousTypes=true"

GO          ?= go

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell $(GO) env GOBIN))
GOBIN=$(shell $(GO) env GOPATH)/bin
else
GOBIN=$(shell $(GO) env GOBIN)
endif

GO_VERSION         := $(shell head -n 1 ../build/images/deps/go-version)
DOCKER_BUILD_ARGS = --build-arg GO_VERSION=$(GO_VERSION)

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

GO_VERSION         := $(shell head -n 1 ../build/images/deps/go-version)
DOCKER_BUILD_ARGS = --build-arg GO_VERSION=$(GO_VERSION)

YEAR :=$(shell date "+%Y")
.PHONY: all
all: bin

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: crdgen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CURDIR)/hack/generate-manifest.sh -g > build/yamls/antrea-multicluster-leader-global.yml
	$(CURDIR)/hack/generate-manifest.sh -n antrea-multicluster > build/yamls/antrea-multicluster-leader-namespaced.yml
	$(CURDIR)/hack/generate-manifest.sh -l antrea-multicluster > build/yamls/antrea-multicluster-leader.yml
	$(CURDIR)/hack/generate-manifest.sh -m > build/yamls/antrea-multicluster-member.yml
	$(CURDIR)/hack/update-checksum.sh

fmt: ## Run go fmt against code.
	$(GO) fmt ./...

vet: ## Run go vet against code.
	$(GO) vet ./...

.PHONY: .coverage
.coverage:
	mkdir -p $(CURDIR)/.coverage

.PHONY: test-unit test-integration
test-unit: fmt vet .coverage
	@echo "==> Running unit tests <=="
	$(GO) test -race -coverprofile=.coverage/coverage-unit.txt -covermode=atomic -cover antrea.io/antrea/multicluster/controllers/multicluster/...
test-integration: .coverage
	@echo "==> Running Multi-cluster integration tests <=="
	$(CURDIR)/hack/verify-tools.sh
	$(CURDIR)/hack/mc-integration-test.sh
##@ Build

bin: fmt vet ## Build manager binary.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o bin/antrea-mc-controller antrea.io/antrea/multicluster/cmd/...

.PHONY: antrea-mc-instr-binary
antrea-mc-instr-binary:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -cover -coverpkg=antrea.io/antrea/multicluster/...,antrea.io/antrea/multicluster/cmd/... -o bin/antrea-mc-controller-coverage antrea.io/antrea/multicluster/cmd/...

run: manifests generate fmt vet ## Run a controller from your host.
	$(GO) run ./main.go

##@ Deployment

.PHONY: crdgen
crdgen:
	@echo "===> Updating generated base manifests <==="
	$(CURDIR)/hack/update-codegen.sh crdgen

codegen:
	./hack/update-codegen.sh

.PHONY: mockgen
mockgen:
	@echo "===> Updating generated mock code <==="
	$(CURDIR)/hack/update-codegen.sh mockgen
