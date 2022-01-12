
# Image URL to use all building/pushing image targets
IMG ?= antrea/antrea-mc-controller:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
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

.PHONY: all
all: build

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

manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=controller-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	$(CURDIR)/hack/generate-manifest.sh -g > build/yamls/antrea-multicluster-leader-global.yml
	$(CURDIR)/hack/generate-manifest.sh -l changeme > build/yamls/antrea-multicluster-leader-namespaced.yml
	$(CURDIR)/hack/generate-manifest.sh -m > build/yamls/antrea-multicluster-member.yml

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

.PHONY: .coverage
.coverage:
	mkdir -p $(CURDIR)/.coverage

.PHONY: test-unit test-integration
test-unit: fmt vet .coverage
	@echo "==> Running unit tests <=="
	go test -race -coverprofile=.coverage/coverage-unit.txt -covermode=atomic -cover antrea.io/antrea/multicluster/controllers/multicluster/...
test-integration: .coverage
	@echo "==> Running integration tests <=="
ifneq ($(NO_LOCAL),)
	@echo "===> Building Antrea Multi-cluster Integration Test Docker image <==="
	docker build -t antrea/mc-test -f build/images/test/Dockerfile $(DOCKER_BUILD_ARGS) .
	$(CURDIR)/hack/verify-tools.sh "/home/jenkins"
	$(CURDIR)/hack/mc-integration-test.sh "/home/jenkins"
else
	$(CURDIR)/hack/verify-tools.sh
	$(CURDIR)/hack/mc-integration-test.sh
endif
##@ Build

build: generate fmt vet ## Build manager binary.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/antrea-mc-controller antrea.io/antrea/multicluster/cmd/...

run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

#docker-build: test ## Build docker image with the manager.
docker-build: build ## Build docker image with the manager.
	docker build --target product -f build/images/Dockerfile -t ${IMG} .

##@ Deployment

install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/default | kubectl delete -f -


CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1)

KUSTOMIZE = $(shell pwd)/bin/kustomize

kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v3@v3.8.7)

codegen:
	./hack/update-codegen.sh

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
