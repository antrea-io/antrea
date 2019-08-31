# go options
GO          ?= go
LDFLAGS     :=
GOFLAGS     :=
BINDIR      := $(CURDIR)/bin
GO_FILES := $$(find . -name '*.go')
GOPATH      ?= $$(go env GOPATH)

.PHONY: all
all: bin build

.PHONY: bin
bin:
	GOBIN=$(BINDIR) $(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' okn/cmd/...

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
	$(GO) test -cover $$(go list okn/pkg/... | grep -E -v "okn/pkg/(ovs/ovsconfig|test)")

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
	@rm -f .mockgen

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

### Docker images ###

.PHONY: ubuntu
ubuntu:
	@echo "===> Building okn-ubuntu Docker image <==="
	docker build -t okn-ubuntu -f build/images/Dockerfile.ubuntu .
