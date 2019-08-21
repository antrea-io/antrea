# go options
GO          ?= go
LDFLAGS     :=
GOFLAGS     :=
BINDIR      ?= $(CURDIR)/bin
GO_FILES := $$(find . -name '*.go')

.PHONY: all
all: dev build

.PHONY: dev
dev:
	GOBIN=$(BINDIR) $(GO) install $(GOFLAGS) -ldflags '$(LDFLAGS)' okn/cmd/...

.PHONY: build
build:
	@$(MAKE) -C build

.PHONY: test
test: build
test: test-unit
test: test-fmt

.PHONY: test-unit
test-unit:
	@echo
	@echo "==> Running unit tests <=="
	$(GO) test -cover $$(go list ./... | grep -v "okn/pkg/[ovs/ovsconfig\|test]")

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
