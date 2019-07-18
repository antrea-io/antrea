BUILD_DIR = $(PWD)/BUILD
GO_FILES=`find . -name "*.go" -type f`

export BUILD_DIR

all: build_dir cmd build

build_dir:
	mkdir -p $(BUILD_DIR)

cmd: build_dir
	@$(MAKE) -C cmd

build: build_dir
	@$(MAKE) -C build

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: fmt
fmt:
	gofmt -s -l -w $(GO_FILES)

.PHONY: lint
lint:
	golint $$(go list ./...)

.PHONY: test test-fmt test-unit
test: test-fmt test-unit

test-fmt:
	@test -z "$$(gofmt -s -l -d $(GO_FILES) | tee /dev/stderr)"

test-unit:
	go test -cover $$(go list ./... | grep -v "okn/pkg/ovs/ovsconfig")
