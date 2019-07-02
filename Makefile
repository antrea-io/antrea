BUILD_DIR = $(PWD)/BUILD

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
