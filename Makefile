BUILD_DIR = $(PWD)/BUILD

export BUILD_DIR

all: build_dir cmd

build_dir:
	mkdir -p $(BUILD_DIR)

cmd: build_dir
	@$(MAKE) -C cmd

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
