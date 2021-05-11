# check if git is available
ifeq ($(shell which git),)
        $(warning git is not available, binaries will not include git SHA)
        GIT_SHA :=
        GIT_TREE_STATE :=
        GIT_TAG :=
        VERSION_SUFFIX := unknown
else
        GIT_SHA := $(shell git rev-parse --short HEAD)
        # Tree state is "dirty" if there are uncommitted changes, untracked files are ignored
        GIT_TREE_STATE := $(shell test -n "`git status --porcelain --untracked-files=no`" && echo "dirty" || echo "clean")
        # Empty string if we are not building a tag
        GIT_TAG := $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
        ifeq ($(GIT_TREE_STATE),dirty)
                VERSION_SUFFIX := $(GIT_SHA).dirty
        else
                VERSION_SUFFIX := $(GIT_SHA)
        endif
endif

# if building a tag or VERSION is set, set RELEASE_STATUS to "released"
ifdef VERSION
        RELEASE_STATUS := released
else ifneq ($(GIT_TAG),)
        RELEASE_STATUS := released
else
        RELEASE_STATUS := unreleased
endif

ifndef VERSION
        VERSION := $(shell head -n 1 VERSION)
        DOCKER_IMG_VERSION := $(VERSION)-$(VERSION_SUFFIX)
else
        DOCKER_IMG_VERSION := $(VERSION)
endif

VERSION_LDFLAGS = -X antrea.io/antrea/pkg/version.Version=$(VERSION)
VERSION_LDFLAGS += -X antrea.io/antrea/pkg/version.GitSHA=$(GIT_SHA)
VERSION_LDFLAGS += -X antrea.io/antrea/pkg/version.GitTreeState=$(GIT_TREE_STATE)
VERSION_LDFLAGS += -X antrea.io/antrea/pkg/version.ReleaseStatus=$(RELEASE_STATUS)

version-info:
	@echo "===> Version information <==="
	@echo "VERSION: $(VERSION)"
	@echo "GIT_SHA: $(GIT_SHA)"
	@echo "GIT_TREE_STATE: $(GIT_TREE_STATE)"
	@echo "RELEASE_STATUS: $(RELEASE_STATUS)"
	@echo "DOCKER_IMG_VERSION: $(DOCKER_IMG_VERSION)"
