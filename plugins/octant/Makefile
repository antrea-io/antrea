SHELL                            := /bin/bash
GO                               ?= go
LDFLAGS                          :=
GOFLAGS                          :=
BINDIR                           ?= $(CURDIR)/bin
ANTREA_OCTANT_PLUGIN_BINARY_NAME ?= antrea-octant-plugin


# We disable cgo to avoid the following issue when building
# github.com/containers/storage (an indirect dependency of Octant).
# The code that requires cgo is not actually used by Octant / us, so there is no
# issue associated with disabling cgo.
# # pkg-config --cflags  -- devmapper
# Package devmapper was not found in the pkg-config search path.
# Perhaps you should add the directory containing `devmapper.pc'
# to the PKG_CONFIG_PATH environment variable
# No package 'devmapper' found
# pkg-config: exit status 1

.PHONY: antrea-octant-plugin
antrea-octant-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux CGO_ENABLED=0 $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' antrea.io/antrea/plugins/octant/cmd/antrea-octant-plugin

.PHONY: octant-plugins
octant-plugins:
	@mkdir -p $(BINDIR)
	GOOS=linux CGO_ENABLED=0 $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' antrea.io/antrea/plugins/octant/cmd/...

.PHONY: antrea-octant-plugin-release
antrea-octant-plugin-release:
	@CGO_ENABLED=0 $(GO) build -o $(BINDIR)/$(ANTREA_OCTANT_PLUGIN_BINARY_NAME) $(GOFLAGS) -ldflags '$(LDFLAGS)'  antrea.io/antrea/plugins/octant/cmd/antrea-octant-plugin
