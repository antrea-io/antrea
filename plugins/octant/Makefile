SHELL                            := /bin/bash
GO                               ?= go
LDFLAGS                          :=
GOFLAGS                          :=
BINDIR                           ?= $(CURDIR)/bin
ANTREA_OCTANT_PLUGIN_BINARY_NAME ?= antrea-octant-plugin

.PHONY: antrea-octant-plugin
antrea-octant-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' antrea.io/antrea/plugins/octant/cmd/antrea-octant-plugin

.PHONY: octant-plugins
octant-plugins:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' antrea.io/antrea/plugins/octant/cmd/...

.PHONY: antrea-octant-plugin-release
antrea-octant-plugin-release:
	@$(GO) build -o $(BINDIR)/$(ANTREA_OCTANT_PLUGIN_BINARY_NAME) $(GOFLAGS) -ldflags '$(LDFLAGS)'  antrea.io/antrea/plugins/octant/cmd/antrea-octant-plugin
