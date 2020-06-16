SHELL  := /bin/bash
GO     ?= go
BINDIR ?= $(CURDIR)/bin

.PHONY: antrea-octant-plugin
antrea-octant-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware-tanzu/antrea/plugins/octant/cmd/antrea-octant-plugin

.PHONY: octant-plugins
octant-plugins:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware-tanzu/antrea/plugins/octant/cmd/...
