SHELL              := /bin/bash
GO                 ?= go
BINDIR             ?= $(CURDIR)/bin

.PHONY: antrea-octant-plugin
antrea-octant-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware-tanzu/antrea/plugins/cmd/antrea-octant-plugin

.PHONY: antrea-traceflow-octant-plugin
antrea-traceflow-octant-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware-tanzu/antrea/plugins/cmd/antrea-traceflow-octant-plugin

.PHONY: plugins
plugins:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware-tanzu/antrea/plugins/cmd/...