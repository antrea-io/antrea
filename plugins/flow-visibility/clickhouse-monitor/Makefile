SHELL                            := /bin/bash
GO                               ?= go
LDFLAGS                          :=
GOFLAGS                          :=
BINDIR                           ?= $(CURDIR)/bin

.PHONY: clickhouse-monitor-plugin
clickhouse-monitor-plugin:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) $(GOFLAGS) -ldflags '$(LDFLAGS)' antrea.io/antrea/plugins/flow-visibility/clickhouse-monitor
