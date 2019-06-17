BUILD_DIR ?= $(PWD)
GOPATH = ${BUILD_DIR}/go
GOBIN = ${GOPATH}/bin
GOSRC = ${GOPATH}/src
OKN_PKG_DIR = ${GOSRC}/okn
MAKEFILE_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

GCFLAGS ?= ""
LDFLAGS ?= ""

export GOPATH
export GOBIN

all: build_env cni

build_env:
	mkdir -p $(GOBIN) $(GOSRC)
	rm -f $(OKN_PKG_DIR)
	ln -s $(MAKEFILE_DIR)/.. $(OKN_PKG_DIR)

cni: build_env
	go install -gcflags "${GCFLAGS}" -ldflags "${LDFLAGS}" okn/cmd/okn-cni

.PHONY: clean
clean:
	rm -rf $(GOPATH)
