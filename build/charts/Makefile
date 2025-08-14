USERID  := $(shell id -u)
GRPID   := $(shell id -g)

VERSION := $(shell head -n 1 ../../VERSION | cut -c 2-)

.PHONY: helm-docs
helm-docs:
	docker run --rm --volume "$(CURDIR):/helm-docs" --user=$(USERID):$(GRPID) jnorwood/helm-docs:v1.14.2
	sed -i.bak "s/0\.0\.0\.0:10352/placeholder/g" antrea/README.md # avoid "0.0.0" is replaced by $VERSION
	sed -i.bak "s/0\.0\.0/$(VERSION)/g" antrea/README.md # replace version placeholder
	sed -i.bak "s/placeholder/0\.0\.0\.0:10352/g" antrea/README.md
	sed -i.bak "s/-dev-informational/--dev-informational/g" antrea/README.md # fix img.shields.io badge URLs
	sed -i.bak "s/0\.0\.0/$(VERSION)/g" flow-aggregator/README.md # replace version placeholder
	sed -i.bak "s/0\.0\.0/$(VERSION)/g" antrea-windows/README.md # replace version placeholder
	sed -i.bak "s/-dev-informational/--dev-informational/g" flow-aggregator/README.md # fix img.shields.io badge URLs