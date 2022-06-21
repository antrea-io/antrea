USERID  := $(shell id -u)
GRPID   := $(shell id -g)

.PHONY: helm-docs
helm-docs:
	docker run --rm --volume "$(CURDIR):/helm-docs" --user=$(USERID):$(GRPID) jnorwood/helm-docs:v1.7.0
