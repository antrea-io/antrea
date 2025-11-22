USERID  := $(shell id -u)
GRPID   := $(shell id -g)

VERSION := $(shell head -n 1 ../../VERSION | cut -c 2-)

# SED_VERSION_REGEX:
# Safely replaces the placeholder version string "0.0.0" with $(VERSION) in README files.
# The regex is designed to avoid matching IP addresses such as "0.0.0.0", where the same "0.0.0" sequence appears as
# part of an IPv4 address. It enforces two boundary conditions:
#   1. The preceding character must be either:
#         - the start of the line (^), or
#         - a character that is NOT a digit and NOT a dot ([^0-9.])
#      This prevents matching cases like "10.0.0" or the "0.0.0" inside "0.0.0.0".
#
#   2. The trailing character must be either:
#         - a character that is NOT a digit and NOT a dot ([^0-9.]), or
#         - the end of the line ($$)
#      This avoids matching "0.0.0.123" or "0.0.0.0".
#
# Capture groups (\1 and \2) preserve the original prefix/suffix characters around "0.0.0".
# Note: Backslashes are doubled (\\.) because Makefile eats one layer of escaping.
SED_VERSION_REGEX = s/(^|[^0-9.])0\\.0\\.0([^0-9.]|$$)/\1$(VERSION)\2/g

SED_BADGE_FIX_REGEX = s/-dev-informational/--dev-informational/g

.PHONY: helm-docs
helm-docs:
	docker run --rm --volume "$(CURDIR):/helm-docs" --user=$(USERID):$(GRPID) jnorwood/helm-docs:v1.14.2
	sed -i.bak -E "$(SED_VERSION_REGEX)" antrea/README.md # replace version placeholder
	sed -i.bak "$(SED_BADGE_FIX_REGEX)" antrea/README.md # fix img.shields.io badge URLs
	sed -i.bak -E "$(SED_VERSION_REGEX)" flow-aggregator/README.md # replace version placeholder
	sed -i.bak "$(SED_BADGE_FIX_REGEX)" flow-aggregator/README.md # fix img.shields.io badge URLs
	sed -i.bak -E "$(SED_VERSION_REGEX)" antrea-windows/README.md # replace version placeholder
	sed -i.bak "$(SED_BADGE_FIX_REGEX)" antrea-windows/README.md # fix img.shields.io badge URLs
