#!/usr/bin/env bash

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# docs will be frozen to version in /VERSION unless VERSION is defined.
FILE_VERSION="$( cat $THIS_DIR/../VERSION )"
VERSION="${VERSION:-$FILE_VERSION}"

function prereqs {
  if ! command -v yq &> /dev/null; then
    echo "yq not found, please install it"
    exit 1
  fi

  if ! command -v grep &> /dev/null; then
    echo "grep not found, please install it"
    exit 1
  fi

  # Frozen docs are frozen from the ToT docs. Update them.
  ./prepare-tot-docs.sh
}

function copy_main_docs_to_versioned_docs {
  printf "Copying main site/docs to docs/$VERSION (following symbolic links to freeze changes)"
  rm -rf docs/$VERSION
  cp -RL docs/main docs/$VERSION
}

function add_toc_nav_mapping {
  printf "Adding TOC mapping for $VERSION\n"

  # note the name does not include the .yml (it is implied by Jekyll)
  VERSION_TOC_NAME="$( echo $VERSION | sed 's/^v\(.*\)/\1/' | tr . - )-toc"

  # .yml file extension used for toc yaml content
  cp -f "${THIS_DIR}/_data/main-toc.yml" "${THIS_DIR}/_data/${VERSION_TOC_NAME}.yml"
  
  printf "Created ${THIS_DIR}/_data/${VERSION_TOC_NAME}.yml from ${THIS_DIR}/_data/main-toc.yml\n"

  printf "Adding TOC entry for $VERSION ${THIS_DIR}/_data/toc-mapping.yml\n"
  yq w -i "${THIS_DIR}/_data/toc-mapping.yml" \"$VERSION\" "$VERSION_TOC_NAME"
}

function add_defaults_scope_and_values_for_new_docs_version {
  # Only add defaults item if the version does not already have one
  # so that this remains idempotent.

  if ! yq r _config.yml "defaults.(values.layout==docs)" | grep $VERSION; then
    printf "Adding default page scope for $VERSION\n"

    version_page_scope=$(mktemp /tmp/freeze-version-page-scope.XXXXXX)
    cat <<EOF > $version_page_scope
defaults:
- scope:
    path: docs/$VERSION
  values:
    version: $VERSION
    gh: https://github.com/antrea-io/antrea/tree/$VERSION
    layout: "docs"
EOF
    yq m -a=append -i "${THIS_DIR}/_config.yml" "$version_page_scope"
    rm -f "$version_page_scope"
  fi
}

function extract_versions {
  # Get current array of versions
  VERSIONS=($(yq r _config.yml versions | cut -d' ' -f2))

  # Remove main (should be first in list) so we can sort all versions
  VERSIONS=( "${VERSIONS[@]:1}" )

  # Add new version
  VERSIONS=( "${VERSION}" "${VERSIONS[@]}" )

  # Sort versions using "version sort"
  IFS="|$IFS"; SORTED_VERSIONS=( $(sort -Vr <<<"${VERSIONS[*]}") ); IFS="${IFS:1}"
    
  # Re-insert main at head of list.
  SORTED_VERSIONS=( "main" "${VERSIONS[@]}" )
}

function add_version_to_site_versions_array {
    if ! yq r _config.yml versions | grep $VERSION; then
      # Generate YAML snippet for an ovewrite merge back into _config.yml
      VERSIONS_YAML=$(printf 'versions:\n'; printf '  - %s\n' "${SORTED_VERSIONS[@]}")

      appended_versions=$(mktemp /tmp/freeze-version-config-versions.XXXXXX)
      echo "$VERSIONS_YAML" > "$appended_versions"

      # Merge versions back into _config.yml
      yq m -x -i "${THIS_DIR}/_config.yml" "$appended_versions"
      rm -f "$appended_versions"
    fi
}

function set_latest_version {
  # Set latest version to highest version number.
  LATEST_VERSION="${SORTED_VERSIONS[1]}"
  printf "Setting default doc version to latest non-main version: $LATEST_VERSION\n"
  yq w -i $THIS_DIR/_config.yml "latest" "$LATEST_VERSION"
}

prereqs
copy_main_docs_to_versioned_docs
add_toc_nav_mapping
add_defaults_scope_and_values_for_new_docs_version
extract_versions
add_version_to_site_versions_array
set_latest_version

printf "complete\n"
