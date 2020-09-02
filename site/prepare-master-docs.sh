#!/usr/bin/env bash

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function reset_docs_master {
  printf "Resetting master docs directory\n"
  rm -f *
}

function copy_root_markdowns_to_docs_master {
  # Copy README.md and other root markdown docs used in site documentation
  printf "Copying root markdown docs and fixing up relative links\n"

  ROOT_DOCS=( README CONTRIBUTING CODE_OF_CONDUCT CHANGELOG ROADMAP )

  for doc in "${ROOT_DOCS[@]}"; do
      cp -f ../../../${doc}.md .
      sed -i.bak 's/\([("]\)\(\/\)\{0,1\}docs\//\1/g' ${doc}.md
      rm -f ${doc}.md.bak
  done
}

function create_symbolic_links_to_root_docs {
  # Create symbolic links to docs files and subdirectories.
  printf "Creating symbolic links for files and subdirectories in /docs...\n"

  for f in ../../../docs/*; do
    printf "symbolically linking $f... \n"
    ln -s ${f}
  done
}

pushd $THIS_DIR/docs/master

reset_docs_master
copy_root_markdowns_to_docs_master
create_symbolic_links_to_root_docs

popd

printf "complete\n"