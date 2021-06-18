#!/usr/bin/env bash
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR/docs/main

# Copy README.md and other root markdown docs used in site documentation
printf "Copying root markdown docs and fixing up relative links..."

ROOT_DOCS=( README CONTRIBUTING CODE_OF_CONDUCT CHANGELOG ROADMAP )

for doc in "${ROOT_DOCS[@]}"; do
    cp -f ../../../${doc}.md .
    sed -i.bak '/https:\/\/kubernetes.io\/docs\//! s/\/docs\///g' ${doc}.md
    sed -i.bak '/https:\/\/kubernetes.io\/docs\//! s/docs\///g' ${doc}.md
    rm -f ${doc}.md.bak
done

# Copy VERSION into site documentation
printf "Copying VERSION file into site root and converting to MD..."

VERSION=( VERSION )

for doc in "${VERSION[@]}"; do
    cp -f ../../../${doc} ../../${doc}
done

# Create symbolic links to docs files and subdirectories.
printf "Creating symbolic links for files and subdirectories in /docs..."

for f in ../../../docs/*; do
  printf "symbolically linking $f... \n"
  ln -s ${f}
done

popd
printf "complete"
