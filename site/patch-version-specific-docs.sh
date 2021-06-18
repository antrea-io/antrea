#!/usr/bin/env bash

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR/..

VERSION=${1:-$(cat VERSION)}
FILES=(docs README.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md ROADMAP.md VERSION)

for f in "${FILES[@]}"; do
    mv $f $f.temp
    git checkout tags/$VERSION -- $f
done

pushd $THIS_DIR

markdownlint --fix -c .markdownlint.json ../docs/**/*.md
markdownlint --fix -c .markdownlint.json ../*.md

./prepare-main-docs.sh
./freeze-version-docs.sh

popd

for f in "${FILES[@]}"; do
    rm -rf $f
    mv $f.temp $f
done

popd


