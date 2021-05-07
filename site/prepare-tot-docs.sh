#!/usr/bin/env bash

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function reset_docs_main {
  printf "Resetting main docs directory\n"
  rm -rf *
}

function copy_root_markdowns_to_docs_main {
  # Copy README.md and other root markdown docs used in site documentation
  printf "Copying root markdown docs and fixing up relative links\n"

  ROOT_DOCS=( README CONTRIBUTING CODE_OF_CONDUCT ROADMAP ADOPTERS )

  for doc in "${ROOT_DOCS[@]}"; do
      cp -f ../../../${doc}.md .
      sed -i.bak 's/\([("]\)\(\/\)\{0,1\}docs\//\1/g' ${doc}.md
      rm -f ${doc}.md.bak
  done

  # Fix links to adopters' logos
  sed -i.bak 's/^<img\(.*\)src="assets\//<img\1src="..\/assets\//' ADOPTERS.md
}

function copy_markdowns_to_docs_main {
  printf "Copying markdown docs\n"

  cp -rf ../../../docs/* .

  printf "Using symbolic links for assets\n"

  rm -rf assets
  ln -s ../../../docs/assets assets
  rm -rf cookbooks/multus/assets
  ln -s ../../../../../docs/cookbooks/multus/assets cookbooks/multus/assets

  printf "Fixing up HTML img tags\n"

  # The Antrea markdown files sometimes use HTML tags for images in order to
  # set a fixed size for them. We still need jekyll / redcarpet to fix the links
  # for us, so we convert the HTML tag to standard markdown (and lose the size
  # information). This is quite brittle but it works for now.
  for doc in $(find "$PWD" -type f -name "*.md"); do
      sed -i.bak 's/<img src="\(.*\)" \(.*\) alt="\(.*\)">/![\3](\1)/' ${doc}
      rm -f ${doc}.bak
  done

  printf "Removing absolute links to non-docs\n"
  for doc in $(find "$PWD" -type f -name "*.md"); do
      sed -i.bak 's/\[\(.*\)\](\/\(.*\))/\1 (`\/\2`)/' ${doc}
      rm -f ${doc}.bak
  done

  printf "Removing '..' from links to root docs\n"
  for doc in $(find "$PWD" -type f -name "*.md"); do
      sed -i.bak 's/\[\(.*\)\](\.\.\/\(.*\)\([README\|CONTRIBUTING\|CODE_OF_CONDUCT\|CHANGELOG\|ROADMAP\|ADOPTERS]\)\.md/[\1](\2\3.md/' ${doc}
      rm -f ${doc}.bak
  done

  printf "Changing links to VERSION file\n"
  for doc in $(find "$PWD" -type f -name "*.md"); do
      sed -i.bak 's/\[\(.*\)\](.*VERSION)/[\1](https:\/\/github.com\/vmware-tanzu\/antrea\/blob\/master\/VERSION)/' ${doc}
      rm -f ${doc}.bak
  done
}

pushd $THIS_DIR/docs/main

reset_docs_main
copy_markdowns_to_docs_main
# This is done after copy_markdowns_to_docs_main, to overwrite changes made by
# that function
copy_root_markdowns_to_docs_main

printf "Updating links to ci/README.md\n"
for doc in $(find "$PWD" -type f -name "*.md"); do
    sed -i.bak 's/(ci\/README\.md)/(https:\/\/github.com\/vmware-tanzu\/antrea\/blob\/master\/ci\/README.md)/' ${doc}
    rm -f ${doc}.bak
done

printf "Changing links to LICENSE file\n"
for doc in $(find "$PWD" -type f -name "*.md"); do
    sed -i.bak 's/\[\(.*\)\](LICENSE)/[\1](https:\/\/raw.githubusercontent.com\/vmware-tanzu\/antrea\/master\/LICENSE)/' ${doc}
    rm -f ${doc}.bak
done

# For some reason (list formatting I think), jekyll / redcarpet does not like
# the "toc" comments
printf "Fixing up HTML comments\n"
for doc in $(find "$PWD" -type f -name "*.md"); do
    sed -i.bak '/<!-- toc -->/d' ${doc}
    rm -f ${doc}.bak
    sed -i.bak '/<!-- \/toc -->/d' ${doc}
    rm -f ${doc}.bak
done

printf "Copying API reference\n"
cp -f ../../api-reference.md .

printf "Adding CHANGELOG link\n"
echo "Please refer to the CHANGELOG on [Github](https://github.com/vmware-tanzu/antrea/tree/main/CHANGELOG)" > CHANGELOG.md

popd

printf "complete\n"
