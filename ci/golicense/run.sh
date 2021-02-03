#!/usr/bin/env bash

set -eo pipefail

if [ "$#" -ne 2 ]; then
    echo "Invalid number of parameters. Usage: $0 <PATH TO ANTREA BINARIES DIRECTORY> <OUT PATH FOR REPORTS>"
    exit 1
fi

IMG=antrea/lichen
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BINARIES_DIR="$( cd "$1" >/dev/null 2>&1 && pwd )"
REPORTS_DIR="$( cd "$2" >/dev/null 2>&1 && pwd )"

failed_binaries=""

for f in "$1"/*; do
    [ -e "$f" ] || continue
    if [[ $f =~ antrea-agent || $f =~ antrea-controller || $f =~ antrea-cni || $f =~ antctl || $f =~ antrea-octant-plugin ]]; then
        base=$(basename $f)
        echo "Processing $base"
        echo "****************"
        docker run --rm -v $THIS_DIR:/conf -v "$BINARIES_DIR":/bins $IMG --config=/conf/conf.yml /bins/$base | tee "$REPORTS_DIR/$base.deps.txt" || failed_binaries="$failed_binaries $base"
        echo "****************"
    fi
done

echo "Merging all files as $REPORTS_DIR/ALL.deps.txt"
echo "****************"
# The 'grep -v' is to remove the dependency of the Antrea Octant plugin to Antrea
cat "$REPORTS_DIR"/*.deps.txt | grep -v "\.\./\.\." | uniq | tee "$REPORTS_DIR/ALL.deps.txt"
echo "****************"

if [ -z "$failed_binaries" ]; then
  echo "#### SUCCESS ####"
else
  echo "#### FAILURE ####"
  echo "Scan failed for the following binaries: $failed_binaries"
  echo "Check $REPORTS_DIR/ALL.deps.txt for more info"
fi
