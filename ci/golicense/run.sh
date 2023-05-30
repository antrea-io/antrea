#!/usr/bin/env bash
# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -eo pipefail

if [ "$#" -ne 2 ]; then
    echo "Invalid number of parameters. Usage: $0 <PATH TO ANTREA BINARIES DIRECTORY> <OUT PATH FOR REPORTS>"
    exit 1
fi

IMG=antrea/lichen:v0.1.7
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BINARIES_DIR="$( cd "$1" >/dev/null 2>&1 && pwd )"
REPORTS_DIR="$( cd "$2" >/dev/null 2>&1 && pwd )"

failed_binaries=""

for f in "$1"/*; do
    [ -e "$f" ] || continue
    if [[ $f =~ antrea-agent || $f =~ antrea-controller || $f =~ antrea-cni || $f =~ antctl ]]; then
        base=$(basename $f)
        echo "Processing $base"
        echo "****************"
        docker run --rm -v $THIS_DIR:/conf -v "$BINARIES_DIR":/bins $IMG --config=/conf/conf.yml /bins/$base | tee "$REPORTS_DIR/$base.deps.txt" || failed_binaries="$failed_binaries $base"
        echo "****************"
    fi
done

echo "Merging all files as $REPORTS_DIR/ALL.deps.txt"
echo "****************"
cat "$REPORTS_DIR"/*.deps.txt | sort | uniq | tee "$REPORTS_DIR/ALL.deps.txt"
echo "****************"

rc=
if [ -z "$failed_binaries" ]; then
  echo "#### SUCCESS ####"
  rc=0
else
  echo "#### FAILURE ####"
  echo "Scan failed for the following binaries: $failed_binaries"
  echo "Check $REPORTS_DIR/ALL.deps.txt for more info"
  rc=1
fi
exit $rc
