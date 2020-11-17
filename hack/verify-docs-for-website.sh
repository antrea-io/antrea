#!/usr/bin/env bash

# Copyright 2020 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

function echoerr {
    >&2 echo "$@"
}

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR/.. > /dev/null

rc=0

function check_one_file {
    echoerr "*** CHECKING $1"
    if grep "](/docs" $1; then
        echoerr "All markdown links to files under docs/ should be relative"
        rc=1
    fi
    if grep "](/.*md" $1; then
        echoerr "All markdown links to other markdown documents should be relative"
        rc=1
    fi
    if grep "<img.*src=\"/docs" $1; then
        echoerr "All <img> tags for images under docs/ should use relative links"
        rc=1
    fi
}

for f in $(find docs -name '*.md'); do
    check_one_file $f
done
for f in $(find . -maxdepth 1 -name '*.md'); do
    check_one_file $f
done

popd > /dev/null

exit $rc
