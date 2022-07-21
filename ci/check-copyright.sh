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

function echoerr {
    >&2 echo "$@"
}

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $THIS_DIR/.. > /dev/null

make add-copyright
go_files=`find . -type f -name "*.go"`
sh_files=`find . -type f -name "*.sh"`
docker_files=`find . -type f -name "Dockerfile*"`
diff="$(git status --porcelain $go_files $sh_files $docker_files)"

if [ ! -z "$diff" ]; then
    echoerr "The copyrights of some files are not generated"
    echoerr "You can regenerate them with 'make add-copyright' and commit the changes"
    exit 1
fi
