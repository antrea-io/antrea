#!/usr/bin/env bash

# Copyright 2023 Antrea Authors
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

# Generate mocks for testing with mockgen.
function generate_mocks {
  # Command mockgen does not automatically replace variable YEAR with current year
  # like others do, e.g. client-gen.
  current_year=$(date +"%Y")
  sed -i "s/YEAR/${current_year}/g" hack/boilerplate/license_header.raw.txt
  for target in "${MOCKGEN_TARGETS[@]}"; do
    read -r src_package interfaces dst_package_name dst_file_name <<<"${target}"
    src_package_name=$(basename "${src_package}")
    # Generate mocks in the same package as src if dst_file_name is ".", otherwise create a sub package.
    if [[ "${dst_package_name}" == "." ]]; then
      package="${src_package_name}"
      if [ -n "${dst_file_name}" ]; then
        destination="${src_package}/${dst_file_name}"
      else
        destination="${src_package}/mock_${src_package_name}_test.go"
      fi
    else
      package="${dst_package_name}"
      if [ -n "${dst_file_name}" ]; then
        destination="${src_package}/${dst_package_name}/${dst_file_name}"
      else
        destination="${src_package}/${dst_package_name}/mock_${src_package_name}.go"
      fi
    fi
    $GOPATH/bin/mockgen \
      -copyright_file hack/boilerplate/license_header.raw.txt \
      -destination "${destination}" \
      -package "${package}" \
      "${ANTREA_PKG}/${src_package}" "${interfaces}"
  done
  git checkout HEAD -- hack/boilerplate/license_header.raw.txt
}

function reset_year_change {
  set +x
  echo "=== Start resetting changes introduced by YEAR ==="
  # The call to 'tac' ensures that we cannot have concurrent git processes, by
  # waiting for the call to 'git diff  --numstat' to complete before iterating
  # over the files and calling 'git diff ${file}'.
  git diff  --numstat | awk '$1 == "1" && $2 == "1" {print $3}' | tac | while read file; do
    if [[ "$(git diff ${file})" == *"-// Copyright "*" Antrea Authors"* ]]; then
      git checkout HEAD -- "${file}"
      echo "=== ${file} is reset ==="
    fi
  done
}
