#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
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

set +e

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_DIR=$(dirname "$THIS_DIR")

pushd "$THIS_DIR" >/dev/null || exit

MOD_FILE="$PROJECT_DIR/go.mod"
SUM_FILE="$PROJECT_DIR/go.sum"
TMP_DIR="$THIS_DIR/.tmp.tidy-check"
TMP_MOD_FILE="$TMP_DIR/go.mod"
TMP_SUM_FILE="$TMP_DIR/go.sum"
TARGET_GO_VERSION="1.13"
TARGET_GO_VERSION_PATTERN="go$TARGET_GO_VERSION.*"

# if Go environment variable is set, use it as it is, otherwise default to "go"
: "${GO:=go}"

function echoerr {
  >&2 echo "$@"
}

function general_help {
  echoerr "Please run the following command to generate a new go.mod & go.sum:"
  if [ -n "$GO" ] && [[ "$($GO version|awk '{print $3}')" == $TARGET_GO_VERSION_PATTERN ]]; then
    echoerr "  \$ make tidy"
  else
    echoerr "  \$ make docker-tidy"
  fi
}

function precheck {
  if [ ! -r "$MOD_FILE" ]; then
    echoerr "no go.mod found"
    general_help
    exit 1
  fi
  if [ ! -r "$SUM_FILE" ]; then
    echoerr "no go.sum found"
    general_help
    exit 1
  fi
  mkdir -p "$TMP_DIR"
}

function tidy {
  cp "$MOD_FILE" "$TMP_MOD_FILE"
  mv "$SUM_FILE" "$TMP_SUM_FILE"

  if [ -n "$GO" ] && [[ "$($GO version|awk '{print $3}')" == $TARGET_GO_VERSION_PATTERN ]]; then
    /usr/bin/env bash -c "$GO mod tidy" >>/dev/null 2>&1
  else
    docker run --rm -u "$(id -u):$(id -g)" \
      -e "GOCACHE=/tmp/gocache" \
      -e "GOPATH=/tmp/gopath" \
      -w /usr/src/github.com/vmware-tanzu/antrea \
      -v "$PROJECT_DIR:/usr/src/github.com/vmware-tanzu/antrea" \
      golang:$TARGET_GO_VERSION bash -c "go mod tidy >> /dev/null 2>&1"
  fi
}

function clean {
  mv "$TMP_MOD_FILE" "$MOD_FILE"
  mv "$TMP_SUM_FILE" "$SUM_FILE"
  rm -fr "$TMP_DIR"
}

function failed {
  echoerr "'go mod tidy' failed, there are errors in dependencies"
  general_help
  clean
  exit 1
}

function check {
  MOD_DIFF=$(diff "$MOD_FILE" "$TMP_MOD_FILE")
  SUM_DIFF=$(diff "$SUM_FILE" "$TMP_SUM_FILE")
  if [ -n "$MOD_DIFF" ] || [ -n "$SUM_DIFF" ]; then
    echoerr "dependencies are not tidy"
    general_help
    clean
    exit 1
  fi
  clean
}

precheck
if tidy; then
  check
else
  failed
fi

popd >/dev/null || exit
