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

command -v protoc >/dev/null 2>&1 || { echo "Protoc is not installed."; exit 1;}

# install latest version of protoc go plugin
go get -u github.com/golang/protobuf/protoc-gen-go

GOPATH=`go env GOPATH`
PATH=$PATH:$GOPATH/bin protoc --go_out=plugins=grpc:. ./pkg/apis/cni/v1beta1/cni.proto
