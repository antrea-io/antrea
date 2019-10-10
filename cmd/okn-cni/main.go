// Copyright 2019 OKN Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"

	"okn/pkg/cni"
	"okn/pkg/version"

	"github.com/containernetworking/cni/pkg/skel"
	cni_version "github.com/containernetworking/cni/pkg/version"
)

func main() {
	skel.PluginMain(
		cni.ActionAdd.Request,
		cni.ActionCheck.Request,
		cni.ActionDel.Request,
		cni_version.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1"),
		fmt.Sprintf("OKN CNI %s", version.GetFullVersionWithRuntimeInfo()),
	)
}
