// Copyright 2019 Antrea Authors
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

	"github.com/vmware-tanzu/antrea/pkg/cni"
	"github.com/vmware-tanzu/antrea/pkg/log"
	"github.com/vmware-tanzu/antrea/pkg/version"

	"github.com/containernetworking/cni/pkg/skel"
	cni_version "github.com/containernetworking/cni/pkg/version"
)

func init() {
	log.InitKlog()
}

func main() {
	skel.PluginMain(
		cni.ActionAdd.Request,
		cni.ActionCheck.Request,
		cni.ActionDel.Request,
		cni_version.All,
		fmt.Sprintf("Antrea CNI %s", version.GetFullVersionWithRuntimeInfo()),
	)
}
