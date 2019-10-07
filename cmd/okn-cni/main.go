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
