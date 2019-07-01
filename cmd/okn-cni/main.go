package main

import (
	"okn/pkg/cni"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

func main() {
	skel.PluginMain(
		cni.ActionAdd.Request,
		cni.ActionCheck.Request,
		cni.ActionDel.Request,
		version.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1"),
		"OKN CNI",
	)
}
