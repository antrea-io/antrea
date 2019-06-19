package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

const cniInfoString = "OKN CNI"

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, cniInfoString)
}

func cmdAdd(args *skel.CmdArgs) error {
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	return nil
}
