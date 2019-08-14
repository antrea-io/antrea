package ipam

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types/current"
	"okn/pkg/apis/cni"
)

var ipamDrivers map[string]IPAMDriver

type IPAMDriver interface {
	Add(args *invoke.Args, networkConfig []byte) (*current.Result, error)
	Del(args *invoke.Args, networkConfig []byte) error
	Check(args *invoke.Args, networkConfig []byte) error
}

func RegisterIPAMDriver(ipamType string, ipamDriver IPAMDriver) error {
	if ipamDrivers == nil {
		ipamDrivers = make(map[string]IPAMDriver)
	}
	if _, existed := ipamDrivers[ipamType]; existed {
		return fmt.Errorf("Already registered IPAM with type %s", ipamType)
	}
	ipamDrivers[ipamType] = ipamDriver
	return nil
}

func argsFromEnv(cniArgs *cnimsg.CniCmdArgsMessage) *invoke.Args {
	return &invoke.Args{
		ContainerID: cniArgs.ContainerId,
		NetNS:       cniArgs.Netns,
		IfName:      cniArgs.Ifname,
		Path:        cniArgs.Path,
	}
}

func ExecIPAMAdd(cniArgs *cnimsg.CniCmdArgsMessage, ipamType string) (*current.Result, error) {
	args := argsFromEnv(cniArgs)
	driver := ipamDrivers[ipamType]
	return driver.Add(args, cniArgs.NetworkConfiguration)
}

func ExecIPAMDelete(cniArgs *cnimsg.CniCmdArgsMessage, ipamType string) error {
	args := argsFromEnv(cniArgs)
	driver := ipamDrivers[ipamType]
	return driver.Del(args, cniArgs.NetworkConfiguration)
}

func ExecIPAMCheck(cniArgs *cnimsg.CniCmdArgsMessage, ipamType string) error {
	args := argsFromEnv(cniArgs)
	driver := ipamDrivers[ipamType]
	return driver.Check(args, cniArgs.NetworkConfiguration)
}

func IsIPAMTypeValid(ipamType string) bool {
	_, valid := ipamDrivers[ipamType]
	return valid
}
