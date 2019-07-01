package cni

import (
	"context"
	"fmt"
	"net"
	cnipb "okn/pkg/apis/cni"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"google.golang.org/grpc"
)

type Action int

const (
	ActionAdd Action = iota
	ActionCheck
	ActionDel
)

const (
	OKNCniAddr = "/var/run/okn/cni.sock"
	OKNVersion = "1.0.0"
)

var withClient = rpcClient

func rpcClient(f func(client cnipb.CniClient) error) error {
	conn, err := grpc.Dial(
		OKNCniAddr,
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (conn net.Conn, e error) {
			return net.Dial("unix", addr)
		}),
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	return f(cnipb.NewCniClient(conn))
}

func (a Action) Request(arg *skel.CmdArgs) error {
	return withClient(func(client cnipb.CniClient) error {
		cmdRequest := cnipb.CniCmdRequestMessage{
			CniArgs: &cnipb.CniCmdArgsMessage{
				ContainerId:          arg.ContainerID,
				Ifname:               arg.IfName,
				Args:                 arg.Args,
				Netns:                arg.Netns,
				NetworkConfiguration: arg.StdinData,
				Path:                 arg.Path,
			},
			Version: OKNVersion,
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var resp *cnipb.CniCmdResponseMessage
		var err error

		switch a {
		case ActionAdd:
			resp, err = client.CmdAdd(ctx, &cmdRequest)
		case ActionCheck:
			resp, err = client.CmdCheck(ctx, &cmdRequest)
		case ActionDel:
			resp, err = client.CmdDel(ctx, &cmdRequest)
		}

		// The error here is only used to indicate issues during rpc but not cni procedure
		if err != nil {
			return &types.Error{
				Code: uint(cnipb.CniCmdResponseMessage_TRY_AGAIN_LATER),
				Msg:  err.Error(),
			}
		}
		return a.generateOutput(resp)
	})
}

func (a Action) generateOutput(resp *cnipb.CniCmdResponseMessage) error {
	if resp.StatusCode == cnipb.CniCmdResponseMessage_SUCCESS {
		fmt.Print(string(resp.CniResult))
		return nil
	} else {
		return &types.Error{
			Msg:  resp.ErrorMessage,
			Code: uint(resp.StatusCode),
		}
	}
}
