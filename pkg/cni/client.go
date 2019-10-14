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

package cni

import (
	"context"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"google.golang.org/grpc"

	cnipb "okn/pkg/apis/cni"
)

type Action int

const (
	ActionAdd Action = iota
	ActionCheck
	ActionDel
)

const (
	OKNCNISocketAddr = "/var/run/okn/cni.sock"
	OKNVersion       = "1.0.0"
)

// To allow for testing with a fake client.
var withClient = rpcClient

func rpcClient(f func(client cnipb.CniClient) error) error {
	conn, err := grpc.Dial(
		OKNCNISocketAddr,
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

// Request requests the okn-agent to execute the specified action with the provided arguments via RPC.
// If successful, it outputs the result to stdout and returns nil. Otherwise types.Error is returned.
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

		// The error indicates issues during rpc.
		if err != nil {
			return &types.Error{
				Code: uint(cnipb.CniCmdResponseMessage_TRY_AGAIN_LATER),
				Msg:  err.Error(),
			}
		}
		// The error indicates issues during cni procedure.
		if resp.StatusCode != cnipb.CniCmdResponseMessage_SUCCESS {
			return &types.Error{
				Code: uint(resp.StatusCode),
				Msg:  resp.ErrorMessage,
			}
		}
		fmt.Print(string(resp.CniResult))
		return nil
	})
}
