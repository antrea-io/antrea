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
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cnipb "okn/pkg/apis/cni"
)

type testClient struct {
	*testing.T
	add, check, del testClientBehave
}

type testClientBehave int

const (
	normal testClientBehave = iota
	badProtoVersion
	rpcError
)

func (c *testClient) CmdAdd(ctx context.Context, requestMsg *cnipb.CniCmdRequestMessage, opts ...grpc.CallOption) (*cnipb.CniCmdResponseMessage, error) {
	switch c.add {
	case normal:
		return &cnipb.CniCmdResponseMessage{
			StatusCode: cnipb.CniCmdResponseMessage_SUCCESS,
			CniResult:  []byte(`{"cniVersion": "0.3.1"}`),
		}, nil
	case badProtoVersion:
		return &cnipb.CniCmdResponseMessage{
			StatusCode:   cnipb.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION,
			ErrorMessage: "determined test error",
		}, nil
	case rpcError:
		return nil, status.Error(codes.Unknown, "determined test error")
	default:
		c.Fatalf("unexpected %+v action", c.add)
		c.FailNow()
		return nil, nil
	}
}

func (c *testClient) CmdCheck(ctx context.Context, requestMsg *cnipb.CniCmdRequestMessage, opts ...grpc.CallOption) (*cnipb.CniCmdResponseMessage, error) {
	switch c.check {
	case normal:
		return &cnipb.CniCmdResponseMessage{
			StatusCode: cnipb.CniCmdResponseMessage_SUCCESS,
			CniResult:  []byte(`{"cniVersion": "0.3.1"}`),
		}, nil
	case badProtoVersion:
		return &cnipb.CniCmdResponseMessage{
			StatusCode:   cnipb.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION,
			ErrorMessage: "determined test error",
		}, nil
	case rpcError:
		return nil, status.Error(codes.Unknown, "determined test error")
	default:
		c.Fatalf("unexpected %+v action", c.check)
		c.FailNow()
		return nil, nil
	}
}

func (c *testClient) CmdDel(ctx context.Context, requestMsg *cnipb.CniCmdRequestMessage, opts ...grpc.CallOption) (*cnipb.CniCmdResponseMessage, error) {
	switch c.del {
	case normal:
		return &cnipb.CniCmdResponseMessage{
			StatusCode: cnipb.CniCmdResponseMessage_SUCCESS,
			CniResult:  []byte(``),
		}, nil
	case badProtoVersion:
		return &cnipb.CniCmdResponseMessage{
			StatusCode:   cnipb.CniCmdResponseMessage_INCOMPATIBLE_PROTO_VERSION,
			ErrorMessage: "determined test error",
		}, nil
	case rpcError:
		return nil, status.Error(codes.Unknown, "determined test error")
	default:
		c.Fatalf("unexpected %+v action", c.del)
		c.FailNow()
		return nil, nil
	}
}

func enableTestClient(t *testing.T, add, check, del testClientBehave) {
	withClient = func(f func(client cnipb.CniClient) error) error {
		return f(&testClient{t, add, check, del})
	}
}

func disableTestClient() {
	withClient = rpcClient
}

func TestMismatchVersionAdd(t *testing.T) {
	enableTestClient(t, badProtoVersion, normal, normal)
	defer disableTestClient()

	stdinData := `{ "name":"okn-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionAdd.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	if err == nil {
		t.Fatal("request passed unexpected")
	}
}

func TestMismatchVersionDel(t *testing.T) {
	enableTestClient(t, normal, normal, badProtoVersion)
	defer disableTestClient()

	stdinData := `{ "name":"okn-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionDel.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	if err == nil {
		t.Fatal("request passed unexpected")
	}
}

func TestSuccessAdd(t *testing.T) {
	enableTestClient(t, normal, normal, normal)
	defer disableTestClient()

	stdinData := `{ "name":"okn-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionAdd.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	if err != nil {
		t.Fatal("request failed unexpected:", err)
	}
}

func TestSuccessDel(t *testing.T) {
	enableTestClient(t, normal, normal, normal)
	defer disableTestClient()

	stdinData := `{ "name":"okn-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionDel.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	if err != nil {
		t.Fatal("request failed unexpected:", err)
	}
}
