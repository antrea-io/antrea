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

// +build linux

package cni

import (
	"context"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cnipb "antrea.io/antrea/pkg/apis/cni/v1beta1"
)

type testClient struct {
	*testing.T
	add, check, del testClientBehave
}

type testClientBehave int

const (
	normal testClientBehave = iota
	invalidNetworkConfig
	rpcError
	rpcErrorTransient
	rpcErrorUnimplemented
)

func makeErrorResponse(cniErrorCode cnipb.ErrorCode, cniErrorMsg string) *cnipb.CniCmdResponse {
	return &cnipb.CniCmdResponse{
		Error: &cnipb.Error{
			Code:    cniErrorCode,
			Message: cniErrorMsg,
		},
	}
}

func (c *testClient) cmdHandle(ctx context.Context, b testClientBehave, requestMsg *cnipb.CniCmdRequest) (*cnipb.CniCmdResponse, error) {
	switch b {
	case normal:
		return &cnipb.CniCmdResponse{}, nil
	case invalidNetworkConfig:
		return makeErrorResponse(cnipb.ErrorCode_INVALID_NETWORK_CONFIG, "CNI error"), nil
	case rpcError:
		return nil, status.Error(codes.Unknown, "rpc error")
	case rpcErrorTransient:
		return nil, status.Error(codes.Unavailable, "transient rpc error")
	case rpcErrorUnimplemented:
		return nil, status.Error(codes.Unimplemented, "unimplemented rpc error")
	default:
		c.Fatalf("unexpected %+v action", c.add)
		return nil, nil
	}
}

func (c *testClient) CmdAdd(ctx context.Context, requestMsg *cnipb.CniCmdRequest, opts ...grpc.CallOption) (*cnipb.CniCmdResponse, error) {
	return c.cmdHandle(ctx, c.add, requestMsg)
}

func (c *testClient) CmdCheck(ctx context.Context, requestMsg *cnipb.CniCmdRequest, opts ...grpc.CallOption) (*cnipb.CniCmdResponse, error) {
	return c.cmdHandle(ctx, c.check, requestMsg)
}

func (c *testClient) CmdDel(ctx context.Context, requestMsg *cnipb.CniCmdRequest, opts ...grpc.CallOption) (*cnipb.CniCmdResponse, error) {
	return c.cmdHandle(ctx, c.del, requestMsg)
}

func enableTestClient(t *testing.T, add, check, del testClientBehave) {
	withClient = func(f func(client cnipb.CniClient) error) error {
		return f(&testClient{t, add, check, del})
	}
}

func disableTestClient() {
	withClient = rpcClient
}

func checkCNIError(t *testing.T, err error, expectedCode cnipb.ErrorCode) {
	e, ok := err.(*types.Error)
	require.True(t, ok, "expected error of type types.Error")
	// we need to use EqualValues (and not Equal) because the 2 values have different types
	assert.EqualValues(t, expectedCode, e.Code)
}

func TestInvalidNetworkConfigAdd(t *testing.T) {
	enableTestClient(t, invalidNetworkConfig, normal, normal)
	defer disableTestClient()

	stdinData := `{ "name":"antrea-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionAdd.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	require.NotNil(t, err)
	checkCNIError(t, err, cnipb.ErrorCode_INVALID_NETWORK_CONFIG)
}

func TestRpcErrorsCheck(t *testing.T) {
	testCases := []struct {
		behavior testClientBehave
		cniCode  cnipb.ErrorCode
	}{
		{rpcError, cnipb.ErrorCode_UNKNOWN_RPC_ERROR},
		{rpcErrorTransient, cnipb.ErrorCode_TRY_AGAIN_LATER},
		{rpcErrorUnimplemented, cnipb.ErrorCode_INCOMPATIBLE_API_VERSION},
	}

	stdinData := `{ "name":"antrea-cni", "some": "config", "cniVersion": "9.8.7" }`

	for _, tc := range testCases {
		t.Run(tc.cniCode.String(), func(t *testing.T) {
			tc := tc
			enableTestClient(t, tc.behavior, normal, normal)
			defer disableTestClient()

			err := ActionAdd.Request(&skel.CmdArgs{
				ContainerID: "some-container-id",
				Netns:       "/some/netns/path",
				IfName:      "eth0",
				Args:        "some;extra;args",
				Path:        "/some/cni/path",
				StdinData:   []byte(stdinData),
			})
			require.NotNil(t, err)
			checkCNIError(t, err, tc.cniCode)
		})
	}
}

func TestSuccessAdd(t *testing.T) {
	enableTestClient(t, normal, normal, normal)
	defer disableTestClient()

	stdinData := `{ "name":"antrea-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionAdd.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	require.Nil(t, err, "CNI ADD request failed")
}

func TestSuccessDel(t *testing.T) {
	enableTestClient(t, normal, normal, normal)
	defer disableTestClient()

	stdinData := `{ "name":"antrea-cni", "some": "config", "cniVersion": "9.8.7" }`
	err := ActionDel.Request(&skel.CmdArgs{
		ContainerID: "some-container-id",
		Netns:       "/some/netns/path",
		IfName:      "eth0",
		Args:        "some;extra;args",
		Path:        "/some/cni/path",
		StdinData:   []byte(stdinData),
	})
	require.Nil(t, err, "CNI DEL request failed")
}
