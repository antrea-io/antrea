// Copyright 2026 Antrea Authors
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

package flowstreamservice

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

// newSocketDir returns a directory for a socket. Unix socket paths are limited to about 100
// characters, which the directory of t.TempDir can exceed.
func newSocketDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "fs")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestListenLocal(t *testing.T) {
	svc := NewLocalFlowStreamService(ringbuffer.NewBroadcastBuffer[*flowpb.Flow](4))

	t.Run("only the current user can reach the socket", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows does not enforce Unix permission bits")
		}
		// The directory of a volume is created with a mode that lets everyone in.
		dir := filepath.Join(newSocketDir(t), "volume")
		require.NoError(t, os.Mkdir(dir, 0o777))
		require.NoError(t, os.Chmod(dir, 0o777))
		path := filepath.Join(dir, "flowstream.sock")

		lis, err := svc.ListenLocal(path)
		require.NoError(t, err)
		defer lis.Close()

		dirInfo, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
		sockInfo, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.ModeSocket|0o600, sockInfo.Mode())
	})

	t.Run("creates the directory and replaces a stale socket", func(t *testing.T) {
		path := filepath.Join(newSocketDir(t), "run", "flowstream.sock")
		first, err := svc.ListenLocal(path)
		require.NoError(t, err)
		// A socket file stays behind when the process does not get to close its listener.
		first.(*net.UnixListener).SetUnlinkOnClose(false)
		require.NoError(t, first.Close())

		second, err := svc.ListenLocal(path)
		require.NoError(t, err)
		require.NoError(t, second.Close())
	})

	t.Run("fails where nothing can be created", func(t *testing.T) {
		file := filepath.Join(newSocketDir(t), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o600))
		_, err := svc.ListenLocal(filepath.Join(file, "flowstream.sock"))
		assert.Error(t, err)
	})
}

func TestRunLocal(t *testing.T) {
	t.Run("serves every record unredacted to a client without credentials", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("gRPC cannot dial a Unix socket path of Windows")
		}
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](16)
		t.Cleanup(buf.Shutdown)
		buf.Produce(newFlow("flow-1", newPodK8S("kube-system", "coredns-abc", "other-ns", "backend-xyz")))

		svc := NewLocalFlowStreamService(buf)
		path := filepath.Join(newSocketDir(t), "flowstream.sock")
		lis, err := svc.ListenLocal(path)
		require.NoError(t, err)
		stopCh := make(chan struct{})
		errCh := make(chan error, 1)
		go func() { errCh <- svc.RunLocal(lis, stopCh) }()
		t.Cleanup(func() {
			close(stopCh)
			require.NoError(t, <-errCh)
		})

		conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		stream, err := flowpb.NewFlowStreamServiceClient(conn).GetFlows(t.Context(), &flowpb.GetFlowsRequest{ClusterWide: true})
		require.NoError(t, err)

		var got []*flowpb.Flow
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			got = append(got, resp.GetFlows()...)
		}
		require.Len(t, got, 1)
		k8s := got[0].GetK8S()
		assert.Equal(t, "coredns-abc", k8s.GetSourcePodName())
		assert.Equal(t, "backend-xyz", k8s.GetDestinationPodName())
	})

	t.Run("refuses a listener that is not a Unix socket", func(t *testing.T) {
		svc := NewLocalFlowStreamService(ringbuffer.NewBroadcastBuffer[*flowpb.Flow](4))
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		err = svc.RunLocal(lis, make(chan struct{}))
		assert.ErrorContains(t, err, "only served on a Unix socket")
		_, err = lis.Accept()
		assert.Error(t, err, "the listener must have been closed")
	})
}
