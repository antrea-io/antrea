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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

const (
	// LocalSocketPath is where a Flow Aggregator serves the FlowStreamService to the processes of
	// its own container, which is what "antctl observe" run inside the Pod connects to. The
	// directory is an emptyDir volume in the chart, so that the socket can be created whatever the
	// container's root filesystem allows.
	LocalSocketPath = "/var/run/antrea/flow-aggregator/flowstream.sock"
	// localDirMode and localSocketMode let the user the Flow Aggregator runs as, and nobody else,
	// reach the socket.
	localDirMode    os.FileMode = 0o700
	localSocketMode os.FileMode = 0o600
)

// NewLocalFlowStreamService creates a FlowStreamService for the processes of the Flow Aggregator's
// own container, to be served on a Unix socket with RunLocal. It does not authenticate or authorize
// its clients, and shows them every record unredacted, because the ones that can reach the socket
// are the ones that can already read everything the Flow Aggregator holds in memory: being able
// to open it requires running as the Flow Aggregator's user inside its container. For that reason
// RunLocal only serves on a Unix socket, and the service on the TCP port is built by
// NewFlowStreamService, which does not let clients through without a Kubernetes identity.
func NewLocalFlowStreamService(buffer ringbuffer.BroadcastBuffer[*flowpb.Flow]) *FlowStreamService {
	return newFlowStreamServiceWithoutAuthentication(buffer, nil)
}

// ListenLocal binds the Unix socket at path for RunLocal, replacing a socket that a previous run of
// the Flow Aggregator left behind, and makes the socket reachable by the current user only.
func (s *FlowStreamService) ListenLocal(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, localDirMode); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", dir, err)
	}
	// The directory may exist already, as the mount point of a volume, with whatever mode the volume has.
	if err := os.Chmod(dir, localDirMode); err != nil {
		return nil, fmt.Errorf("failed to restrict access to %s: %w", dir, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to remove the stale socket %s: %w", path, err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, localSocketMode); err != nil {
		lis.Close()
		return nil, fmt.Errorf("failed to restrict access to %s: %w", path, err)
	}
	return lis, nil
}

// RunLocal serves the FlowStreamService on lis, a Unix socket of ListenLocal, which it takes
// ownership of, and blocks until stopCh is closed and the server has stopped, which takes at most
// gracefulStopTimeout. Unlike Run, it needs no certificate, and it is only for a service created by
// NewLocalFlowStreamService: it refuses a listener that is not a Unix socket, since nothing
// authenticates the clients of the server it starts.
func (s *FlowStreamService) RunLocal(lis net.Listener, stopCh <-chan struct{}) error {
	if _, ok := lis.Addr().(*net.UnixAddr); !ok {
		lis.Close()
		return fmt.Errorf("the unauthenticated FlowStreamService is only served on a Unix socket, not on %s", lis.Addr())
	}
	server := grpc.NewServer(
		grpc.ForceServerCodecV2(newFlowStreamCodec()),
		grpc.ConnectionTimeout(connectionTimeout),
	)
	flowpb.RegisterFlowStreamServiceServer(server, s)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		klog.InfoS("Starting FlowStreamService gRPC server for the Flow Aggregator container", "addr", lis.Addr())
		// See Run for why grpc.ErrServerStopped is not a failure.
		if err := server.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			klog.ErrorS(err, "FlowStreamService gRPC server for the Flow Aggregator container failed")
		}
	}()
	<-stopCh
	gracefulStop(server)
	wg.Wait()
	return nil
}
