// Copyright 2025 Antrea Authors
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

package collector

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

const grpcCollectorAddress = "0.0.0.0:14739"

type grpcCollector struct {
	service *grpcService
	server  *grpc.Server
}

func NewGRPCCollector(recordCh chan *flowpb.Flow, caCert, serverKey, serverCert []byte) (*grpcCollector, error) {
	cas := x509.NewCertPool()
	if ok := cas.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("error when adding generate CA cert to pool")
	}
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key pair: %w", err)
	}
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cas,
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	service := &grpcService{
		recordCh: recordCh,
	}
	// grpc_recovery ensures that a panic while handling one stream (e.g. triggered by
	// a malformed Flow message) is recovered into a gRPC error for that stream only,
	// instead of taking down the whole flow-aggregator process.
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainStreamInterceptor(recovery.StreamServerInterceptor()),
	)
	flowpb.RegisterFlowExportServiceServer(server, service)
	return &grpcCollector{
		service: service,
		server:  server,
	}, nil
}

func (c *grpcCollector) Run(stopCh <-chan struct{}) {
	// #nosec G102: binding to all network interfaces is intentional
	lis, err := net.Listen("tcp", grpcCollectorAddress)
	if err != nil {
		klog.ErrorS(err, "Failed to listen on address", "addr", grpcCollectorAddress)
		return
	}
	// c.server.Stop() will close the listener
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		klog.InfoS("Starting gRPC collector", "addr", lis.Addr().String())
		if err := c.server.Serve(lis); err != nil {
			klog.ErrorS(err, "gRPC server error")
		}
	}()
	<-stopCh
	c.server.Stop()
	wg.Wait()
}

func (c *grpcCollector) GetNumRecordsReceived() int64 {
	return c.service.numRecordsReceived.Load()
}

func (c *grpcCollector) GetNumConnsToCollector() int64 {
	return c.service.numConns.Load()
}

type grpcService struct {
	flowpb.UnimplementedFlowExportServiceServer
	recordCh           chan *flowpb.Flow
	numRecordsReceived atomic.Int64
	numConns           atomic.Int64
}

func (s *grpcService) Export(stream flowpb.FlowExportService_ExportServer) error {
	s.numConns.Add(1)
	defer s.numConns.Add(-1)

	var exportAddress string
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		klog.ErrorS(nil, "Missing gRPC peer information")
	} else {
		exportAddress = p.Addr.String()
		// Natches the go-ipfix code:
		// https://github.com/vmware/go-ipfix/blob/961f78e9fa2d7a417ee4dd1b95f29b08fa2a794d/pkg/collector/process.go#L274-L279
		// handle IPv6 address which may involve []
		portIndex := strings.LastIndex(exportAddress, ":")
		exportAddress = exportAddress[:portIndex]
		exportAddress = strings.ReplaceAll(exportAddress, "[", "")
		exportAddress = strings.ReplaceAll(exportAddress, "]", "")
	}

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		for _, record := range req.Flows {
			s.numRecordsReceived.Add(1)
			if err := validateFlow(record); err != nil {
				klog.ErrorS(err, "Ignoring invalid Flow record", "exportAddress", exportAddress)
				continue
			}
			record.Ipfix.ExporterIp = exportAddress
			s.recordCh <- record
		}
	}

	return stream.SendAndClose(&flowpb.ExportResponse{})
}

// validateFlow checks that the sub-messages of a Flow record which are unconditionally
// dereferenced by downstream flow-aggregator processing (K8s metadata enrichment,
// aggregation and exporters) are present. A client-supplied Flow with any of these
// sub-messages omitted would otherwise cause a nil pointer dereference panic once the
// record leaves the gRPC collector.
// Aggregation is intentionally not checked here: it is always populated internally by
// the aggregation process itself, not expected from the client. App is deprecated and
// unused.
func validateFlow(record *flowpb.Flow) error {
	switch {
	case record.Ipfix == nil:
		return fmt.Errorf("flow record is missing the ipfix field")
	case record.StartTs == nil:
		return fmt.Errorf("flow record is missing the start_ts field")
	case record.EndTs == nil:
		return fmt.Errorf("flow record is missing the end_ts field")
	case record.Ip == nil:
		return fmt.Errorf("flow record is missing the ip field")
	case record.Transport == nil:
		return fmt.Errorf("flow record is missing the transport field")
	case record.K8S == nil:
		return fmt.Errorf("flow record is missing the k8s field")
	case record.Stats == nil:
		return fmt.Errorf("flow record is missing the stats field")
	case record.ReverseStats == nil:
		return fmt.Errorf("flow record is missing the reverse_stats field")
	}
	return nil
}
