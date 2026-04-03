// Copyright 2022 Antrea Authors
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

package exporter

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/pkg/flowaggregator/clickhouseclient"
	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/ringbuffer"
)

type ClickHouseExporter struct {
	chConfig        *clickhouseclient.ClickHouseConfig
	chExportProcess *clickhouseclient.ClickHouseExportProcess
}

const (
	CACertFile      = "ca.crt"
	CertDir         = "/etc/flow-aggregator/certs/clickhouse"
	DefaultInterval = 1 * time.Second
	Timeout         = 1 * time.Minute
)

func buildClickHouseConfig(opt *options.Options) clickhouseclient.ClickHouseConfig {
	return clickhouseclient.ClickHouseConfig{
		Username:           os.Getenv("CH_USERNAME"),
		Password:           os.Getenv("CH_PASSWORD"),
		Database:           opt.Config.ClickHouse.Database,
		DatabaseURL:        opt.Config.ClickHouse.DatabaseURL,
		Debug:              opt.Config.ClickHouse.Debug,
		Compress:           opt.Config.ClickHouse.Compress,
		CommitInterval:     opt.ClickHouseCommitInterval,
		CACert:             opt.Config.ClickHouse.TLS.CACert,
		InsecureSkipVerify: opt.Config.ClickHouse.TLS.InsecureSkipVerify,
	}
}

func NewClickHouseExporter(clusterUUID uuid.UUID, opt *options.Options) (*ClickHouseExporter, error) {
	chConfig := buildClickHouseConfig(opt)
	klog.InfoS("ClickHouse configuration", "database", chConfig.Database, "databaseURL", chConfig.DatabaseURL, "debug", chConfig.Debug,
		"compress", *chConfig.Compress, "commitInterval", chConfig.CommitInterval, "insecureSkipVerify", chConfig.InsecureSkipVerify, "caCert", chConfig.CACert)
	var errMessage error
	if chConfig.CACert {
		err := wait.PollUntilContextTimeout(context.TODO(), DefaultInterval, Timeout, false, func(ctx context.Context) (bool, error) {
			caCertPath := path.Join(CertDir, CACertFile)
			certificate, err := os.ReadFile(caCertPath)
			if err != nil {
				errMessage = err
				return false, nil
			}
			chConfig.Certificate = certificate
			return true, nil
		})
		if err != nil {
			return nil, fmt.Errorf("error when reading custom CA certificate: %v", errMessage)
		}
	}
	chExportProcess, err := clickhouseclient.NewClickHouseClient(chConfig, clusterUUID.String())
	if err != nil {
		return nil, err
	}
	return &ClickHouseExporter{
		chConfig:        &chConfig,
		chExportProcess: chExportProcess,
	}, nil
}

// Run consumes flow records from the ring buffer and writes them to ClickHouse.
// It blocks until ctx is cancelled or the consumer signals shutdown.
func (e *ClickHouseExporter) Run(ctx context.Context, buf ringbuffer.BroadcastBuffer[*flowpb.Flow]) {
	consumer := buf.NewConsumer(ringbuffer.WithMaxConsumeDeadline(e.chConfig.CommitInterval))
	e.chExportProcess.Start()
	defer e.chExportProcess.Stop()

	for {
		record, n, _, shutdown := consumer.Consume()
		if n == 0 {
			if shutdown {
				return
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}

		if err := e.chExportProcess.CacheRecord(record); err != nil {
			klog.ErrorS(err, "Error when caching record for ClickHouse")
		}

		if shutdown || ctx.Err() != nil {
			return
		}
	}
}
