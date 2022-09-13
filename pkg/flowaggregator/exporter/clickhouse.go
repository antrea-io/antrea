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
	"os"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/clickhouseclient"
	"antrea.io/antrea/pkg/flowaggregator/options"
)

type ClickHouseExporter struct {
	chInput         *clickhouseclient.ClickHouseInput
	chExportProcess *clickhouseclient.ClickHouseExportProcess
}

func buildClickHouseInput(opt *options.Options) clickhouseclient.ClickHouseInput {
	return clickhouseclient.ClickHouseInput{
		Username:       os.Getenv("CH_USERNAME"),
		Password:       os.Getenv("CH_PASSWORD"),
		Database:       opt.Config.ClickHouse.Database,
		DatabaseURL:    opt.Config.ClickHouse.DatabaseURL,
		Debug:          opt.Config.ClickHouse.Debug,
		Compress:       opt.Config.ClickHouse.Compress,
		CommitInterval: opt.ClickHouseCommitInterval,
	}
}

func NewClickHouseExporter(k8sClient kubernetes.Interface, opt *options.Options) (*ClickHouseExporter, error) {
	chInput := buildClickHouseInput(opt)
	klog.InfoS("ClickHouse configuration", "database", chInput.Database, "databaseURL", chInput.DatabaseURL, "debug", chInput.Debug, "compress", *chInput.Compress, "commitInterval", chInput.CommitInterval)
	clusterUUID, err := getClusterUUID(k8sClient)
	if err != nil {
		return nil, err
	}
	chExportProcess, err := clickhouseclient.NewClickHouseClient(chInput, clusterUUID.String())
	if err != nil {
		return nil, err
	}
	return &ClickHouseExporter{
		chInput:         &chInput,
		chExportProcess: chExportProcess,
	}, nil
}

func (e *ClickHouseExporter) AddRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	e.chExportProcess.CacheRecord(record)
	return nil
}

func (e *ClickHouseExporter) Start() {
	e.chExportProcess.Start()
}

func (e *ClickHouseExporter) Stop() {
	e.chExportProcess.Stop()
}

func (e *ClickHouseExporter) UpdateOptions(opt *options.Options) {
	chInput := buildClickHouseInput(opt)
	dsn, connect, err := clickhouseclient.PrepareClickHouseConnection(chInput)
	if err != nil {
		klog.ErrorS(err, "Error when checking new connection")
		return
	}
	if dsn == e.chExportProcess.GetDsn() && chInput.CommitInterval == e.chExportProcess.GetCommitInterval() {
		return
	}
	klog.InfoS("Updating ClickHouse")
	if chInput.CommitInterval != e.chExportProcess.GetCommitInterval() {
		e.chExportProcess.SetCommitInterval(chInput.CommitInterval)
	}
	if dsn != e.chExportProcess.GetDsn() {
		e.chExportProcess.UpdateCH(dsn, connect)
	}
	klog.InfoS("New ClickHouse configuration", "database", chInput.Database, "databaseURL", chInput.DatabaseURL, "debug", chInput.Debug, "compress", *chInput.Compress, "commitInterval", chInput.CommitInterval)
}
