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
	"reflect"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/clickhouseclient"
	"antrea.io/antrea/pkg/flowaggregator/options"
)

type ClickHouseExporter struct {
	chConfig        *clickhouseclient.ClickHouseConfig
	chExportProcess *clickhouseclient.ClickHouseExportProcess
}

func buildClickHouseConfig(opt *options.Options) clickhouseclient.ClickHouseConfig {
	return clickhouseclient.ClickHouseConfig{
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
	chConfig := buildClickHouseConfig(opt)
	klog.InfoS("ClickHouse configuration", "database", chConfig.Database, "databaseURL", chConfig.DatabaseURL, "debug", chConfig.Debug, "compress", *chConfig.Compress, "commitInterval", chConfig.CommitInterval)
	clusterUUID, err := getClusterUUID(k8sClient)
	if err != nil {
		return nil, err
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
	chConfig := buildClickHouseConfig(opt)
	connect, err := clickhouseclient.PrepareClickHouseConnection(chConfig)
	if err != nil {
		klog.ErrorS(err, "Error when checking new connection")
		return
	}
	if reflect.DeepEqual(chConfig, e.chExportProcess.GetClickHouseConfig()) {
		return
	}
	klog.InfoS("Updating ClickHouse")
	if chConfig.CommitInterval != e.chExportProcess.GetCommitInterval() {
		e.chExportProcess.SetCommitInterval(chConfig.CommitInterval)
	}
	// When a new commitInterval was updated through
	// e.chExportProcess.SetCommitInterval, the following
	// e.chExportProcess.UpdateCH will not be called.
	if !reflect.DeepEqual(chConfig, e.chExportProcess.GetClickHouseConfig()) {
		e.chExportProcess.UpdateCH(chConfig, connect)
	}
	klog.InfoS("New ClickHouse configuration", "database", chConfig.Database, "databaseURL", chConfig.DatabaseURL, "debug", chConfig.Debug, "compress", *chConfig.Compress, "commitInterval", chConfig.CommitInterval)
}
