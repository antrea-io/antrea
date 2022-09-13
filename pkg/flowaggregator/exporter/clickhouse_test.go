// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/clickhouseclient"
	"antrea.io/antrea/pkg/flowaggregator/options"
)

func TestClickHouse_UpdateOptions(t *testing.T) {
	os.Setenv("CH_USERNAME", "default")
	os.Setenv("CH_PASSWORD", "default")
	defer os.Unsetenv("CH_USERNAME")
	defer os.Unsetenv("CH_PASSWORD")
	PrepareClickHouseConnectionSaved := clickhouseclient.PrepareClickHouseConnection
	clickhouseclient.PrepareClickHouseConnection = func(input clickhouseclient.ClickHouseInput) (string, *sql.DB, error) {
		dsn, _ := input.GetDataSourceName()
		return dsn, nil, nil
	}
	defer func() {
		clickhouseclient.PrepareClickHouseConnection = PrepareClickHouseConnectionSaved
	}()
	compress := false
	opt := &options.Options{
		Config: &flowaggregator.FlowAggregatorConfig{
			ClickHouse: flowaggregator.ClickHouseConfig{
				Enable:      true,
				Database:    "default",
				DatabaseURL: "tcp://clickhouse-clickhouse.flow-visibility.svc:9000",
				Debug:       true,
				Compress:    &compress,
			},
		},
		ClickHouseCommitInterval: 8 * time.Second,
	}
	chInput := buildClickHouseInput(opt)
	chExportProcess, err := clickhouseclient.NewClickHouseClient(chInput, uuid.New().String())
	require.NoError(t, err)
	clickHouseExporter := ClickHouseExporter{chInput: &chInput, chExportProcess: chExportProcess}
	clickHouseExporter.Start()
	assert.Equal(t, clickHouseExporter.chExportProcess.GetDsn(), "tcp://clickhouse-clickhouse.flow-visibility.svc:9000?username=default&password=default&database=default&debug=true&compress=false")
	assert.Equal(t, clickHouseExporter.chExportProcess.GetCommitInterval().String(), "8s")
	compress = true
	newOpt := &options.Options{
		Config: &flowaggregator.FlowAggregatorConfig{
			ClickHouse: flowaggregator.ClickHouseConfig{
				Enable:      true,
				Database:    "databaseTest",
				DatabaseURL: "databaseTestURL",
				Debug:       false,
				Compress:    &compress,
			},
		},
		ClickHouseCommitInterval: 5 * time.Second,
	}
	clickHouseExporter.UpdateOptions(newOpt)
	assert.Equal(t, clickHouseExporter.chExportProcess.GetDsn(), "databaseTestURL?username=default&password=default&database=databaseTest&debug=false&compress=true")
	assert.Equal(t, clickHouseExporter.chExportProcess.GetCommitInterval().String(), "5s")
	clickHouseExporter.Stop()
}
