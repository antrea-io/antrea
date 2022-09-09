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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/options"
)

func TestS3_UpdateOptions(t *testing.T) {
	compress := true
	opt := &options.Options{
		Config: &flowaggregator.FlowAggregatorConfig{
			S3Uploader: flowaggregator.S3UploaderConfig{
				BucketName:        "defaultBucketName",
				BucketPrefix:      "defaultBucketPrefix",
				Region:            "us-west-2",
				RecordFormat:      "CSV",
				Compress:          &compress,
				MaxRecordsPerFile: 0,
			},
		},
		S3UploadInterval: 8 * time.Second,
	}
	s3Exporter, err := NewS3Exporter(opt)
	require.NoError(t, err)
	s3Exporter.Start()
	assert.Equal(t, s3Exporter.s3UploadProcess.GetBucketName(), "defaultBucketName")
	assert.Equal(t, s3Exporter.s3UploadProcess.GetBucketPrefix(), "defaultBucketPrefix")
	assert.Equal(t, s3Exporter.s3UploadProcess.GetRegion(), "us-west-2")
	assert.Equal(t, s3Exporter.s3UploadProcess.GetUploadInterval().String(), "8s")

	compress = true
	newOpt := &options.Options{
		Config: &flowaggregator.FlowAggregatorConfig{
			S3Uploader: flowaggregator.S3UploaderConfig{
				BucketName:        "testBucketName",
				BucketPrefix:      "testBucketPrefix",
				Region:            "us-west-1",
				RecordFormat:      "CSV",
				Compress:          &compress,
				MaxRecordsPerFile: 0,
			},
		},
		S3UploadInterval: 5 * time.Second,
	}
	s3Exporter.UpdateOptions(newOpt)
	assert.Equal(t, s3Exporter.s3UploadProcess.GetBucketName(), "testBucketName")
	assert.Equal(t, s3Exporter.s3UploadProcess.GetBucketPrefix(), "testBucketPrefix")
	assert.Equal(t, s3Exporter.s3UploadProcess.GetRegion(), "us-west-1")
	assert.Equal(t, s3Exporter.s3UploadProcess.GetUploadInterval().String(), "5s")
	s3Exporter.Stop()
}
