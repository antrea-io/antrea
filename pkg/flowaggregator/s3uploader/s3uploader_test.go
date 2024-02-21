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

package s3uploader

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/registry"
	"go.uber.org/mock/gomock"

	s3uploadertesting "antrea.io/antrea/pkg/flowaggregator/s3uploader/testing"
	flowaggregatortesting "antrea.io/antrea/pkg/flowaggregator/testing"
)

var (
	fakeClusterUUID = uuid.New().String()
	recordStrIPv4   = "1637706961,1637706973,1637706974,1637706975,3,10.10.0.79,10.10.0.80,44752,5201,6,823188,30472817041,241333,8982624938,471111,24500996,136211,7083284,perftest-a,antrea-test,k8s-node-control-plane,perftest-b,antrea-test-b,k8s-node-control-plane-b,10.10.1.10,5202,perftest,test-flow-aggregator-networkpolicy-ingress-allow,antrea-test-ns,test-flow-aggregator-networkpolicy-rule,2,1,test-flow-aggregator-networkpolicy-egress-allow,antrea-test-ns-e,test-flow-aggregator-networkpolicy-rule-e,5,4,TIME_WAIT,11,'{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}','{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}',15902813472,12381344,15902813473,15902813474,12381345,12381346," + fakeClusterUUID + "," + fmt.Sprintf("%d", time.Now().Unix()) + ",test-egress,172.18.0.1,http,mockHttpString,test-egress-node"
	recordStrIPv6   = "1637706961,1637706973,1637706974,1637706975,3,2001:0:3238:dfe1:63::fefb,2001:0:3238:dfe1:63::fefc,44752,5201,6,823188,30472817041,241333,8982624938,471111,24500996,136211,7083284,perftest-a,antrea-test,k8s-node-control-plane,perftest-b,antrea-test-b,k8s-node-control-plane-b,2001:0:3238:dfe1:64::a,5202,perftest,test-flow-aggregator-networkpolicy-ingress-allow,antrea-test-ns,test-flow-aggregator-networkpolicy-rule,2,1,test-flow-aggregator-networkpolicy-egress-allow,antrea-test-ns-e,test-flow-aggregator-networkpolicy-rule-e,5,4,TIME_WAIT,11,'{\"antrea-e2e\":\"perftest-a\",\"app\":\"iperf\"}','{\"antrea-e2e\":\"perftest-b\",\"app\":\"iperf\"}',15902813472,12381344,15902813473,15902813474,12381345,12381346," + fakeClusterUUID + "," + fmt.Sprintf("%d", time.Now().Unix()) + ",test-egress,172.18.0.1,http,mockHttpString,test-egress-node"
)

const seed = 1

func init() {
	registry.LoadRegistry()
}

func TestUpdateS3Uploader(t *testing.T) {
	s3UploadProc := S3UploadProcess{
		bucketName:     "test-bucket-name-old",
		bucketPrefix:   "test-bucket-prefix-old",
		region:         "us-west-2",
		uploadInterval: 1 * time.Minute,
	}
	newBucketName := "test-bucket-name-new"
	newBucketPrefix := "test-bucket-prefix-new"
	newRegion := "us-west-1"
	s3UploadProc.UpdateS3Uploader(newBucketName, newBucketPrefix, newRegion)
	assert.Equal(t, newBucketName, s3UploadProc.bucketName)
	assert.Equal(t, newBucketPrefix, s3UploadProc.bucketPrefix)
	assert.Equal(t, newRegion, s3UploadProc.region)
	assert.NotNil(t, s3UploadProc.awsS3Client)
	assert.NotNil(t, s3UploadProc.awsS3Uploader)
}

func TestCacheRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	s3UploadProc := S3UploadProcess{
		compress:         false,
		maxRecordPerFile: 2,
		currentBuffer:    &bytes.Buffer{},
		bufferQueue:      make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		clusterUUID:      fakeClusterUUID,
	}

	// First call, cache the record in currentBuffer.
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, s3UploadProc.cachedRecordCount)
	currentBuffer := strings.TrimRight(s3UploadProc.currentBuffer.String(), "\n")
	assert.Equal(t, strings.Split(currentBuffer, ",")[:50], strings.Split(recordStrIPv4, ",")[:50])
	assert.Equal(t, strings.Split(currentBuffer, ",")[51:], strings.Split(recordStrIPv4, ",")[51:])

	// Second call, reach currentBuffer max size, add the currentBuffer to bufferQueue.
	mockRecord = ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, false)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, len(s3UploadProc.bufferQueue))
	buf := s3UploadProc.bufferQueue[0]
	currentBuf := strings.TrimRight(strings.Split(buf.String(), "\n")[1], "\n")
	assert.Equal(t, strings.Split(currentBuf, ",")[:50], strings.Split(recordStrIPv6, ",")[:50])
	assert.Equal(t, strings.Split(currentBuf, ",")[51:], strings.Split(recordStrIPv6, ",")[51:])
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
}

func TestBatchUploadAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockS3Uploader := s3uploadertesting.NewMockS3UploaderAPI(ctrl)
	ctx := context.Background()
	mockS3Uploader.EXPECT().Upload(ctx, gomock.Any(), nil).Return(nil, nil)
	// #nosec G404: random number generator not used for security purposes
	nameRand := rand.New(rand.NewSource(seed))
	s3UploadProc := S3UploadProcess{
		compress:         false,
		maxRecordPerFile: 10,
		currentBuffer:    &bytes.Buffer{},
		bufferQueue:      make([]*bytes.Buffer, 0),
		buffersToUpload:  make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		s3UploaderAPI:    mockS3Uploader,
		nameRand:         nameRand,
		clusterUUID:      fakeClusterUUID,
	}
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, s3UploadProc.cachedRecordCount)

	err := s3UploadProc.batchUploadAll(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 0, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
}

func TestBatchUploadAllPartialSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockS3Uploader := s3uploadertesting.NewMockS3UploaderAPI(ctrl)
	ctx := context.Background()
	gomock.InOrder(
		mockS3Uploader.EXPECT().Upload(ctx, gomock.Any(), nil).Return(nil, nil),
		mockS3Uploader.EXPECT().Upload(ctx, gomock.Any(), nil).Return(nil, fmt.Errorf("random error")),
	)
	// #nosec G404: random number generator not used for security purposes
	nameRand := rand.New(rand.NewSource(seed))
	s3UploadProc := S3UploadProcess{
		compress:         false,
		maxRecordPerFile: 1,
		currentBuffer:    &bytes.Buffer{},
		bufferQueue:      make([]*bytes.Buffer, 0),
		buffersToUpload:  make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		s3UploaderAPI:    mockS3Uploader,
		nameRand:         nameRand,
		clusterUUID:      fakeClusterUUID,
	}
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)
	mockRecord = ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)

	err := s3UploadProc.batchUploadAll(ctx)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 1, len(s3UploadProc.buffersToUpload))
	assert.EqualError(t, err, "error when uploading file to S3: random error")
}

func TestBatchUploadAllError(t *testing.T) {
	ctrl := gomock.NewController(t)
	ctx := context.Background()
	s3uploader := &S3Uploader{}
	// #nosec G404: random number generator not used for security purposes
	nameRand := rand.New(rand.NewSource(seed))
	s3UploadProc := S3UploadProcess{
		bucketName:       "test-bucket-name",
		compress:         false,
		maxRecordPerFile: 10,
		currentBuffer:    &bytes.Buffer{},
		bufferQueue:      make([]*bytes.Buffer, 0),
		buffersToUpload:  make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		s3UploaderAPI:    s3uploader,
		nameRand:         nameRand,
	}
	cfg, _ := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	s3UploadProc.awsS3Client = s3.NewFromConfig(cfg)
	s3UploadProc.awsS3Uploader = s3manager.NewUploader(s3UploadProc.awsS3Client)

	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, s3UploadProc.cachedRecordCount)

	// It is expected to fail when calling uploadFile, as the correct S3 bucket
	// configuration is not provided.
	err := s3UploadProc.batchUploadAll(ctx)
	assert.Equal(t, 1, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	expectedErrMsg := "error when uploading file to S3: operation error S3: PutObject, https response error StatusCode: 301"
	assert.Contains(t, err.Error(), expectedErrMsg)
}

func TestFlowRecordPeriodicCommit(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockS3Uploader := s3uploadertesting.NewMockS3UploaderAPI(ctrl)
	waitCh := make(chan struct{})
	mockS3Uploader.EXPECT().Upload(context.Background(), gomock.Any(), nil).DoAndReturn(
		// arguments have to exactly match func (mr *MockS3UploaderAPIMockRecorder) Upload(arg0, arg1, arg2 interface{}, arg3 ...interface{}) *gomock.Call
		func(arg0, arg1, arg2 interface{}, arg3 ...interface{}) (*s3manager.UploadOutput, error) {
			close(waitCh)
			return nil, nil
		},
	)
	// #nosec G404: random number generator not used for security purposes
	nameRand := rand.New(rand.NewSource(seed))
	s3UploadProc := S3UploadProcess{
		compress:         false,
		maxRecordPerFile: 10,
		uploadInterval:   100 * time.Millisecond,
		currentBuffer:    &bytes.Buffer{},
		bufferQueue:      make([]*bytes.Buffer, 0),
		buffersToUpload:  make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		s3UploaderAPI:    mockS3Uploader,
		nameRand:         nameRand,
		clusterUUID:      fakeClusterUUID,
	}
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, s3UploadProc.cachedRecordCount)

	s3UploadProc.startExportProcess()
	assert.Eventually(t, func() bool {
		select {
		case <-waitCh:
			// mock has been called
			return true
		default:
			// mock has not been called yet
			return false
		}
	}, 1*time.Second, 10*time.Millisecond)
	s3UploadProc.stopExportProcess(false)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 0, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
}

func TestFlushCacheOnStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockS3Uploader := s3uploadertesting.NewMockS3UploaderAPI(ctrl)
	mockS3Uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), nil).Return(nil, nil)
	// #nosec G404: random number generator not used for security purposes
	nameRand := rand.New(rand.NewSource(seed))
	s3UploadProc := S3UploadProcess{
		compress:         false,
		maxRecordPerFile: 10,
		uploadInterval:   100 * time.Second,
		currentBuffer:    &bytes.Buffer{},
		bufferQueue:      make([]*bytes.Buffer, 0),
		buffersToUpload:  make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		s3UploaderAPI:    mockS3Uploader,
		nameRand:         nameRand,
		clusterUUID:      fakeClusterUUID,
	}
	mockRecord := ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, true)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, s3UploadProc.cachedRecordCount)

	s3UploadProc.startExportProcess()
	s3UploadProc.stopExportProcess(true)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 0, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
}
