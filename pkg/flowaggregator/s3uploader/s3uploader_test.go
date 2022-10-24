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
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	ipfixentitiestesting "github.com/vmware/go-ipfix/pkg/entities/testing"
	"github.com/vmware/go-ipfix/pkg/registry"
	"k8s.io/apimachinery/pkg/util/wait"

	flowrecordtesting "antrea.io/antrea/pkg/flowaggregator/flowrecord/testing"
	flowaggregatortesting "antrea.io/antrea/pkg/flowaggregator/testing"
)

var (
	fakeClusterUUID = uuid.New().String()
	recordStrIPv4   = "1637706961,1637706973,1637706974,1637706975,3,10.10.0.79,10.10.0.80,44752,5201,6,823188,30472817041,241333,8982624938,471111,24500996,136211,7083284,perftest-a,antrea-test,k8s-node-control-plane,perftest-b,antrea-test-b,k8s-node-control-plane-b,10.10.1.10,5202,perftest,test-flow-aggregator-networkpolicy-ingress-allow,antrea-test-ns,test-flow-aggregator-networkpolicy-rule,2,1,test-flow-aggregator-networkpolicy-egress-allow,antrea-test-ns-e,test-flow-aggregator-networkpolicy-rule-e,5,4,TIME_WAIT,11,'{\"antrea-e2e\":\"perftest-a\",\"app\":\"perftool\"}','{\"antrea-e2e\":\"perftest-b\",\"app\":\"perftool\"}',15902813472,12381344,15902813473,15902813474,12381345,12381346," + fakeClusterUUID
	recordStrIPv6   = "1637706961,1637706973,1637706974,1637706975,3,2001:0:3238:dfe1:63::fefb,2001:0:3238:dfe1:63::fefc,44752,5201,6,823188,30472817041,241333,8982624938,471111,24500996,136211,7083284,perftest-a,antrea-test,k8s-node-control-plane,perftest-b,antrea-test-b,k8s-node-control-plane-b,2001:0:3238:dfe1:64::a,5202,perftest,test-flow-aggregator-networkpolicy-ingress-allow,antrea-test-ns,test-flow-aggregator-networkpolicy-rule,2,1,test-flow-aggregator-networkpolicy-egress-allow,antrea-test-ns-e,test-flow-aggregator-networkpolicy-rule-e,5,4,TIME_WAIT,11,'{\"antrea-e2e\":\"perftest-a\",\"app\":\"perftool\"}','{\"antrea-e2e\":\"perftest-b\",\"app\":\"perftool\"}',15902813472,12381344,15902813473,15902813474,12381345,12381346," + fakeClusterUUID
)

const seed = 1

type mockS3Uploader struct {
	testReader      *bytes.Buffer
	testReaderMutex sync.Mutex
}

func (m *mockS3Uploader) Upload(ctx context.Context, input *s3.PutObjectInput, awsS3Uploader *s3manager.Uploader, opts ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error) {
	m.testReaderMutex.Lock()
	defer m.testReaderMutex.Unlock()
	m.testReader.ReadFrom(input.Body)
	return nil, nil
}

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
	defer ctrl.Finish()
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
	assert.Contains(t, s3UploadProc.currentBuffer.String(), recordStrIPv4)

	// Second call, reach currentBuffer max size, add the currentBuffer to bufferQueue.
	mockRecord = ipfixentitiestesting.NewMockRecord(ctrl)
	flowaggregatortesting.PrepareMockIpfixRecord(mockRecord, false)
	s3UploadProc.CacheRecord(mockRecord)
	assert.Equal(t, 1, len(s3UploadProc.bufferQueue))
	buf := s3UploadProc.bufferQueue[0]
	assert.Contains(t, buf.String(), recordStrIPv6)
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
}

func TestBatchUploadAll(t *testing.T) {
	mockS3Uploader := &mockS3Uploader{testReader: &bytes.Buffer{}}
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
	testRecord := flowrecordtesting.PrepareTestFlowRecord()
	s3UploadProc.writeRecordToBuffer(testRecord)
	s3UploadProc.cachedRecordCount = 1
	err := s3UploadProc.batchUploadAll(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 0, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	assert.Contains(t, mockS3Uploader.testReader.String(), recordStrIPv4)
}

func TestBatchUploadAllError(t *testing.T) {
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
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-west-2"))
	s3UploadProc.awsS3Client = s3.NewFromConfig(cfg)
	s3UploadProc.awsS3Uploader = s3manager.NewUploader(s3UploadProc.awsS3Client)

	testRecord := flowrecordtesting.PrepareTestFlowRecord()
	s3UploadProc.writeRecordToBuffer(testRecord)
	s3UploadProc.cachedRecordCount = 1
	// It is expected to fail when calling uploadFile, as the correct S3 bucket
	// configuration is not provided.
	err := s3UploadProc.batchUploadAll(context.TODO())
	assert.Equal(t, 1, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	expectedErrMsg := "error when uploading file to S3: operation error S3: PutObject, https response error StatusCode: 301"
	assert.Contains(t, err.Error(), expectedErrMsg)
}

func TestFlowRecordPeriodicCommit(t *testing.T) {
	mockS3Uploader := &mockS3Uploader{testReader: &bytes.Buffer{}}
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
	testRecord := flowrecordtesting.PrepareTestFlowRecord()
	s3UploadProc.writeRecordToBuffer(testRecord)
	s3UploadProc.cachedRecordCount = 1
	s3UploadProc.startExportProcess()
	// wait for ticker to tick
	err := wait.PollImmediate(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		mockS3Uploader.testReaderMutex.Lock()
		defer mockS3Uploader.testReaderMutex.Unlock()
		if mockS3Uploader.testReader.Len() != 0 {
			return true, nil
		}
		return false, nil
	})
	assert.NoError(t, err)
	s3UploadProc.stopExportProcess(false)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 0, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	assert.Contains(t, mockS3Uploader.testReader.String(), recordStrIPv4)
}

func TestFlushCacheOnStop(t *testing.T) {
	mockS3Uploader := &mockS3Uploader{testReader: &bytes.Buffer{}}
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
	testRecord := flowrecordtesting.PrepareTestFlowRecord()
	s3UploadProc.writeRecordToBuffer(testRecord)
	s3UploadProc.cachedRecordCount = 1
	s3UploadProc.startExportProcess()
	s3UploadProc.stopExportProcess(true)
	assert.Equal(t, 0, len(s3UploadProc.bufferQueue))
	assert.Equal(t, 0, len(s3UploadProc.buffersToUpload))
	assert.Equal(t, "", s3UploadProc.currentBuffer.String())
	assert.Equal(t, 0, s3UploadProc.cachedRecordCount)
	assert.Contains(t, mockS3Uploader.testReader.String(), recordStrIPv4)
}
