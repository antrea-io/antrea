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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"k8s.io/klog/v2"

	config "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
)

const (
	bufferFlushTimeout         = 1 * time.Minute
	maxNumBuffersPendingUpload = 5
)

// GetS3BucketRegion is used for unit testing
var GetS3BucketRegion = getBucketRegion

type stopPayload struct {
	flushQueue bool
}

type S3UploadProcess struct {
	bucketName       string
	bucketPrefix     string
	region           string
	compress         bool
	maxRecordPerFile int32
	// uploadInterval is the interval between batch uploads
	uploadInterval time.Duration
	// uploadTicker is a ticker, containing a channel used to trigger batchUploadAll() for every uploadInterval period
	uploadTicker *time.Ticker
	// stopCh is the channel to receive stop message
	stopCh chan stopPayload
	// exportWg is to ensure that all messages have been flushed from the queue when we stop
	exportWg             sync.WaitGroup
	exportProcessRunning bool
	// mutex protects configuration state from concurrent access
	mutex sync.Mutex
	// queueMutex protects currentBuffer and bufferQueue from concurrent access
	queueMutex sync.Mutex
	// currentBuffer caches flow record
	currentBuffer *bytes.Buffer
	// cachedRecordCount keeps track of the number of flow records written into currentBuffer
	cachedRecordCount int
	// bufferQueue caches currentBuffer when it is full
	bufferQueue []*bytes.Buffer
	// buffersToUpload stores all the buffers to be uploaded for the current uploadFile() call
	buffersToUpload []*bytes.Buffer
	gzipWriter      *gzip.Writer
	// awsS3Client is used to initialize awsS3Uploader
	awsS3Client *s3.Client
	// awsS3Uploader makes the real call to aws-sdk Upload() method to upload an object to S3
	awsS3Uploader *s3manager.Uploader
	// s3UploaderAPI wraps the call made by awsS3Uploader
	s3UploaderAPI S3UploaderAPI
	nameRand      *rand.Rand
	clusterUUID   string
}

type S3Input struct {
	Config         config.S3UploaderConfig
	UploadInterval time.Duration
}

// Define a wrapper interface S3UploaderAPI to assist unit testing.
type S3UploaderAPI interface {
	Upload(ctx context.Context, input *s3.PutObjectInput, awsS3Uploader *s3manager.Uploader, opts ...func(*s3manager.Uploader)) (
		*s3manager.UploadOutput, error,
	)
}

type S3Uploader struct{}

func (u *S3Uploader) Upload(ctx context.Context, input *s3.PutObjectInput, awsS3Uploader *s3manager.Uploader, opts ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error) {
	return awsS3Uploader.Upload(ctx, input, opts...)
}

// getBucketRegion determines the exact region in which the bucket is
// located. regionHint can be any region in the same partition as the one in
// which the bucket is located.
func getBucketRegion(ctx context.Context, bucket string, regionHint string) (string, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(regionHint))
	if err != nil {
		return "", fmt.Errorf("unable to load AWS SDK config: %w", err)

	}
	s3Client := s3.NewFromConfig(awsCfg)
	bucketRegion, err := s3manager.GetBucketRegion(ctx, s3Client, bucket)
	if err != nil {
		return "", fmt.Errorf("unable to determine region for bucket '%s', make sure the bucket exists and set the region parameter appropriately: %w", bucket, err)
	}
	return bucketRegion, err
}

func NewS3UploadProcess(input S3Input, clusterUUID string) (*S3UploadProcess, error) {
	config := input.Config
	region, err := GetS3BucketRegion(context.TODO(), config.BucketName, config.Region)
	if err != nil {
		return nil, err
	}
	klog.InfoS("S3 bucket region successfully determined for flow upload", "bucket", config.BucketName, "region", region)
	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(), awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("error when loading AWS config: %w", err)
	}
	awsS3Client := s3.NewFromConfig(awsCfg)
	awsS3Uploader := s3manager.NewUploader(awsS3Client)

	buf := &bytes.Buffer{}
	// #nosec G404: random number generator not used for security purposes
	nameRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	s3ExportProcess := &S3UploadProcess{
		bucketName:       config.BucketName,
		bucketPrefix:     config.BucketPrefix,
		region:           region,
		compress:         *config.Compress,
		maxRecordPerFile: config.MaxRecordsPerFile,
		uploadInterval:   input.UploadInterval,
		currentBuffer:    buf,
		bufferQueue:      make([]*bytes.Buffer, 0),
		buffersToUpload:  make([]*bytes.Buffer, 0, maxNumBuffersPendingUpload),
		gzipWriter:       gzip.NewWriter(buf),
		awsS3Client:      awsS3Client,
		awsS3Uploader:    awsS3Uploader,
		s3UploaderAPI:    &S3Uploader{},
		nameRand:         nameRand,
		clusterUUID:      clusterUUID,
	}
	return s3ExportProcess, nil
}

func (p *S3UploadProcess) GetBucketName() string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.bucketName
}

func (p *S3UploadProcess) GetBucketPrefix() string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.bucketPrefix
}

func (p *S3UploadProcess) GetRegion() string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.region
}

func (p *S3UploadProcess) GetUploadInterval() time.Duration {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.uploadInterval
}

func (p *S3UploadProcess) UpdateS3Uploader(bucketName, bucketPrefix, region string) error {
	p.stopExportProcess(false)
	defer p.startExportProcess()
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if bucketName != p.bucketName {
		p.bucketName = bucketName
	}
	if bucketPrefix != p.bucketPrefix {
		p.bucketPrefix = bucketPrefix
	}
	if region != p.region {
		cfg, err := awsconfig.LoadDefaultConfig(context.TODO(), awsconfig.WithRegion(region))
		if err != nil {
			return fmt.Errorf("error when loading AWS config: %w", err)
		}
		p.region = region
		p.awsS3Client = s3.NewFromConfig(cfg)
		p.awsS3Uploader = s3manager.NewUploader(p.awsS3Client)
	}
	return nil
}

func (p *S3UploadProcess) SetUploadInterval(uploadInterval time.Duration) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.uploadInterval = uploadInterval
	if p.uploadTicker != nil {
		p.uploadTicker.Reset(p.uploadInterval)
	}
}

func (p *S3UploadProcess) CacheRecord(record ipfixentities.Record) {
	r := flowrecord.GetFlowRecord(record)
	p.queueMutex.Lock()
	defer p.queueMutex.Unlock()
	p.writeRecordToBuffer(r)
	// If the number of pending records in the buffer reaches maxRecordPerFile,
	// add the buffer to bufferQueue.
	if int32(p.cachedRecordCount) == p.maxRecordPerFile {
		p.appendBufferToQueue()
	}
}

func (p *S3UploadProcess) Start() {
	p.startExportProcess()
}

func (p *S3UploadProcess) Stop() {
	p.stopExportProcess(true)
}

func (p *S3UploadProcess) startExportProcess() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.exportProcessRunning {
		return
	}
	p.exportProcessRunning = true
	p.uploadTicker = time.NewTicker(p.uploadInterval)
	p.stopCh = make(chan stopPayload, 1)
	p.exportWg.Add(1)
	go func() {
		defer p.exportWg.Done()
		p.flowRecordPeriodicCommit()
	}()
}

func (p *S3UploadProcess) stopExportProcess(flushQueue bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !p.exportProcessRunning {
		return
	}
	p.exportProcessRunning = false
	defer p.uploadTicker.Stop()
	p.stopCh <- stopPayload{
		flushQueue: flushQueue,
	}
	p.exportWg.Wait()
}

func (p *S3UploadProcess) flowRecordPeriodicCommit() {
	klog.InfoS("Starting S3 exporting process")
	ctx := context.Background()
	for {
		select {
		case stop := <-p.stopCh:
			klog.InfoS("Stopping S3 exporting process")
			if !stop.flushQueue {
				return
			}
			ctx, cancelFn := context.WithTimeout(ctx, bufferFlushTimeout)
			defer cancelFn()
			err := p.batchUploadAll(ctx)
			if err != nil {
				klog.ErrorS(err, "Error when doing batchUploadAll on stop")
			}
			return
		case <-p.uploadTicker.C:
			err := p.batchUploadAll(ctx)
			if err != nil {
				klog.ErrorS(err, "Error when doing batchUploadAll on triggered timer")
			}
		}
	}
}

// batchUploadAll uploads all buffers cached in bufferQueue and previous fail-
// to-upload buffers stored in buffersToUpload. Returns error encountered
// during upload if any.
func (p *S3UploadProcess) batchUploadAll(ctx context.Context) error {
	func() {
		p.queueMutex.Lock()
		defer p.queueMutex.Unlock()

		if p.cachedRecordCount != 0 {
			p.appendBufferToQueue()
		}
		// dump cached buffers from bufferQueue to buffersToUpload
		for _, buf := range p.bufferQueue {
			p.buffersToUpload = append(p.buffersToUpload, buf)
			if len(p.buffersToUpload) > maxNumBuffersPendingUpload {
				p.buffersToUpload = p.buffersToUpload[1:]
			}
		}
		p.bufferQueue = p.bufferQueue[:0]
	}()

	uploaded := 0
	for _, buf := range p.buffersToUpload {
		reader := bytes.NewReader(buf.Bytes())
		err := p.uploadFile(ctx, reader)
		if err != nil {
			p.buffersToUpload = p.buffersToUpload[uploaded:]
			return err
		}
		uploaded += 1
	}
	p.buffersToUpload = p.buffersToUpload[:0]
	return nil
}

func (p *S3UploadProcess) writeRecordToBuffer(record *flowrecord.FlowRecord) {
	var writer io.Writer
	writer = p.currentBuffer
	if p.compress {
		writer = p.gzipWriter
	}
	writeRecord(writer, record, p.clusterUUID)
	io.WriteString(writer, "\n")
	p.cachedRecordCount += 1
}

func (p *S3UploadProcess) uploadFile(ctx context.Context, reader *bytes.Reader) error {
	fileName := fmt.Sprintf("records-%s.csv", randSeq(p.nameRand, 12))
	if p.compress {
		fileName += ".gz"
	}
	key := fileName
	if p.bucketPrefix != "" {
		key = fmt.Sprintf("%s/%s", p.bucketPrefix, fileName)
	}
	if _, err := p.s3UploaderAPI.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(p.bucketName),
		Key:    aws.String(key),
		Body:   reader,
	}, p.awsS3Uploader); err != nil {
		return fmt.Errorf("error when uploading file to S3: %v", err)
	}
	return nil
}

// appendBufferToQueue appends currentBuffer to bufferQueue, and reset
// currentBuffer. Caller of this function should acquire queueMutex.
func (p *S3UploadProcess) appendBufferToQueue() {
	p.bufferQueue = append(p.bufferQueue, p.currentBuffer)
	newBuffer := &bytes.Buffer{}
	// avoid too many memory allocations
	newBuffer.Grow(p.currentBuffer.Cap())
	p.currentBuffer = newBuffer
	p.cachedRecordCount = 0
	if p.compress {
		p.gzipWriter.Close()
		p.gzipWriter.Reset(p.currentBuffer)
	}
}

func randSeq(randSrc *rand.Rand, n int) string {
	var alphabet = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		randIdx := randSrc.Intn(len(alphabet))
		b[i] = alphabet[randIdx]
	}
	return string(b)
}

func writeRecord(w io.Writer, r *flowrecord.FlowRecord, clusterUUID string) {
	io.WriteString(w, fmt.Sprintf("%d", r.FlowStartSeconds.Unix()))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.FlowEndSeconds.Unix()))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.FlowEndSecondsFromSourceNode.Unix()))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.FlowEndSecondsFromDestinationNode.Unix()))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.FlowEndReason))
	io.WriteString(w, ",")
	io.WriteString(w, r.SourceIP)
	io.WriteString(w, ",")
	io.WriteString(w, r.DestinationIP)
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.SourceTransportPort))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.DestinationTransportPort))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ProtocolIdentifier))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.PacketTotalCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.OctetTotalCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.PacketDeltaCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.OctetDeltaCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReversePacketTotalCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReverseOctetTotalCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReversePacketDeltaCount))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReverseOctetDeltaCount))
	io.WriteString(w, ",")
	io.WriteString(w, r.SourcePodName)
	io.WriteString(w, ",")
	io.WriteString(w, r.SourcePodNamespace)
	io.WriteString(w, ",")
	io.WriteString(w, r.SourceNodeName)
	io.WriteString(w, ",")
	io.WriteString(w, r.DestinationPodName)
	io.WriteString(w, ",")
	io.WriteString(w, r.DestinationPodNamespace)
	io.WriteString(w, ",")
	io.WriteString(w, r.DestinationNodeName)
	io.WriteString(w, ",")
	io.WriteString(w, r.DestinationClusterIP)
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.DestinationServicePort))
	io.WriteString(w, ",")
	io.WriteString(w, r.DestinationServicePortName)
	io.WriteString(w, ",")
	io.WriteString(w, r.IngressNetworkPolicyName)
	io.WriteString(w, ",")
	io.WriteString(w, r.IngressNetworkPolicyNamespace)
	io.WriteString(w, ",")
	io.WriteString(w, r.IngressNetworkPolicyRuleName)
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.IngressNetworkPolicyRuleAction))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.IngressNetworkPolicyType))
	io.WriteString(w, ",")
	io.WriteString(w, r.EgressNetworkPolicyName)
	io.WriteString(w, ",")
	io.WriteString(w, r.EgressNetworkPolicyNamespace)
	io.WriteString(w, ",")
	io.WriteString(w, r.EgressNetworkPolicyRuleName)
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.EgressNetworkPolicyRuleAction))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.EgressNetworkPolicyType))
	io.WriteString(w, ",")
	io.WriteString(w, r.TcpState)
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.FlowType))
	io.WriteString(w, ",")
	// Enclose Pod labels with single quote because commas are used to separate
	// different columns in CSV and Pod labels json string contains commas.
	io.WriteString(w, fmt.Sprintf("'%s'", r.SourcePodLabels))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("'%s'", r.DestinationPodLabels))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.Throughput))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReverseThroughput))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ThroughputFromSourceNode))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ThroughputFromDestinationNode))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReverseThroughputFromSourceNode))
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", r.ReverseThroughputFromDestinationNode))
	io.WriteString(w, ",")
	io.WriteString(w, clusterUUID)
	io.WriteString(w, ",")
	io.WriteString(w, fmt.Sprintf("%d", time.Now().Unix()))
	io.WriteString(w, ",")
	io.WriteString(w, r.EgressName)
	io.WriteString(w, ",")
	io.WriteString(w, r.EgressIP)
	io.WriteString(w, ",")
	io.WriteString(w, r.AppProtocolName)
	io.WriteString(w, ",")
	io.WriteString(w, r.HttpVals)
	io.WriteString(w, ",")
	io.WriteString(w, r.EgressNodeName)
}
