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
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/options"
	"antrea.io/antrea/pkg/flowaggregator/s3uploader"
)

type S3Exporter struct {
	s3Input         *s3uploader.S3Input
	s3UploadProcess *s3uploader.S3UploadProcess
}

func buildS3Input(opt *options.Options) s3uploader.S3Input {
	return s3uploader.S3Input{
		Config:         opt.Config.S3Uploader,
		UploadInterval: opt.S3UploadInterval,
	}
}

func NewS3Exporter(k8sClient kubernetes.Interface, opt *options.Options) (*S3Exporter, error) {
	s3Input := buildS3Input(opt)
	klog.InfoS("S3Uploader configuration", "bucketName", s3Input.Config.BucketName, "bucketPrefix", s3Input.Config.BucketPrefix, "region", s3Input.Config.Region, "recordFormat", s3Input.Config.RecordFormat, "compress", *s3Input.Config.Compress, "maxRecordsPerFile", s3Input.Config.MaxRecordsPerFile, "uploadInterval", s3Input.UploadInterval)
	clusterUUID, err := getClusterUUID(k8sClient)
	if err != nil {
		return nil, err
	}
	s3UploadProcess, err := s3uploader.NewS3UploadProcess(s3Input, clusterUUID.String())
	if err != nil {
		return nil, err
	}
	return &S3Exporter{
		s3Input:         &s3Input,
		s3UploadProcess: s3UploadProcess,
	}, nil
}

func (e *S3Exporter) AddRecord(record ipfixentities.Record, isRecordIPv6 bool) error {
	e.s3UploadProcess.CacheRecord(record)
	return nil
}

func (e *S3Exporter) Start() {
	e.s3UploadProcess.Start()
}

func (e *S3Exporter) Stop() {
	e.s3UploadProcess.Stop()
}

func (e *S3Exporter) UpdateOptions(opt *options.Options) {
	s3Input := buildS3Input(opt)
	config := s3Input.Config
	if config.BucketName == e.s3UploadProcess.GetBucketName() &&
		config.BucketPrefix == e.s3UploadProcess.GetBucketPrefix() &&
		config.Region == e.s3UploadProcess.GetRegion() &&
		s3Input.UploadInterval == e.s3UploadProcess.GetUploadInterval() {
		return
	}
	klog.InfoS("Updating S3Uploader")
	if s3Input.UploadInterval != e.s3UploadProcess.GetUploadInterval() {
		e.s3UploadProcess.SetUploadInterval(s3Input.UploadInterval)
	}
	if config.BucketName != e.s3UploadProcess.GetBucketName() ||
		config.BucketPrefix != e.s3UploadProcess.GetBucketPrefix() ||
		config.Region != e.s3UploadProcess.GetRegion() {
		err := e.s3UploadProcess.UpdateS3Uploader(config.BucketName, config.BucketPrefix, config.Region)
		if err != nil {
			klog.ErrorS(err, "Error when updating S3Uploader config")
			return
		}
	}
	klog.InfoS("New S3Uploader configuration", "bucketName", s3Input.Config.BucketName, "bucketPrefix", s3Input.Config.BucketPrefix, "region", s3Input.Config.Region, "recordFormat", s3Input.Config.RecordFormat, "compress", *s3Input.Config.Compress, "maxRecordsPerFile", s3Input.Config.MaxRecordsPerFile, "uploadInterval", s3Input.Config.UploadInterval)
}
