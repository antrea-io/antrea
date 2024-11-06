// Copyright 2024 Antrea Authors.
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

package sftp

import (
	"fmt"
	"io"
	"net/url"
	"path"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"k8s.io/klog/v2"
)

const (
	uploadToFileServerMaxRetries = 5
	uploadToFileServerRetryDelay = 5 * time.Second
)

func ParseSFTPUploadUrl(uploadUrl string) (*url.URL, error) {
	parsedURL, err := url.Parse(uploadUrl)
	if err != nil {
		parsedURL, err = url.Parse("sftp://" + uploadUrl)
		if err != nil {
			return nil, err
		}
	}
	if parsedURL.Scheme != "sftp" {
		return nil, fmt.Errorf("not sftp protocol")
	}
	return parsedURL, nil
}

type Uploader interface {
	// Upload uploads a file to the target sftp address using ssh config.
	Upload(url string, fileName string, config *ssh.ClientConfig, outputFile io.Reader) error
}

type sftpUploader struct {
}

func NewUploader() Uploader {
	return &sftpUploader{}
}

func (uploader *sftpUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile io.Reader) error {
	// url should be like: 10.92.23.154:22/path or sftp://10.92.23.154:22/path
	parsedURL, err := ParseSFTPUploadUrl(url)
	if err != nil {
		return err
	}
	joinedPath := path.Join(parsedURL.Path, fileName)

	retries := 0
	var uploadErr error
	for {
		if uploadErr = upload(parsedURL.Host, joinedPath, config, outputFile); uploadErr == nil {
			return nil
		}
		retries++
		if retries >= uploadToFileServerMaxRetries {
			return fmt.Errorf("failed to upload file after %d attempts", uploadToFileServerMaxRetries)
		}
		klog.ErrorS(uploadErr, "Failed to upload file after retries", "retries", retries)
		time.Sleep(uploadToFileServerRetryDelay)
	}
}

func upload(address string, path string, config *ssh.ClientConfig, file io.Reader) error {
	conn, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("error when connecting to the file server: %w", err)
	}
	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("error when setting up sftp client: %w", err)
	}
	defer func() {
		if err := sftpClient.Close(); err != nil {
			klog.ErrorS(err, "Error when closing sftp client")
		}
	}()
	targetFile, err := sftpClient.Create(path)
	if err != nil {
		return fmt.Errorf("error when creating target file on the remote server: %w", err)
	}
	defer func() {
		if err := targetFile.Close(); err != nil {
			klog.ErrorS(err, "Error when closing target file on the remote server")
		}
	}()
	if written, err := io.Copy(targetFile, file); err != nil {
		return fmt.Errorf("error encountered after copying %d bytes to target file: %w", written, err)
	}
	klog.InfoS("Successfully uploaded file to path", "filePath", path)
	return nil
}
