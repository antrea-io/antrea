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

package ftp

import (
	"fmt"
	"io"
	"net/url"
	"path"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
	"k8s.io/klog/v2"
)

const (
	uploadToFileServerTries      = 5
	uploadToFileServerRetryDelay = 5 * time.Second
)

func ParseFTPUploadUrl(uploadUrl string) (*url.URL, error) {
	parsedURL, err := url.Parse(uploadUrl)
	if err != nil {
		return nil, err
	}
	if parsedURL.Scheme != "sftp" {
		return nil, fmt.Errorf("not sftp protocol")
	}
	return parsedURL, nil
}

type Uploader interface {
	// Upload uploads a file to the target sftp address using ssh config.
	Upload(url string, fileName string, config *ssh.ClientConfig, outputFile afero.File) error
}

type SftpUploader struct {
}

func (uploader *SftpUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile afero.File) error {
	if _, err := outputFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to upload to file server while setting offset: %v", err)
	}
	// url should be like: 10.92.23.154:22/path or sftp://10.92.23.154:22/path
	parsedURL, _ := ParseFTPUploadUrl(url)
	joinedPath := path.Join(parsedURL.Path, fileName)

	triesLeft := uploadToFileServerTries
	var uploadErr error
	for triesLeft > 0 {
		if uploadErr = upload(parsedURL.Host, joinedPath, config, outputFile); uploadErr == nil {
			return nil
		}
		triesLeft--
		if triesLeft == 0 {
			return fmt.Errorf("failed to upload file after %d attempts", uploadToFileServerTries)
		}
		klog.InfoS("Failed to upload file", "UploadError", uploadErr, "TriesLeft", triesLeft)
		time.Sleep(uploadToFileServerRetryDelay)
	}
	return nil
}

func upload(address string, path string, config *ssh.ClientConfig, file io.Reader) error {
	conn, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("error when connecting to fs server: %w", err)
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
		return fmt.Errorf("error when creating target file on remote: %v", err)
	}
	defer func() {
		if err := targetFile.Close(); err != nil {
			klog.ErrorS(err, "Error when closing target file on remote")
		}
	}()
	if written, err := io.Copy(targetFile, file); err != nil {
		return fmt.Errorf("error when copying target file: %v, written: %d", err, written)
	}
	klog.InfoS("Successfully upload file to path", "filePath", path)
	return nil
}
