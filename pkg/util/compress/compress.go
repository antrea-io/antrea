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

package compress

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

// Sanitize archive file pathing from "G305: Zip Slip vulnerability"
func sanitizeExtractPath(filePath string, destination string) (string, error) {
	destPath := filepath.Join(destination, filePath) // result will be "clean"
	destDir := filepath.Clean(destination)
	// As a special case, if destDir is the current working directory (as "."), we just check that
	// the extract path matches the path in the archive. This is because when calling Join with "."
	// as the directory, the leading "./" is removed, which is not handled correctly by the general
	// case (prefix check) below.
	if destDir == "." && filePath == destPath {
		return destPath, nil
	}
	if strings.HasPrefix(destPath, destDir+string(filepath.Separator)) {
		return destPath, nil
	}
	return "", fmt.Errorf("illegal file path: %s", filePath)
}

func UnpackDir(fs afero.Fs, fileName string, targetDir string) error {
	file, err := fs.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	return UnpackReader(fs, file, true, targetDir)
}

func UnpackReader(fs afero.Fs, file io.Reader, useGzip bool, targetDir string) error {
	reader := file
	var err error
	var gzipReader *gzip.Reader
	if useGzip {
		gzipReader, err = gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		targetPath, err := sanitizeExtractPath(header.Name, targetDir)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := fs.Mkdir(targetPath, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			outFile, err := fs.Create(targetPath)
			if err != nil {
				return err
			}
			defer outFile.Close()
			for {
				// to resolve G110: Potential DoS vulnerability via decompression bomb
				if _, err := io.CopyN(outFile, tarReader, 1024); err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
			}
		default:
			return errors.New("unknown type found when reading tgz file")
		}
	}
	return nil
}

func PackDir(fs afero.Fs, dir string, writer io.Writer) ([]byte, error) {
	hash := sha256.New()
	gzWriter := gzip.NewWriter(io.MultiWriter(hash, writer))
	targzWriter := tar.NewWriter(gzWriter)
	err := afero.Walk(fs, dir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.IsDir() {
			return nil
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}
		header.Name = strings.TrimPrefix(strings.ReplaceAll(filePath, dir, ""), string(filepath.Separator))
		err = targzWriter.WriteHeader(header)
		if err != nil {
			return err
		}
		f, err := fs.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(targzWriter, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	targzWriter.Close()
	gzWriter.Close()
	return hash.Sum(nil), nil
}
