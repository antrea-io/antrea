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

	"github.com/spf13/afero"
)

// sanitizeExtractPath ensures that the target extract path (when joining the destination directory
// and the path from the archive) is within the intended destination directory.
// This is meant to address the "Zip Slip" vulnerability (G305).
// See https://security.snyk.io/research/zip-slip-vulnerability.
func sanitizeExtractPath(filePath string, destination string) (string, error) {
	// If IsLocal(path) returns true, then Join(base, path) will always produce a path contained
	// within base and Clean(path) will always produce an unrooted path with no ".." path
	// elements.
	// IsLocal was introduced in Go 1.20.
	// This will also reject absolute paths, which is not strictly required (e.g., tar can
	// produce such archives when it is run with -P).
	if !filepath.IsLocal(filePath) {
		return "", fmt.Errorf("illegal file path: %s", filePath)
	}
	// Join also calls Clean on the path.
	return filepath.Join(destination, filePath), nil
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
			// Note in particular that we do not handle symlinks.
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

		if header.Name, err = filepath.Rel(dir, filePath); err != nil {
			return err
		}
		if err := targzWriter.WriteHeader(header); err != nil {
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
