// Copyright 2025 Antrea Authors
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

package filestore

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
)

// Set it to NewMemMapFs as the file system may be not writable.
// Change it to NewOsFs to evaluate performance when writing to disk.
// It's for testing only.
var newFS = afero.NewMemMapFs

type AnyObjectWithUID struct {
	UID    string
	Object any
}

type Serializer interface {
	Encode(obj any, w io.Writer) error
	Decode(data []byte, into *AnyObjectWithUID) error
}

type GobSerializer struct{}

func (j *GobSerializer) Encode(obj any, w io.Writer) error {
	return gob.NewEncoder(w).Encode(obj)
}

func (j *GobSerializer) Decode(data []byte, into *AnyObjectWithUID) error {
	dec := gob.NewDecoder(bytes.NewReader(data))
	return dec.Decode(into)
}

func NewFakeFileStore() *FileStore {
	gob.Register(&interfacestore.InterfaceConfig{})
	serializer := &GobSerializer{}
	fs := afero.NewBasePathFs(newFS(), "/var/run/antrea-test/file-store")
	s, _ := NewFileStore(fs, "sriov", serializer)
	return s
}

// FileStore encodes and stores golang objects in files. Each object will be stored in a
// separate file under the given directory.
type FileStore struct {
	fs afero.Fs
	// The directory to store the files.
	dir string
	// serializer knows how to encode and decode the objects.
	serializer Serializer
}

func NewFileStore(fs afero.Fs, dir string, serializer Serializer) (*FileStore, error) {
	s := &FileStore{
		fs:         fs,
		dir:        dir,
		serializer: serializer,
	}
	klog.V(2).InfoS("Creating directory for cache", "dir", dir)
	if err := s.fs.MkdirAll(dir, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// Save stores the given object in file with the object's UID as the file name, overwriting
// any existing content if the file already exists.
func (s FileStore) Save(item AnyObjectWithUID) error {
	path := filepath.Join(s.dir, item.UID)
	file, err := s.fs.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("error opening file for writing object %v: %w", item.UID, err)
	}
	defer file.Close()
	err = s.serializer.Encode(item, file)
	if err != nil {
		fmt.Printf("err %v", err)
		return fmt.Errorf("error writing object %v to file: %w", item.UID, err)
	}
	return nil
}

// Delete removes the file with the object's UID as the file name if it exists.
func (s FileStore) Delete(item AnyObjectWithUID) error {
	path := filepath.Join(s.dir, item.UID)
	err := s.fs.Remove(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// ReplaceAll replaces all files under the directory with the given objects. Existing files
// not in the given objects will be removed.
func (s FileStore) ReplaceAll(items []AnyObjectWithUID) error {
	if err := s.fs.RemoveAll(s.dir); err != nil {
		return err
	}
	if err := s.fs.MkdirAll(s.dir, 0o600); err != nil {
		return err
	}
	for _, item := range items {
		if err := s.Save(item); err != nil {
			return err
		}
	}
	return nil
}

func (s FileStore) LoadAll() ([]AnyObjectWithUID, error) {
	var objects []AnyObjectWithUID
	err := afero.Walk(s.fs, s.dir, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		file, err2 := s.fs.Open(path)
		if err2 != nil {
			return err2
		}
		defer file.Close()
		data, err2 := io.ReadAll(file)
		if err2 != nil {
			return err2
		}

		object := &AnyObjectWithUID{}
		err2 = s.serializer.Decode(data, object)
		// If the data is corrupted somehow, we still want to load other data and continue the process.
		if err2 != nil {
			klog.ErrorS(err2, "Failed to decode data from file, ignore it", "file", path)
			return nil
		}
		objects = append(objects, *object)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return objects, nil
}
