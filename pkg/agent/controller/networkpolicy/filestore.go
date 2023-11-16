// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
)

// fileStore encodes and stores runtime.Objects in files. Each object will be stored in a separate file under the given
// directory.
type fileStore struct {
	fs afero.Fs
	// The directory to store the files.
	dir string
	// serializer knows how to encode and decode the objects.
	serializer runtime.Serializer
}

func newFileStore(fs afero.Fs, dir string, serializer runtime.Serializer) (*fileStore, error) {
	s := &fileStore{
		fs:         fs,
		dir:        dir,
		serializer: serializer,
	}
	klog.V(2).InfoS("Creating directory for NetworkPolicy cache", "dir", dir)
	if err := s.fs.MkdirAll(dir, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// save stores the given object in file with the object's UID as the file name, overwriting any existing content if the
// file already exists. Note the method may update the object's GroupVersionKind in-place during serialization.
func (s fileStore) save(item runtime.Object) error {
	object := item.(metav1.Object)
	path := filepath.Join(s.dir, string(object.GetUID()))
	file, err := s.fs.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("error opening file for writing object %v: %w", object.GetUID(), err)
	}
	defer file.Close()
	// Encode may update the object's GroupVersionKind in-place during serialization.
	err = s.serializer.Encode(item, file)
	if err != nil {
		return fmt.Errorf("error writing object %v to file: %w", object.GetUID(), err)
	}
	return nil
}

// delete removes the file with the object's UID as the file name if it exists.
func (s fileStore) delete(item runtime.Object) error {
	object := item.(metav1.Object)
	path := filepath.Join(s.dir, string(object.GetUID()))
	err := s.fs.Remove(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// replaceAll replaces all files under the directory with the given objects. Existing files not in the given objects
// will be removed. Note the method may update the object's GroupVersionKind in-place during serialization.
func (s fileStore) replaceAll(items []runtime.Object) error {
	if err := s.fs.RemoveAll(s.dir); err != nil {
		return err
	}
	if err := s.fs.MkdirAll(s.dir, 0o600); err != nil {
		return err
	}
	for _, item := range items {
		if err := s.save(item); err != nil {
			return err
		}
	}
	return nil
}

func (s fileStore) loadAll() ([]runtime.Object, error) {
	var objects []runtime.Object
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

		object, gkv, err2 := s.serializer.Decode(data, nil, nil)
		// If the data is corrupted somehow, we still want to load other data and continue the process.
		if err2 != nil {
			klog.ErrorS(err2, "Failed to decode data from file, ignore it", "file", path)
			return nil
		}
		// Note: we haven't stored a different version so far but version conversion should be performed when the used
		// version is upgraded in the future.
		klog.V(2).InfoS("Loaded object from file", "gkv", gkv, "object", object)
		objects = append(objects, object)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return objects, nil
}
