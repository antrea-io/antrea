// Copyright 2025 Antrea Authors.
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

package packetcapture

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	_ "unsafe"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type PodFileCopy interface {
	CopyFromPod(ctx context.Context, namespace, name, containerName, srcPath, dstDir string) error
}

type podFile struct {
	restConfig    *rest.Config
	restInterface rest.Interface
}

func (p *podFile) CopyFromPod(ctx context.Context, namespace, name, containerName, srcPath, dstDir string) error {
	reader, outStream := io.Pipe()
	cmdArr := []string{"tar", "cf", "-", srcPath}
	req := p.restInterface.
		Get().
		Namespace(namespace).
		Resource("pods").
		Name(name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmdArr,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(p.restConfig, "POST", req.URL())
	if err != nil {
		return err
	}
	go func() {
		defer outStream.Close()
		err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  os.Stdin,
			Stdout: outStream,
			Stderr: os.Stderr,
			Tty:    false,
		})
		if err != nil {
			panic(err)
		}
	}()
	err = untarAll(reader, dstDir)
	return err
}

// TODO: wait for https://github.com/antrea-io/antrea/pull/3659 got merged and reuse its function.
// nolint: gosec
func untarAll(reader io.Reader, dstDir string) error {
	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		baseName := filepath.Base(header.Name)
		outFile, err := defaultFS.Create(filepath.Join(dstDir, baseName))
		if err != nil {
			return err
		}
		defer outFile.Close()
		if _, err := io.Copy(outFile, tarReader); err != nil {
			return err
		}
	}
	return nil
}
