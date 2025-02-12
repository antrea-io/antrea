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
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/antctl/raw/check"
	"antrea.io/antrea/pkg/util/compress"
	"antrea.io/antrea/pkg/util/env"
)

type PodFileCopy interface {
	CopyFromPod(ctx context.Context, namespace, name, containerName, srcPath, dstDir string) error
}

type podFile struct {
	restConfig *rest.Config
	client     kubernetes.Interface
}

func (p *podFile) CopyFromPod(ctx context.Context, namespace, name, containerName, srcPath, dstDir string) error {
	dir, fileName := filepath.Split(srcPath)
	cmdArr := []string{"/bin/sh", "-c", fmt.Sprintf("cd %s; tar cf - %s", dir, fileName)}
	output, _, err := check.ExecInPod(ctx, p.client, p.restConfig, env.GetAntreaNamespace(), name, "antrea-agent", cmdArr)
	if err != nil {
		return err
	}
	return compress.UnpackReader(defaultFS, strings.NewReader(output), false, option.outputDir)
}
