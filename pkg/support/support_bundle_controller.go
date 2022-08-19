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

package support

import (
	"fmt"
	"io"
	"k8s.io/utils/exec"
	"net/http"
	"strconv"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/compress"
	"github.com/spf13/afero"
)

type SupportBundleController struct {
	ovsCtlClient ovsctl.OVSCtlClient
	aq           agentquerier.AgentQuerier
	npq          querier.AgentNetworkPolicyInfoQuerier
	v4Enabled    bool
	v6Enabled    bool
}

func NewSupportBundleController(ovsCtlClient ovsctl.OVSCtlClient, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, v4Enabled, v6Enabled bool) *SupportBundleController {
	c := &SupportBundleController{
		ovsCtlClient: ovsCtlClient,
		aq:           aq,
		npq:          npq,
		v4Enabled:    v4Enabled,
		v6Enabled:    v6Enabled,
	}
	return c
}

// TODO: watcher to watch controller internal object
func (c *SupportBundleController) generateSupportBundle(since string, server BundleServer) error {
	defaultFS := afero.NewOsFs()
	defaultExecutor := exec.New()
	basedir, err := afero.TempDir(defaultFS, "", "bundle_tmp_")
	if err != nil {
		return fmt.Errorf("error when creating tempdir: %w", err)
	}
	defer defaultFS.RemoveAll(basedir)

	dumper := NewAgentDumper(defaultFS, defaultExecutor, c.ovsCtlClient, c.aq, c.npq, since, c.v4Enabled, c.v6Enabled)
	if err = dumper.DumpLog(basedir); err != nil {
		return err
	}
	if err = dumper.DumpHostNetworkInfo(basedir); err != nil {
		return err
	}
	if err = dumper.DumpFlows(basedir); err != nil {
		return err
	}
	if err = dumper.DumpNetworkPolicyResources(basedir); err != nil {
		return err
	}
	if err = dumper.DumpAgentInfo(basedir); err != nil {
		return err
	}
	if err = dumper.DumpHeapPprof(basedir); err != nil {
		return err
	}
	if err = dumper.DumpOVSPorts(basedir); err != nil {
		return err
	}

	outputFile, err := afero.TempFile(defaultFS, "", "bundle_*.tar.gz")
	if err != nil {
		return fmt.Errorf("error when creating output tarfile: %w", err)
	}
	defer outputFile.Close()

	if _, err = compress.PackDir(basedir, outputFile); err != nil {
		return fmt.Errorf("error when packaging support bundle: %w", err)
	}
	if err = c.uploadToBundleServer(outputFile, server); err != nil {
		return fmt.Errorf("failed to upload support bundle to server: %w", err)
	}
	// TODO: update status
	return nil
}

type BundleServer struct {
	Address  string
	Port     int
	Path     string
	Protocol BundleUploadProtocol
	Verb     string
}

type BundleUploadProtocol string

const (
	HTTP  BundleUploadProtocol = "http"
	HTTPS BundleUploadProtocol = "https"
)

func (c *SupportBundleController) uploadToBundleServer(file io.Reader, server BundleServer) error {
	url := string(server.Protocol) + "://" + server.Address + ":" + strconv.Itoa(server.Port) + "/" + server.Path
	req, err := http.NewRequest(server.Verb, url, file)
	if err != nil {
		return fmt.Errorf("failed to generate HTTP request, err: %w", err)
	}
	// TODO: Get APIKey from controller
	var APIKey string
	req.SetBasicAuth("api", APIKey)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed, err: %w", err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	return nil
}
