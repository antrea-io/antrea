// Copyright 2020 Antrea Authors
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

package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

func dumpFlows(basedir string) error {
	brListOutput, err := defaultExecutor.Command("ovs-vsctl", "list-br").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when collecting ovs bridge info: %w", err)
	}
	err = defaultFS.Mkdir(filepath.Join(basedir, "flows"), os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating flows output dir: %w", err)
	}
	for _, brName := range strings.Split(strings.TrimSpace(string(brListOutput)), "\n") {
		dumpFlowOutput, err := defaultExecutor.Command("ovs-ofctl", "dump-flows", brName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping flows on bridge %s: %w", brName, err)
		}
		err = afero.WriteFile(defaultFS, filepath.Join(basedir, "flows", brName), dumpFlowOutput, 0644)
		if err != nil {
			return fmt.Errorf("error when creating flows output file: %w", err)
		}
	}
	return nil
}

func dumpIPTables(basedir string) error {
	iptablesOutput, err := defaultExecutor.Command("iptables-save").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when dumping iptables data: %w", err)
	}
	err = afero.WriteFile(defaultFS, filepath.Join(basedir, "iptables"), iptablesOutput, 0644)
	if err != nil {
		return fmt.Errorf("error when writing iptables dumps: %w", err)
	}
	return nil
}

func dumpAntctlGet(name, basedir string) error {
	output, err := defaultExecutor.Command("antctl", "-oyaml", "get", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when dumping %s: %w", name, err)
	}
	err = afero.WriteFile(defaultFS, filepath.Join(basedir, name), output, 0644)
	if err != nil {
		return fmt.Errorf("error when writing %s dumps: %w", name, err)
	}
	return nil
}

func dumpNetworkPolicies(basedir string) error {
	return dumpAntctlGet("networkpolicies", basedir)
}

func dumpAppliedToGroups(basedir string) error {
	return dumpAntctlGet("appliedtogroups", basedir)
}

func dumpAddressGroups(basedir string) error {
	return dumpAntctlGet("addressgroups", basedir)
}

func dumpControllerInfo(basedir string) error {
	return dumpAntctlGet("controllerinfo", basedir)
}

func dumpAgentInfo(basedir string) error {
	return dumpAntctlGet("agentinfo", basedir)
}

func dumpLog(targetDir string, logDir string, prefixFilter string) error {
	err := defaultFS.MkdirAll(targetDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating logs output dir: %w", err)
	}
	return afero.Walk(defaultFS, logDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if !strings.HasPrefix(info.Name(), prefixFilter) {
			return nil
		}
		targetPath := path.Join(targetDir, info.Name())
		targetFile, err := defaultFS.Create(targetPath)
		if err != nil {
			return err
		}
		defer targetFile.Close()
		logFile, err := defaultFS.Open(filePath)
		if err != nil {
			return err
		}
		defer logFile.Close()
		_, err = io.Copy(targetFile, logFile)
		return err
	})
}

func dumpAgentLog(basedir string) error {
	return dumpLog(path.Join(basedir, "logs", "agent"), "/var/log/antrea", "antrea-agent")
}

func dumpControllerLog(basedir string) error {
	return dumpLog(path.Join(basedir, "logs", "controller"), "/var/log/antrea", "antrea-controller")
}

func dumpOVSLog(basedir string) error {
	return dumpLog(path.Join(basedir, "logs", "ovs"), "/var/log/antrea", "ovs")
}

func dumpIPToolInfo(basedir string) error {
	dump := func(name string) error {
		output, err := defaultExecutor.Command("ip", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", name, err)
		}
		err = afero.WriteFile(defaultFS, filepath.Join(basedir, name), output, 0644)
		if err != nil {
			return fmt.Errorf("error when writing %s: %w", name, err)
		}
		return nil
	}
	for _, item := range []string{"route", "link", "address"} {
		if err := dump(item); err != nil {
			return err
		}
	}
	return nil
}

func packDir(dir string, writer io.Writer) ([]byte, error) {
	hash := sha256.New()
	gzWriter := gzip.NewWriter(io.MultiWriter(hash, writer))
	targzWriter := tar.NewWriter(gzWriter)
	err := afero.Walk(defaultFS, dir, func(filePath string, info os.FileInfo, err error) error {
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
		f, err := defaultFS.Open(filePath)
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
