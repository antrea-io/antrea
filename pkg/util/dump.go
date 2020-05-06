package util

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"k8s.io/utils/exec"
)

type Dumper interface {
	DumpNetworkPolicies(basedir string) error
	DumpAppliedToGroups(basedir string) error
	DumpAddressGroups(basedir string) error
	DumpControllerInfo(basedir string) error
	DumpControllerLog(basedir string) error
	DumpAgentInfo(basedir string) error
	DumpAgentLog(basedir string) error
	DumpOVSLog(basedir string) error
}

func NewDumper(fs afero.Fs, executor exec.Interface) Dumper {
	return &dumper{
		fs:       fs,
		executor: executor,
	}
}

type dumper struct {
	fs       afero.Fs
	executor exec.Interface
}

func (d *dumper) dumpAntctlGet(name, basedir string) error {
	output, err := d.executor.Command("antctl", "-oyaml", "get", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when dumping %s: %w", name, err)
	}
	err = afero.WriteFile(d.fs, filepath.Join(basedir, name), output, 0644)
	if err != nil {
		return fmt.Errorf("error when writing %s dumps: %w", name, err)
	}
	return nil
}

func (d *dumper) DumpNetworkPolicies(basedir string) error {
	return d.dumpAntctlGet("networkpolicies", basedir)
}

func (d *dumper) DumpAppliedToGroups(basedir string) error {
	return d.dumpAntctlGet("appliedtogroups", basedir)
}

func (d *dumper) DumpAddressGroups(basedir string) error {
	return d.dumpAntctlGet("addressgroups", basedir)
}

func (d *dumper) DumpControllerInfo(basedir string) error {
	return d.dumpAntctlGet("controllerinfo", basedir)
}

func (d *dumper) DumpAgentInfo(basedir string) error {
	return d.dumpAntctlGet("agentinfo", basedir)
}

func (d *dumper) dumpLog(targetDir string, logDir string, prefixFilter string) error {
	err := d.fs.MkdirAll(targetDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating logs output dir: %w", err)
	}
	return afero.Walk(d.fs, logDir, func(filePath string, info os.FileInfo, err error) error {
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
		targetFile, err := d.fs.Create(targetPath)
		if err != nil {
			return err
		}
		defer targetFile.Close()
		logFile, err := d.fs.Open(filePath)
		if err != nil {
			return err
		}
		defer logFile.Close()
		_, err = io.Copy(targetFile, logFile)
		return err
	})
}

func (d *dumper) DumpAgentLog(basedir string) error {
	return d.dumpLog(path.Join(basedir, "logs", "agent"), "/var/log/antrea", "antrea-agent")
}

func (d *dumper) DumpControllerLog(basedir string) error {
	return d.dumpLog(path.Join(basedir, "logs", "controller"), "/var/log/antrea", "antrea-controller")
}

func (d *dumper) DumpOVSLog(basedir string) error {
	return d.dumpLog(path.Join(basedir, "logs", "ovs"), "/var/log/antrea", "ovs")
}
