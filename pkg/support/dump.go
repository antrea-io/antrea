package support

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

// AgentDumper is the interface for dumping runtime information of the agent. Its
// functions should only work in an agent Pod or a Windows Node which has an agent
// installed.
type AgentDumper interface {
	// DumpFlows should create files that contains flows under the basedir.
	DumpFlows(basedir string) error
	// DumpHostNetworkInfo should create files that contains host network
	// information under the basedir. Host network information should include
	// links, routes, addresses and etc.
	DumpHostNetworkInfo(basedir string) error
	// DumpLog should create files that contains container logs of the agent
	// Pod under the basedir.
	DumpLog(basedir string) error
	// DumpAgentInfo should create a file that contains AgentInfo of the agent Pod
	// under the basedir.
	DumpAgentInfo(basedir string) error
	// DumpNetworkPolicyResources should create files that contains networkpolicy
	// resources on the agent Pod under the base dir.
	DumpNetworkPolicyResources(basedir string) error
}

// ControllerDumper is the interface for dumping runtime information of the
// controller. Its functions should only work in the controller Pod.
type ControllerDumper interface {
	// DumpLog should create files that contains container logs of the controller
	// Pod under the basedir.
	DumpLog(basedir string) error
	// DumpControllerInfo should create a file that contains ControllerInfo of
	// the controller Pod under the basedir.
	DumpControllerInfo(basedir string) error
	// DumpNetworkPolicyResources should create files that contains networkpolicy
	// resources on the controller Pod under the base dir.
	DumpNetworkPolicyResources(basedir string) error
}

func dumpAntctlGet(fs afero.Fs, executor exec.Interface, name, basedir string) error {
	output, err := executor.Command("antctl", "-oyaml", "get", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when dumping %s: %w", name, err)
	}
	err = afero.WriteFile(fs, filepath.Join(basedir, name), output, 0644)
	if err != nil {
		return fmt.Errorf("error when writing %s dumps: %w", name, err)
	}
	return nil
}

func dumpNetworkPolicyResources(fs afero.Fs, executor exec.Interface, basedir string) error {
	if err := dumpAntctlGet(fs, executor, "networkpolicies", basedir); err != nil {
		return err
	}
	if err := dumpAntctlGet(fs, executor, "appliedtogroups", basedir); err != nil {
		return err
	}
	return dumpAntctlGet(fs, executor, "addressgroups", basedir)
}

// fileCopy copies files under the srcDir to the targetDir. Only files whose
// name matches the prefixFilter will be copied. Copied files will be located
// under the same relative path.
func fileCopy(fs afero.Fs, targetDir string, srcDir string, prefixFilter string) error {
	err := fs.MkdirAll(targetDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating target dir: %w", err)
	}
	return afero.Walk(fs, srcDir, func(filePath string, info os.FileInfo, err error) error {
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
		targetFile, err := fs.Create(targetPath)
		if err != nil {
			return err
		}
		defer targetFile.Close()
		srcFile, err := fs.Open(filePath)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		_, err = io.Copy(targetFile, srcFile)
		return err
	})
}

type controllerDumper struct {
	fs       afero.Fs
	executor exec.Interface
}

func (d *controllerDumper) DumpControllerInfo(basedir string) error {
	return dumpAntctlGet(d.fs, d.executor, "controllerinfo", basedir)
}

func (d *controllerDumper) DumpNetworkPolicyResources(basedir string) error {
	return dumpNetworkPolicyResources(d.fs, d.executor, basedir)
}

func (d *controllerDumper) DumpLog(basedir string) error {
	return fileCopy(d.fs, path.Join(basedir, "logs", "controller"), "/var/log/antrea", "antrea-controller")
}

func NewControllerDumper(fs afero.Fs, executor exec.Interface) ControllerDumper {
	return &controllerDumper{
		fs:       fs,
		executor: executor,
	}
}
