package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"k8s.io/utils/exec"

	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

type Dumper interface {
	DumpFlows(basedir string) error
	DumpIPTables(basedir string) error
	DumpIPToolInfo(basedir string) error
}

type ofctlClientFactory func(bridge string) ovsctl.OVSCtlClient

func NewDumper(fs afero.Fs, executor exec.Interface, factory ofctlClientFactory) Dumper {
	return &dumper{
		factory:  factory,
		fs:       fs,
		executor: executor,
	}
}

type dumper struct {
	factory  ofctlClientFactory
	fs       afero.Fs
	executor exec.Interface
}

func (d *dumper) DumpFlows(basedir string) error {
	brs, err := ovsctl.ListBridges(d.executor)
	if err != nil {
		return fmt.Errorf("error when collecting ovs bridge info: %w", err)
	}
	err = d.fs.Mkdir(filepath.Join(basedir, "flows"), os.ModePerm)
	if err != nil {
		return fmt.Errorf("error when creating flows output dir: %w", err)
	}
	for _, br := range brs {
		flows, err := d.factory(br).DumpFlows()
		if err != nil {
			return fmt.Errorf("error when dumping flows on bridge %s: %w", br, err)
		}
		err = afero.WriteFile(d.fs, filepath.Join(basedir, "flows", br), []byte(strings.Join(flows, "\n")), 0644)
		if err != nil {
			return fmt.Errorf("error when creating flows output file: %w", err)
		}
	}
	return nil
}

func (d *dumper) DumpIPTables(basedir string) error {
	iptablesOutput, err := d.executor.Command("iptables-save").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error when dumping iptables data: %w", err)
	}
	err = afero.WriteFile(d.fs, filepath.Join(basedir, "iptables"), iptablesOutput, 0644)
	if err != nil {
		return fmt.Errorf("error when writing iptables dumps: %w", err)
	}
	return nil
}

func (d *dumper) DumpIPToolInfo(basedir string) error {
	dump := func(name string) error {
		output, err := d.executor.Command("ip", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error when dumping %s: %w", name, err)
		}
		err = afero.WriteFile(d.fs, filepath.Join(basedir, name), output, 0644)
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
