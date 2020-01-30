package util

import (
	"bytes"
	"fmt"
)
import "os/exec"

type kubectl struct {
	kubeconfig string
}

func NewKubeCtl(kubeconfig string) *kubectl {
	return &kubectl{kubeconfig: kubeconfig}
}

func (c *kubectl) IsPresent() error {
	cmd := exec.Command("kubectl", fmt.Sprintf("--kubeconfig=%s", c.kubeconfig), "version")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubeclt check failed, err %w, output %v", err, output)
	}
	return nil
}

func (c *kubectl) Apply(content []byte) error {
	if err := c.IsPresent(); err != nil {
		return err
	}
	cmd := exec.Command("kubectl", fmt.Sprintf("--kubeconfig=%s", c.kubeconfig), "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(content)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubeclt apply failed, err %w, output %s", err, string(output))
	}
	return nil
}

func (c *kubectl) Delete(content []byte) error {
	if err := c.IsPresent(); err != nil {
		return err
	}
	cmd := exec.Command("kubectl", fmt.Sprintf("--kubeconfig=%s", c.kubeconfig), "delete", "-f", "-")
	cmd.Stdin = bytes.NewReader(content)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubeclt delete failed, err %w, output %s", err, output)
	}
	return nil
}

func (c *kubectl) Patch(content []byte, kind, name string) error {
	if err := c.IsPresent(); err != nil {
		return err
	}
	cmd := exec.Command("kubectl", fmt.Sprintf("--kubeconfig=%s", c.kubeconfig), "patch", kind, name, "-p", string(content))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubeclt patch failed, err %w, output %s", err, output)
	}
	return nil
}
