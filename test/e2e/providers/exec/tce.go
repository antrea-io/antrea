package exec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
)

type TCECluster struct {
	Name      string
	Namespace string
	Status    string
}

// GetTCEControllerPlaneNodeName ...
func GetTCEControllerPlaneNodeName() (
	string, error,
) {

	args := []string{"cluster", "list", "-o", "json"}

	tceCmd := exec.Command("tanzu", args...)
	stdoutPipe, err := tceCmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("error when connecting to stdout: %v", err)
	}
	stderrPipe, err := tceCmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("error when connecting to stderr: %v", err)
	}
	if err := tceCmd.Start(); err != nil {
		return "", fmt.Errorf("error when starting command: %v", err)
	}

	stdoutBytes, _ := ioutil.ReadAll(stdoutPipe)
	stderrBytes, _ := ioutil.ReadAll(stderrPipe)

	if err := tceCmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", errors.New(string(stderrBytes))
		}
		return "", err
	}

	var clusters []TCECluster
	if err := json.Unmarshal(stdoutBytes, &clusters); err != nil {
		return "", err
	}

	if len(clusters) < 1 {
		return "", errors.New(fmt.Sprintf("no workload cluster found: %s", string(stderrBytes)))
	}

	return clusters[0].Name, nil

}
