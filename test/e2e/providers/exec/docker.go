// Copyright 2019 Antrea Authors
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

package exec

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// TODO: we could use the Docker Go SDK for this, but it seems like a big dependency to pull in just
// to run some "docker exec" commands.

// RunDockerExecCommand runs the provided command on the specified host using "docker exec". Returns
// the exit code of the command, along with the contents of stdout and stderr as strings. Note that
// if the command returns a non-zero error code, this function does not report it as an error.
func RunDockerExecCommand(container, cmd, workdir string, envs map[string]string, stdin string) (
	code int, stdout string, stderr string, err error,
) {
	args := []string{"exec"}
	// Set environment variables.
	for e, v := range envs {
		args = append(args, "-e", e+"="+v)
	}
	if stdin != "" {
		// Interactive mode to get input from stdin.
		args = append(args, "-i")
	}
	args = append(args, "-w", workdir, container)

	if strings.Contains(cmd, "/bin/sh") {
		// Just split in to "/bin/sh" "-c" and "actual_cmd"
		// This is useful for passing piped commands in to os/exec interface.
		args = append(args, strings.SplitN(cmd, " ", 3)...)
	} else {
		args = append(args, strings.Fields(cmd)...)
	}

	dockerCmd := exec.Command("docker", args...)

	stdoutPipe, err := dockerCmd.StdoutPipe()
	if err != nil {
		return 0, "", "", fmt.Errorf("error when connecting to stdout: %v", err)
	}
	stderrPipe, err := dockerCmd.StderrPipe()
	if err != nil {
		return 0, "", "", fmt.Errorf("error when connecting to stderr: %v", err)
	}
	if stdin != "" {
		stdinPipe, err := dockerCmd.StdinPipe()
		if err != nil {
			return 0, "", "", fmt.Errorf("error when connecting to stdin: %v", err)
		}
		_, err = io.WriteString(stdinPipe, stdin)
		stdinPipe.Close()
		if err != nil {
			return 0, "", "", fmt.Errorf("error when writing to stdin: %v", err)
		}
	}

	if err := dockerCmd.Start(); err != nil {
		return 0, "", "", fmt.Errorf("error when starting command: %v", err)
	}
	var stdoutBytes, stderrBytes []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		stdoutBytes, _ = io.ReadAll(stdoutPipe)
	}()
	go func() {
		defer wg.Done()
		stderrBytes, _ = io.ReadAll(stderrPipe)
	}()
	wg.Wait()

	if err := dockerCmd.Wait(); err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return e.ExitCode(), string(stdoutBytes), string(stderrBytes), nil
		}
		return 0, "", "", err
	}

	// command is successful
	return 0, string(stdoutBytes), string(stderrBytes), nil
}

// RunDockerPsFilterCommand runs the provided command on the specified host using "docker ps filter". Returns
// the exit code of the command, along with the contents of stdout and stderr as strings.
func RunDockerPsFilterCommand(filter string) (
	code int, stdout string, stderr string, err error,
) {
	args := []string{"ps", "--filter", filter}
	dockerCmd := exec.Command("docker", args...)
	stdoutPipe, err := dockerCmd.StdoutPipe()
	if err != nil {
		return 0, "", "", fmt.Errorf("error when connecting to stdout: %v", err)
	}
	stderrPipe, err := dockerCmd.StderrPipe()
	if err != nil {
		return 0, "", "", fmt.Errorf("error when connecting to stderr: %v", err)
	}
	if err := dockerCmd.Start(); err != nil {
		return 0, "", "", fmt.Errorf("error when starting command: %v", err)
	}

	stdoutBytes, _ := io.ReadAll(stdoutPipe)
	stderrBytes, _ := io.ReadAll(stderrPipe)

	if err := dockerCmd.Wait(); err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return e.ExitCode(), string(stdoutBytes), string(stderrBytes), nil
		}
		return 0, "", "", err
	}

	// command is successful
	return 0, string(stdoutBytes), string(stderrBytes), nil
}
