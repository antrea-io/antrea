//go:build windows
// +build windows

//Copyright 2021 Antrea Authors
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

package powershell

import (
	"fmt"
	"os/exec"
)

func RunCommand(cmd string) (string, error) {
	// The try/catch command idea is from the following page:
	// https://stackoverflow.com/questions/19282870/how-can-i-use-try-catch-and-get-my-script-to-stop-if-theres-an-error/19285405
	psCmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$ErrorActionPreference="Stop";try {%s} catch {Write-Host $_;os.Exit(1)}`, cmd)) // #nosec G204
	stdout, err := psCmd.Output()
	stdoutStr := string(stdout)
	if err != nil {
		return "", fmt.Errorf("failed to run command '%s': output '%s', %v", cmd, stdoutStr, err)
	}
	return stdoutStr, nil
}
