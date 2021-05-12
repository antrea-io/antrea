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

package antctl

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	antreaversion "antrea.io/antrea/pkg/version"
)

var (
	serverError = fmt.Errorf("cannot reach server")
)

// TestCommandListValidation ensures the command list is valid.
func TestCommandListValidation(t *testing.T) {
	errs := CommandList.validate()
	assert.Len(t, errs, 0)
}

// TestCommandVersionRequestError verifies that even when the request to the
// server fails, the version of the antctl client is still output (along with
// the error message).
func TestCommandVersionRequestError(t *testing.T) {
	// This setup code can be moved to a separate function if more tests
	// like this one are written.
	rootCmd := &cobra.Command{
		Use: "antctl",
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := NewMockAntctlClient(ctrl)
	var bufOut bytes.Buffer
	CommandList.applyToRootCommand(rootCmd, client, &bufOut)

	client.EXPECT().request(gomock.Any()).Return(nil, serverError)

	rootCmd.SetOut(&bufOut)
	rootCmd.SetErr(&bufOut)
	rootCmd.SetArgs([]string{"version"})
	rootCmd.Execute()
	expected := fmt.Sprintf("antctlVersion: %s", antreaversion.GetFullVersion())
	assert.Contains(t, bufOut.String(), expected)
	assert.Contains(t, bufOut.String(), serverError.Error())
}

// TestExtraArgs ensures that there will be an error if extra positional
// arguments are passed to the traceflow command.
func TestExtraArgs(t *testing.T) {
	cmd := &cobra.Command{
		Use: "antctl",
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := NewMockAntctlClient(ctrl)
	var bufOut bytes.Buffer
	CommandList.applyToRootCommand(cmd, client, os.Stdout)

	extraArg := "icmp"
	cmd.SetOut(&bufOut)
	cmd.SetErr(&bufOut)
	cmd.SetArgs([]string{"traceflow", "-S", "pod1", "-D", "pod2", extraArg})
	cmd.Execute()
	assert.Contains(t, bufOut.String(), fmt.Sprintf("unknown command %q for", extraArg))
}
