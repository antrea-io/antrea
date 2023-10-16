// Copyright 2020 Antrea Authors
//
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

package ovsctl

import (
	"fmt"
	"os/exec"
)

type OVSAppctlRunner interface {
	RunAppctlCmd(cmd string, needsBridge bool, args ...string) ([]byte, error)
}

type OVSOfctlRunner interface {
	RunOfctlCmd(cmd string, args ...string) ([]byte, error)
}

type OVSCtlClient interface {
	OVSOfctlRunner
	OVSAppctlRunner
	// DumpFlows returns flows of the bridge.
	DumpFlows(args ...string) ([]string, error)
	// DumpFlowsWithoutTableNames returns flows of the bridge, and the table is shown as uint8 value in the result.
	// This function is only used in test.
	DumpFlowsWithoutTableNames(args ...string) ([]string, error)
	// DumpMatchedFlows returns the flow which exactly matches the matchStr.
	DumpMatchedFlow(matchStr string) (string, error)
	// DumpTableFlows returns all flows in the table.
	DumpTableFlows(table uint8) ([]string, error)
	// DumpGroup returns the OpenFlow group if it exists on the bridge.
	DumpGroup(groupID uint32) (string, error)
	// DumpGroups returns OpenFlow groups of the bridge.
	DumpGroups() ([]string, error)
	// DumpPortsDesc returns OpenFlow ports descriptions of the bridge.
	DumpPortsDesc() ([][]string, error)
	// SetPortNoFlood sets the given port with config "no-flood". This configuration must work with OpenFlow10.
	SetPortNoFlood(ofport int) error
	// Trace executes "ovs-appctl ofproto/trace" to perform OVS packet tracing.
	Trace(req *TracingRequest) (string, error)
	// GetDPFeatures executes "ovs-appctl dpif/show-dp-features" to check supported DP features.
	GetDPFeatures() (map[DPFeature]bool, error)
	// DeleteDPInterface executes "ovs-appctl dpctl/del-if ovs-system $name" to delete OVS datapath interface.
	DeleteDPInterface(name string) error
}

type BadRequestError string

func (e BadRequestError) Error() string {
	return string(e)
}

// ExecError is for errors happened in command execution.
type ExecError struct {
	error
	// stderr output.
	errorOutput string
}

// CommandExecuted returns whether the OVS command has been executed.
func (e *ExecError) CommandExecuted() bool {
	exit, ok := e.error.(*exec.ExitError)
	return ok && exit.ExitCode() != exitCodeCommandNotFound
}

// GetErrorOutput returns the command's output to stderr if it has been executed
// and exited with an error.
func (e *ExecError) GetErrorOutput() string {
	if !e.CommandExecuted() {
		return ""
	}
	return e.errorOutput
}

func (e *ExecError) Error() string {
	return fmt.Sprintf("ExecError: %v, output: %s", e.error, e.errorOutput)
}
