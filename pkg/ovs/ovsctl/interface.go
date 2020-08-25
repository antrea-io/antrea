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
	"net"
	"os/exec"
)

// TracingRequest defines tracing request parameters.
type TracingRequest struct {
	InPort string // Input port.
	SrcIP  net.IP
	DstIP  net.IP
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
	Flow   string
	// Whether in_port field in Flow can override InPort.
	AllowOverrideInPort bool
}

// OVSCtlClient is an interface for executing OVS "ovs-ofctl" and "ovs-appctl"
// commands.
type OVSCtlClient interface {
	// DumpFlows returns flows of the bridge.
	DumpFlows(args ...string) ([]string, error)
	// DumpMatchedFlows returns the flow which exactly matches the matchStr.
	DumpMatchedFlow(matchStr string) (string, error)
	// DumpTableFlows returns all flows in the table.
	DumpTableFlows(table uint8) ([]string, error)
	// DumpGroups returns OpenFlow groups of the bridge.
	DumpGroups(args ...string) ([][]string, error)
	// DumpPortsDesc returns OpenFlow ports descriptions of the bridge.
	DumpPortsDesc() ([][]string, error)
	// RunOfctlCmd executes "ovs-ofctl" command and returns the outputs.
	RunOfctlCmd(cmd string, args ...string) ([]byte, error)
	// SetPortNoFlood sets the given port with config "no-flood". This configuration must work with OpenFlow10.
	SetPortNoFlood(ofport int) error
	// Trace executes "ovs-appctl ofproto/trace" to perform OVS packet tracing.
	Trace(req *TracingRequest) (string, error)
	// RunAppctlCmd executes "ovs-appctl" command and returns the outputs.
	// Some commands are bridge specific and some are not. Passing a bool to distinguish that.
	RunAppctlCmd(cmd string, needsBridge bool, args ...string) ([]byte, *ExecError)
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

// GetErrorOutput returns the command's output to stderr if it has ben executed
// and exited with an error.
func (e *ExecError) GetErrorOutput() string {
	if !e.CommandExecuted() {
		return ""
	}
	return e.errorOutput
}
