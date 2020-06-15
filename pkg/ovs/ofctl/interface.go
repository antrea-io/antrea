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

package ofctl

// OfctlClient is an interface for "ovs-ofctl" operations.
type OfctlClient interface {
	// DumpFlows returns flows of the bridge.
	DumpFlows(args ...string) ([]string, error)
	// DumpMatchedFlows returns the flow which exactly matches the matchStr.
	DumpMatchedFlow(matchStr string) (string, error)
	// DumpTableFlows returns all flows in the table.
	DumpTableFlows(table uint8) ([]string, error)
	// DumpGroups returns OpenFlow groups of the bridge.
	DumpGroups(args ...string) ([][]string, error)
	// RunOfctlCmd executes "ovs-ofctl" command and returns the outputs.
	RunOfctlCmd(cmd string, args ...string) ([]byte, error)
}
