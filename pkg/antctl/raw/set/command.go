// Copyright 2022 Antrea Authors
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

package set

import (
	"github.com/spf13/cobra"

	flowaggregator "antrea.io/antrea/pkg/antctl/raw/set/flowaggregator"
)

var SetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set configuration parameters",
}

func init() {
	SetCmd.AddCommand(flowaggregator.NewFlowAggregatorSetCommand())
}
