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

package main

import (
	"os"
	"path"

	"github.com/spf13/cobra"

	"antrea.io/antrea/pkg/antctl"
	"antrea.io/antrea/pkg/log"
)

var commandName = path.Base(os.Args[0])

var rootCmd = &cobra.Command{
	Use:   commandName,
	Short: commandName + " is the command line tool for Antrea",
	Long:  commandName + " is the command line tool for Antrea that supports showing status of ${component}",
}

func main() {
	defer log.FlushLogs()

	antctl.CommandList.ApplyToRootCommand(rootCmd)
	err := rootCmd.Execute()
	if err != nil {
		log.FlushLogs()
		os.Exit(1)
	}
}
