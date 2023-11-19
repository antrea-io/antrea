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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process

package e2e

import (
	"flag"
	"log"
	"os"
	"path"
	"testing"

	antreae2e "antrea.io/antrea/test/e2e"
)

type TestOptions struct {
	logsExportDir    string
	enableAntreaIPAM bool
	skipCases        string
	linuxVMs         string
}

var e2edata *antreae2e.TestData
var testOptions TestOptions
var homeDir, _ = os.UserHomeDir()

// setupLogging creates a temporary directory to export the test logs if necessary. If a directory
// was provided by the user, it checks that the directory exists.
func (tOptions *TestOptions) setupLogging() func() {
	if tOptions.logsExportDir == "" {
		name, err := os.MkdirTemp("", "antrea-e2e-secondary-test-")
		if err != nil {
			log.Fatalf("Error when creating temporary directory to export logs: %v", err)
		}
		log.Printf("Test logs (if any) will be exported under the '%s' directory", name)
		tOptions.logsExportDir = name
		// we will delete the temporary directory if no logs are exported
		return func() {
			if empty, _ := antreae2e.IsDirEmpty(name); empty {
				log.Printf("Removing empty logs directory '%s'", name)
				_ = os.Remove(name)
			} else {
				log.Printf("Logs exported under '%s', it is your responsibility to delete the directory when you no longer need it", name)
			}
		}
	}
	fInfo, err := os.Stat(tOptions.logsExportDir)
	if err != nil {
		log.Fatalf("Cannot stat provided directory '%s': %v", tOptions.logsExportDir, err)
	}
	if !fInfo.Mode().IsDir() {
		log.Fatalf("'%s' is not a valid directory", tOptions.logsExportDir)
	}
	// no-op cleanup function
	return func() {}
}

func testMain(m *testing.M) int {
	flag.StringVar(&testOptions.logsExportDir, "logs-export-dir", "", "Export directory for test logs")
	flag.BoolVar(&testOptions.enableAntreaIPAM, "antrea-ipam", false, "Run tests with AntreaIPAM")
	flag.StringVar(&testOptions.skipCases, "skip", "", "Key words to skip cases")
	flag.StringVar(&testOptions.linuxVMs, "linuxVMs", "", "hostname of Linux VMs")
	flag.Parse()

	cleanupLogging := testOptions.setupLogging()
	defer cleanupLogging()

	testData = &TestData{}
	log.Println("Creating K8s ClientSet")
	kubeconfigPath := path.Join(homeDir, ".kube", "secondary_network_cluster", "config")
	if err := testData.createClient(kubeconfigPath); err != nil {
		log.Fatalf("Error when creating K8s ClientSet: %v", err)
	}
	ret := m.Run()
	return ret
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
