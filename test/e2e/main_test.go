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

package e2e

import (
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"testing"
	"time"
)

// setupLogging creates a temporary directory to export the test logs if necessary. If a directory
// was provided by the user, it checks that the directory exists.
func (tOptions *TestOptions) setupLogging() func() {
	if tOptions.logsExportDir == "" {
		name, err := ioutil.TempDir("", "antrea-test-")
		if err != nil {
			log.Fatalf("Error when creating temporary directory to export logs: %v", err)
		}
		log.Printf("Test logs (if any) will be exported under the '%s' directory", name)
		tOptions.logsExportDir = name
		// we will delete the temporary directory if no logs are exported
		return func() {
			if empty, _ := IsDirEmpty(name); empty {
				log.Printf("Removing empty logs directory '%s'", name)
				_ = os.Remove(name)
			} else {
				log.Printf("Logs exported under '%s', it is your responsibility to delete the directory when you no longer need it", name)
			}
		}
	} else {
		fInfo, err := os.Stat(tOptions.logsExportDir)
		if err != nil {
			log.Fatalf("Cannot stat provided directory '%s': %v", tOptions.logsExportDir, err)
		}
		if !fInfo.Mode().IsDir() {
			log.Fatalf("'%s' is not a valid directory", tOptions.logsExportDir)
		}
	}
	// no-op cleanup function
	return func() {}
}

// testMain is meant to be called by TestMain and enables the use of defer statements.
func testMain(m *testing.M) int {
	flag.StringVar(&testOptions.providerName, "provider", "vagrant", "K8s test cluster provider")
	flag.StringVar(&testOptions.providerConfigPath, "provider-cfg-path", "", "Optional config file for provider")
	flag.StringVar(&testOptions.logsExportDir, "logs-export-dir", "", "Export directory for test logs")
	flag.BoolVar(&testOptions.logsExportOnSuccess, "logs-export-on-success", false, "Export logs even when a test is successful")
	flag.BoolVar(&testOptions.withBench, "benchtest", false, "Run tests include benchmark tests")
	flag.Parse()

	if err := initProvider(); err != nil {
		log.Fatalf("Error when initializing provider: %v", err)
	}

	cleanupLogging := testOptions.setupLogging()
	defer cleanupLogging()

	log.Println("Collecting information about K8s cluster")
	if err := collectClusterInfo(); err != nil {
		log.Fatalf("Error when collecting information about K8s cluster: %v", err)
	} else {
		if clusterInfo.podV4NetworkCIDR != "" {
			log.Printf("Pod IPv4 network: '%s'", clusterInfo.podV4NetworkCIDR)
		}
		if clusterInfo.podV6NetworkCIDR != "" {
			log.Printf("Pod IPv6 network: '%s'", clusterInfo.podV6NetworkCIDR)
		}
		log.Printf("Num nodes: %d", clusterInfo.numNodes)
	}

	rand.Seed(time.Now().UnixNano())
	return m.Run()
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
