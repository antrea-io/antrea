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
	"os"
	"testing"
)

// testMain is meant to be called by TestMain and enables the use of defer statements.
func testMain(m *testing.M) int {
	flag.StringVar(&testOptions.ProviderName, "provider", "vagrant", "K8s test cluster provider")
	flag.StringVar(&testOptions.ProviderConfigPath, "provider-cfg-path", "", "Optional config file for provider")
	flag.StringVar(&testOptions.logsExportDir, "logs-export-dir", "", "Export directory for test logs")
	flag.BoolVar(&testOptions.logsExportOnSuccess, "logs-export-on-success", false, "Export logs even when a test is successful")
	flag.BoolVar(&testOptions.withBench, "benchtest", false, "Run tests include benchmark tests")
	flag.BoolVar(&testOptions.EnableCoverage, "coverage", false, "Run tests and measure coverage")
	flag.BoolVar(&testOptions.enableAntreaIPAM, "antrea-ipam", false, "Run tests with AntreaIPAM")
	flag.BoolVar(&testOptions.flowVisibility, "flow-visibility", false, "Run flow visibility tests")
	flag.BoolVar(&testOptions.DeployAntrea, "deploy-antrea", true, "Deploy Antrea before running tests")
	flag.StringVar(&testOptions.coverageDir, "coverage-dir", "", "Directory for coverage data files")
	flag.StringVar(&testOptions.skipCases, "skip", "", "Key words to skip cases")
	flag.StringVar(&testOptions.linuxVMs, "linuxVMs", "", "hostname of Linux VMs")
	flag.StringVar(&testOptions.windowsVMs, "windowsVMs", "", "hostname of Windows VMs")
	flag.Parse()

	cleanupLogging := testOptions.setupLogging()
	defer cleanupLogging()

	InitializeTestData()

	if testOptions.EnableCoverage {
		cleanupCoverage := testOptions.SetupCoverage(testData)
		defer cleanupCoverage()
		defer GracefulExitAntrea(testData)
	}
	ret := m.Run()
	return ret
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
