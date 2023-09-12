package netpol_conformance

import (
	"flag"
	"os"
	"testing"

	antreaTestFramework "antrea.io/antrea/test/e2e"
)

// testMain is meant to be called by TestMain and enables the use of defer statements.
func testMain(m *testing.M) int {
	testOptions := antreaTestFramework.TestOptions{}
	flag.StringVar(&testOptions.ProviderName, "provider", "vagrant", "K8s test cluster provider")
	flag.StringVar(&testOptions.ProviderConfigPath, "provider-cfg-path", "", "Optional config file for provider")
	flag.BoolVar(&testOptions.DeployAntrea, "deploy-antrea", true, "Deploy Antrea before running tests")
	antreaTestFramework.SetTestOptions(testOptions)
	antreaTestFramework.InitializeTestData()
	testData := antreaTestFramework.GetTestData()
	if testOptions.EnableCoverage {
		cleanupCoverage := testOptions.SetupCoverage(testData)
		defer cleanupCoverage()
		defer antreaTestFramework.GracefulExitAntrea(testData)
	}
	ret := m.Run()
	return ret
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
