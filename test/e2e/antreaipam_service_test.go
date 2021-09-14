package e2e

import (
	"testing"
)

func TestAntreaIPAMClusterIPv4(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)
	skipIfNotIPv4Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	ippool, err := createIPPool(t, data, 0)
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ippool.Name)
	annotations := map[string]string{}
	annotations[IPPoolAnnotationKey] = ippool.Name
	err = data.createNamespaceWithAnnotations(testAntreaIPAMNamespace, annotations)
	if err != nil {
		t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
	}
	defer deleteAntreaIPAMNamespace(t, data)

	data.testClusterIP(t, false, testAntreaIPAMNamespace)
}

func TestAntreaIPAMNodePort(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	ippool, err := createIPPool(t, data, 0)
	if err != nil {
		t.Fatalf("Creating IPPool failed, err=%+v", err)
	}
	defer deleteIPPoolWrapper(t, data, ippool.Name)
	annotations := map[string]string{}
	annotations[IPPoolAnnotationKey] = ippool.Name
	err = data.createNamespaceWithAnnotations(testAntreaIPAMNamespace, annotations)
	if err != nil {
		t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
	}
	defer deleteAntreaIPAMNamespace(t, data)

	data.testNodePort(t, false, testAntreaIPAMNamespace)
}
