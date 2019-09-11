package agent

import (
	"os"
	"testing"
)

func TestGetNodeName(t *testing.T) {
	hostName, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to retrieve hostname, %v", err)
	}
	testTable := map[string]string{
		"node1":     "node1",
		"node_12":   "node_12",
		"":          hostName,
		"node-1234": "node-1234",
	}

	for k, v := range testTable {
		compareNodeName(k, v, t)
	}
}

func compareNodeName(k, v string, t *testing.T) {
	if k != "" {
		_ = os.Setenv(NodeNameKey, k)
		defer os.Unsetenv(NodeNameKey)
	}
	nodeName, err := getNodeName()
	if err != nil {
		t.Errorf("Failure with expected name %s, %v", k, err)
		return
	}
	if nodeName != v {
		t.Errorf("Failed to retrieve nodename, want: %s, get: %s", v, nodeName)
	}
}
