package util

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	interfaceNameLength   = 15
	podNamePrefixLength   = 8
	containerKeyConnector = `-`
)

// Calculates a suitable interface name using the pod namespace and pod name. The output should be
// deterministic (so that multiple calls to GenerateContainerInterfaceName with the same parameters
// return the same value). The output should have length interfaceNameLength (15). The probablity of
// collision should be neglectable.
func GenerateContainerInterfaceName(podName string, podNamespace string) string {
	hash := sha1.New()
	podID := fmt.Sprintf("%s/%s", podNamespace, podName)
	io.WriteString(hash, podID)
	podKey := hex.EncodeToString(hash.Sum(nil))
	name := strings.Replace(podName, "-", "", -1)
	if len(name) > podNamePrefixLength {
		name = name[:podNamePrefixLength]
	}
	podKeyLength := interfaceNameLength - len(name) - len(containerKeyConnector)
	return strings.Join([]string{name, podKey[:podKeyLength]}, containerKeyConnector)
}
