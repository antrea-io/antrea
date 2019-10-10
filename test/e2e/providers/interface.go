package providers

import (
	"golang.org/x/crypto/ssh"
)

// Hides away specific characteristics of the k8s cluster. This should enable the same tests to be
// run on a variety of providers.
type ProviderInterface interface {
	GetSSHConfig(name string) (string, *ssh.ClientConfig, error)
	GetKubeconfigPath() (string, error)
}
