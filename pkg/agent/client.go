package agent

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/component-base/config"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

// CreateAntreaClient creates an Antrea client from the given config.
func CreateAntreaClient(config config.ClientConnectionConfiguration) (versioned.Interface, error) {
	var kubeConfig *rest.Config
	var err error

	if len(config.Kubeconfig) == 0 {
		klog.Info("No antrea kubeconfig file was specified. Falling back to in-cluster config")
		kubeConfig, err = inClusterConfig()
	} else {
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: config.Kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		return nil, err
	}

	// ContentType will be used to define the Accept header if AcceptContentTypes is not set.
	kubeConfig.ContentType = "application/vnd.kubernetes.protobuf"
	kubeConfig.QPS = config.QPS
	kubeConfig.Burst = int(config.Burst)

	client, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// inClusterConfig returns a config object which uses the service account
// kubernetes gives to pods. It's intended for clients that expect to be
// running inside a pod running on kubernetes. It will return error
// if called from a process not running in a kubernetes environment.
func inClusterConfig() (*rest.Config, error) {
	const tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	host, port := os.Getenv("ANTREA_SERVICE_HOST"), os.Getenv("ANTREA_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, fmt.Errorf("unable to load in-cluster configuration, ANTREA_SERVICE_HOST and ANTREA_SERVICE_PORT must be defined")
	}

	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	// Agent is not able to verify Controller's cert as it's generated in-memory with loopback address.
	// Use Insecure for now.
	tlsClientConfig := rest.TLSClientConfig{Insecure: true}

	return &rest.Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		TLSClientConfig: tlsClientConfig,
		BearerToken:     string(token),
		BearerTokenFile: tokenFile,
	}, nil
}
