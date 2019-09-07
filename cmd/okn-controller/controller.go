package main

import (
	"time"

	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	networkpolicy "okn/pkg/controller/networkpolicy"
	"okn/pkg/k8s"
	"okn/pkg/signals"
)

// Determine how often we go through reconciliation (between current and desired state)
// Same as in https://github.com/kubernetes/sample-controller/blob/master/main.go
const informerDefaultResync time.Duration = 30 * time.Second

type OKNController struct {
	client                  clientset.Interface
	informerFactory         informers.SharedInformerFactory
	networkPolicyController *networkpolicy.NetworkPolicyController
}

func newOKNController(config *ControllerConfig) (*OKNController, error) {
	client, err := k8s.CreateClient(config.ClientConnection)
	if err != nil {
		return nil, err
	}
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()

	networkPolicyController, err := networkpolicy.NewNetworkPolicyController(client, podInformer, namespaceInformer, networkPolicyInformer)
	if err != nil {
		return nil, err
	}

	return &OKNController{
		client:                  client,
		informerFactory:         informerFactory,
		networkPolicyController: networkPolicyController,
	}, nil
}

func (c *OKNController) run() error {
	klog.Info("Starting OKN Controller")

	// set up signals so we handle the first shutdown signal gracefully
	stopCh := signals.SetupSignalHandler()

	c.informerFactory.Start(stopCh)

	go c.networkPolicyController.Run(stopCh)

	<-stopCh
	klog.Info("Stopping OKN controller")
	return nil
}
