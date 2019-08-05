package main

import (
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	networkpolicy "okn/pkg/controller/networkpolicy"
	"okn/pkg/k8s"
)

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
	informerFactory := informers.NewSharedInformerFactory(client, 60)
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

	stopCh := make(chan struct{})

	go c.networkPolicyController.Run(stopCh)

	c.informerFactory.Start(stopCh)

	<-stopCh
	return nil
}
