package main

import (
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	"okn/pkg/agent/cniserver"
	nodecontroller "okn/pkg/agent/controller/node"
	"okn/pkg/k8s"
)

type OKNAgent struct {
	client          clientset.Interface
	informerFactory informers.SharedInformerFactory
	cniServer       *cniserver.CNIServer
	nodeController  *nodecontroller.NodeController
}

func newOKNAgent(config *AgentConfig) (*OKNAgent, error) {
	client, err := k8s.CreateClient(config.ClientConnection)
	if err != nil {
		return nil, err
	}
	informerFactory := informers.NewSharedInformerFactory(client, 60)
	nodeInformer := informerFactory.Core().V1().Nodes()

	cniServer, err := cniserver.New(config.CNISocket)
	if err != nil {
		return nil, err
	}

	nodeController, err := nodecontroller.New(client, nodeInformer)
	if err != nil {
		return nil, err
	}

	return &OKNAgent{
		client:          client,
		informerFactory: informerFactory,
		cniServer:       cniServer,
		nodeController:  nodeController,
	}, nil
}

func (agent *OKNAgent) run() error {
	klog.Info("Starting OKN Agent")

	stopCh := make(chan struct{})

	go agent.cniServer.Run(stopCh)

	go agent.nodeController.Run(stopCh)

	agent.informerFactory.Start(stopCh)

	<-stopCh
	return nil
}
