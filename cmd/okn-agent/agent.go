package main

import (
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog"

	"okn/pkg/agent/cniserver"
	nodecontroller "okn/pkg/agent/controller/node"
)

// createClients creates a kube client from the given config.
func createClients(config componentbaseconfig.ClientConnectionConfiguration) (clientset.Interface, error) {
	var kubeConfig *rest.Config
	var err error

	if len(config.Kubeconfig) == 0 {
		klog.Info("No kubeconfig file was specified. Falling back to in-cluster config.")
		kubeConfig, err = rest.InClusterConfig()
	} else {
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: config.Kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		return nil, err
	}

	kubeConfig.AcceptContentTypes = config.AcceptContentTypes
	kubeConfig.ContentType = config.ContentType
	kubeConfig.QPS = config.QPS
	kubeConfig.Burst = int(config.Burst)

	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

type Agent struct {
	client          clientset.Interface
	informerFactory informers.SharedInformerFactory
	nodeInformer    coreinformers.NodeInformer
	cniServer       *cniserver.CNIServer
	nodeController  *nodecontroller.NodeController
}

func newAgent(config *AgentConfig) (*Agent, error) {
	client, err := createClients(config.ClientConnection)
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

	return &Agent{
		client:          client,
		informerFactory: informerFactory,
		nodeInformer:    nodeInformer,
		cniServer:       cniServer,
		nodeController:  nodeController,
	}, nil
}

func (agent *Agent) run() error {
	klog.Info("Starting OKN Agent")

	stopCh := make(chan struct{})

	go agent.cniServer.Run(stopCh)

	go agent.nodeController.Run(stopCh)

	agent.informerFactory.Start(stopCh)

	<-stopCh
	return nil
}
