package main

import (
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"okn/pkg/agent"
	"okn/pkg/agent/cniserver"
	_ "okn/pkg/agent/cniserver/ipam"
	nodecontroller "okn/pkg/agent/controller/node"
	"okn/pkg/k8s"
	"okn/pkg/ovs/ovsconfig"
)

type OKNAgent struct {
	client          clientset.Interface
	informerFactory informers.SharedInformerFactory
	cniServer       *cniserver.CNIServer
	nodeController  *nodecontroller.NodeController
	ovsdbConnection *ovsdb.OVSDB
}

func newOKNAgent(config *AgentConfig) (*OKNAgent, error) {
	client, err := k8s.CreateClient(config.ClientConnection)
	if err != nil {
		return nil, err
	}
	informerFactory := informers.NewSharedInformerFactory(client, 60)
	nodeInformer := informerFactory.Core().V1().Nodes()

	ovsdbConnection, err := ovsconfig.NewOVSDBConnectionUDS("")
	if err != nil {
		// Todo: ovsconfig.NewOVSDBConnectionUDS might return timeout in the future, need to add retry
		// Currently it return nil
		klog.Errorf("Failed to connect OVSDB socket")
		return nil, err
	}
	br, err := ovsconfig.NewOVSBridge(config.OVSBridge, ovsdbConnection)
	if err != nil {
		klog.Errorf("Failed to create OVS bridge %s", config.OVSBridge)
		return nil, err
	}

	nodeConfig, err := agent.GetNodeLocalConfig(client)
	if err != nil {
		klog.Errorf("Failed to calculate local PodCIDR: %v", err)
		return nil, err
	}

	// Create interface store
	ifaceStore := agent.NewInterfaceStore()

	// Create agent initializer
	agentInitializer := agent.NewInitializer(br, ifaceStore)

	err = agentInitializer.SetupNodeNetwork(config.OVSBridge, config.HostGateway, config.TunnelType, nodeConfig)
	if err != nil {
		return nil, err
	}

	cniServer, err := cniserver.New(config.CNISocket, nodeConfig, br, ifaceStore)
	if err != nil {
		return nil, err
	}

	nodeController, err := nodecontroller.NewNodeController(client, nodeInformer)
	if err != nil {
		return nil, err
	}

	return &OKNAgent{
		client:          client,
		informerFactory: informerFactory,
		cniServer:       cniServer,
		nodeController:  nodeController,
		ovsdbConnection: ovsdbConnection,
	}, nil
}

func (agent *OKNAgent) run() error {
	klog.Info("Starting OKN Agent")

	stopCh := make(chan struct{})

	go agent.cniServer.Run(stopCh)

	go agent.nodeController.Run(stopCh)

	agent.informerFactory.Start(stopCh)

	<-stopCh
	// Close OVSDB connection
	agent.ovsdbConnection.Close()
	return nil
}
