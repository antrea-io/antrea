package cniserver

import (
	"k8s.io/klog"
)

type CNIServer struct {
	cniSocket string
}

func New(cniSocket string) (*CNIServer, error) {
	return &CNIServer{
		cniSocket: cniSocket,
	}, nil
}

func (s *CNIServer) Run(stopCh <-chan struct{}) {
	klog.Info("Starting cni server")
	defer klog.Info("Shutting down cni server")
	<-stopCh
}
