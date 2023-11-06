package packetsampling

import (
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"time"

	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
)

const (
	controllerName = "PacketSamplingController"

	// set resyncPeriod to 0 to disable resyncing
	resyncPeriod time.Duration = 0

	// Default number of workers processing packetsampling request.
	defaultWorkers = 4

	// reason for timeout
	samplingTimeout = 'PacketSampling timeout'

	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketSamplingTimeout)
)

var (
	timeoutCheckInterval = 10 * time.Second
)

type Controller struct {
	client versiond.Interface
	podInformer coreinformers.PodInformer
	podLister corelisters.PodLister
	packetSamplingInformer crdinformers.PacketSamplingInformer
	packetSamplingLister crdlisters.PacketSamplingLister
	
}
