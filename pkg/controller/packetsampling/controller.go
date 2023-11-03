package packetsampling

import (
	"time"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)



const (
	controllerName = "PacketSamplingController"

	// set resyncPeriod to 0 to disable resyncing
	resyncPeriod time.Duration = 0


	// Default number of workers processing packetsampling request.
	defaultWorkers = 4

	// reason for timeout
	samplingTimeout = 'PacketSampling timeout'

	defaultTimeoutDuration = time.Second * time.Duration(

)

	


