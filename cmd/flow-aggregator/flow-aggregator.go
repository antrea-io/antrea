// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"hash/fnv"
	"os"
	"path"
	"sync"
	"time"

	"github.com/Shopify/sarama"
	"github.com/google/uuid"
	"github.com/vmware/go-ipfix/pkg/kafka/producer"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/clusteridentity"
	aggregator "antrea.io/antrea/pkg/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator/apiserver"
	"antrea.io/antrea/pkg/flowaggregator/kafka"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/cipher"
)

var (
	// certDir is the directory that the TLS Secret should be mounted to. Declaring it as a variable for testing.
	certDir = "/var/run/antrea/flow-aggregator-kafka-tls"
	// certReadyTimeout is the timeout we will wait for the TLS Secret being ready. Declaring it as a variable for testing.
	certReadyTimeout = 2 * time.Minute
)

const (
	// The names of the files that should contain the CA certificate and the TLS
	// key pair. If the Kafka broker does not have any trust store, CA cert authenticates
	// the broker and TLS key pair authenticates the communication between the Flow
	// Aggregator and the Kafka broker. If the Kafka broker has the trust store,
	// then we presume some bootstrap process generates the CA cert and TLS keys
	// for the Flow Aggregator and mount them through Kubernetes secret.
	CACertFile            = "ca.crt"
	TLSCertFile           = "tls.crt"
	TLSKeyFile            = "tls.key"
	informerDefaultResync = 12 * time.Hour
)

// genObservationDomainID generates an IPFIX Observation Domain ID when one is not provided by the
// user through the flow aggregator configuration. It will first try to generate one
// deterministically based on the cluster UUID (if available, with a timeout of 10s). Otherwise, it
// will generate a random one. The cluster UUID should be available if Antrea is deployed to the
// cluster ahead of the flow aggregator, which is the expectation since when deploying flow
// aggregator as a Pod, networking needs to be configured by the CNI plugin.
func genObservationDomainID(k8sClient kubernetes.Interface) uint32 {
	const retryInterval = time.Second
	const timeout = 10 * time.Second
	const defaultAntreaNamespace = "kube-system"

	clusterIdentityProvider := clusteridentity.NewClusterIdentityProvider(
		defaultAntreaNamespace,
		clusteridentity.DefaultClusterIdentityConfigMapName,
		k8sClient,
	)
	var clusterUUID uuid.UUID
	if err := wait.PollImmediate(retryInterval, timeout, func() (bool, error) {
		clusterIdentity, _, err := clusterIdentityProvider.Get()
		if err != nil {
			return false, nil
		}
		clusterUUID = clusterIdentity.UUID
		return true, nil
	}); err != nil {
		klog.Warningf(
			"Unable to retrieve cluster UUID after %v (does ConfigMap '%s/%s' exist?); will generate a random observation domain ID",
			timeout, defaultAntreaNamespace, clusteridentity.DefaultClusterIdentityConfigMapName,
		)
		clusterUUID = uuid.New()
	}
	h := fnv.New32()
	h.Write(clusterUUID[:])
	observationDomainID := h.Sum32()
	return observationDomainID
}

func run(o *Options) error {
	klog.Infof("Flow aggregator starting...")
	// Set up signal capture: the first SIGTERM / SIGINT signal is handled gracefully and will
	// cause the stopCh channel to be closed; if another signal is received before the program
	// exits, we will force exit.
	stopCh := signals.RegisterSignalHandlers()

	log.StartLogFileNumberMonitor(stopCh)

	k8sClient, err := createK8sClient()
	if err != nil {
		return fmt.Errorf("error when creating K8s client: %v", err)
	}

	informerFactory := informers.NewSharedInformerFactory(k8sClient, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()

	var observationDomainID uint32
	if o.config.ObservationDomainID != nil {
		observationDomainID = *o.config.ObservationDomainID
	} else {
		observationDomainID = genObservationDomainID(k8sClient)
	}
	klog.Infof("Flow aggregator Observation Domain ID: %d", observationDomainID)
	var producerInput *producer.ProducerInput
	if o.config.KafkaParams.KafkaBrokerAddress != "" {
		// Retrieve TLS certificates from user provided K8s secrets.
		var caCertPath, tlsCertPath, tlsKeyPath string
		if o.config.KafkaParams.KafkaTLSEnable {
			caCertPath = path.Join(certDir, CACertFile)
			tlsCertPath = path.Join(certDir, TLSCertFile)
			tlsKeyPath = path.Join(certDir, TLSKeyFile)
			// The secret may be created after the Pod is created, for example, when cert-manager is used the secret
			// is created asynchronously. It waits for a while before it's considered to be failed.
			if err = wait.PollImmediate(2*time.Second, certReadyTimeout, func() (bool, error) {
				for _, path := range []string{caCertPath, tlsCertPath, tlsKeyPath} {
					f, err := os.Open(path)
					if err != nil {
						klog.Warningf("Couldn't read %s when applying the kafka TLS certificate, retrying", path)
						return false, nil
					}
					f.Close()
				}
				return true, nil
			}); err != nil {
				return fmt.Errorf("error reading Kafka TLS CA cert (%s), cert (%s), and key (%s) files present at \"%s\"", CACertFile, TLSCertFile, TLSKeyFile, certDir)
			}
		}

		producerInput = &producer.ProducerInput{
			KafkaBrokers:       []string{o.config.KafkaParams.KafkaBrokerAddress},
			KafkaLogErrors:     true,
			KafkaTopic:         o.kakfaBrokerTopic,
			KafkaTLSEnabled:    o.config.KafkaParams.KafkaTLSEnable,
			KafkaCAFile:        caCertPath,
			KafkaTLSCertFile:   tlsCertPath,
			KafkaTLSKeyFile:    tlsKeyPath,
			KafkaTLSSkipVerify: o.config.KafkaParams.KafkaTLSSkipVerify,
			KafkaVersion:       sarama.DefaultVersion,
		}
		// Depending on the proto schema, pick a convertor. Currently supporting
		// only AntreaFlowMsg proto schema.
		if o.kakfaProtoSchema == kafka.AntreaFlowMsg {
			producerInput.ProtoSchemaConvertor = kafka.NewAntreaFlowMsgConvertor()
		}
	}

	var sendJSONRecord bool
	if o.format == "JSON" {
		sendJSONRecord = true
	} else {
		sendJSONRecord = false
	}

	flowAggregator, err := aggregator.NewFlowAggregator(
		o.externalFlowCollectorAddr,
		o.externalFlowCollectorProto,
		o.activeFlowRecordTimeout,
		o.inactiveFlowRecordTimeout,
		o.aggregatorTransportProtocol,
		o.flowAggregatorAddress,
		o.includePodLabels,
		producerInput,
		k8sClient,
		observationDomainID,
		podInformer,
		sendJSONRecord,
	)
	if err != nil {
		return fmt.Errorf("error when initializing the Flow Aggregator: %v", err)
	}
	err = flowAggregator.InitCollectingProcess()
	if err != nil {
		return fmt.Errorf("error when creating collecting process: %v", err)
	}
	err = flowAggregator.InitAggregationProcess()
	if err != nil {
		return fmt.Errorf("error when creating aggregation process: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go flowAggregator.Run(stopCh, &wg)

	cipherSuites, err := cipher.GenerateCipherSuitesList(o.config.APIServer.TLSCipherSuites)
	if err != nil {
		return fmt.Errorf("error generating Cipher Suite list: %v", err)
	}
	apiServer, err := apiserver.New(
		flowAggregator,
		o.config.APIServer.APIPort,
		cipherSuites,
		cipher.TLSVersionMap[o.config.APIServer.TLSMinVersion])
	if err != nil {
		return fmt.Errorf("error when creating flow aggregator API server: %v", err)
	}
	go apiServer.Run(stopCh)

	informerFactory.Start(stopCh)

	<-stopCh
	klog.Infof("Stopping flow aggregator")
	wg.Wait()
	return nil
}

func createK8sClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return k8sClient, nil
}
