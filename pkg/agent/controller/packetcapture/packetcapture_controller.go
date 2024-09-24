// Copyright 2024 Antrea Authors.
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

package packetcapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"antrea.io/libOpenflow/protocol"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ftp"
)

type StorageProtocolType string

const (
	sftpProtocol StorageProtocolType = "sftp"
)

const (
	controllerName               = "AntreaAgentPacketCaptureController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4

	// 4bits in ovs reg4
	minTagNum uint8 = 1
	maxTagNum uint8 = 15

	// reason for timeout
	captureTimeoutReason   = "PacketCapture timeout"
	defaultTimeoutDuration = time.Second * time.Duration(crdv1alpha1.DefaultPacketCaptureTimeout)
	timeoutCheckInterval   = 10 * time.Second

	captureStatusUpdatePeriod = 10 * time.Second

	// PacketCapture uses a dedicated secret object to store auth info for file server.
	// #nosec G101
	fileServerAuthSecretName      = "antrea-packetcapture-fileserver-auth"
	fileServerAuthSecretNamespace = "kube-system"
)

var (
	packetDirectory = getPacketDirectory()
	defaultFS       = afero.NewOsFs()
)

func getPacketDirectory() string {
	return filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
}

type packetCaptureState struct {
	// name is the PacketCapture name
	name string
	// tag is a node scope unique id for the PacketCapture. It will be written into ovs reg and parsed in packetIn handler
	// to match with existing PacketCapture.
	tag uint8
	// shouldSyncPackets means this node will be responsible for doing the actual packet capture job.
	shouldSyncPackets bool
	// numCapturedPackets record how many packets has been captured. Due to the RateLimiter,
	// this maybe not be realtime data.
	numCapturedPackets int32
	// maxNumCapturedPackets is target number limit for our capture. If numCapturedPackets=maxNumCapturedPackets, means
	// the PacketCapture is succeeded.
	maxNumCapturedPackets int32
	// updateRateLimiter controls the frequency of the updates to PacketCapture status.
	updateRateLimiter *rate.Limiter
	// pcapngFile is the file object for the packet file.
	pcapngFile afero.File
	// pcapngWriter is the writer for the packet file.
	pcapngWriter *pcapgo.NgWriter
}

type Controller struct {
	kubeClient                 clientset.Interface
	crdClient                  clientsetversioned.Interface
	serviceLister              corelisters.ServiceLister
	serviceListerSynced        cache.InformerSynced
	endpointLister             corelisters.EndpointsLister
	endpointSynced             cache.InformerSynced
	packetCaptureInformer      crdinformers.PacketCaptureInformer
	packetCaptureLister        crdlisters.PacketCaptureLister
	packetCaptureSynced        cache.InformerSynced
	ofClient                   openflow.Client
	interfaceStore             interfacestore.InterfaceStore
	nodeConfig                 *config.NodeConfig
	queue                      workqueue.RateLimitingInterface
	runningPacketCapturesMutex sync.RWMutex
	runningPacketCaptures      map[uint8]*packetCaptureState
	sftpUploader               ftp.Uploader
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointInformer coreinformers.EndpointsInformer,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	client openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
) *Controller {
	c := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		packetCaptureInformer: packetCaptureInformer,
		packetCaptureLister:   packetCaptureInformer.Lister(),
		packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
		ofClient:              client,
		interfaceStore:        interfaceStore,
		nodeConfig:            nodeConfig,
		queue: workqueue.NewRateLimitingQueueWithConfig(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay),
			workqueue.RateLimitingQueueConfig{Name: "packetcapture"}),
		runningPacketCaptures: make(map[uint8]*packetCaptureState),
		sftpUploader:          &ftp.SftpUploader{},
	}

	packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketCapture,
		UpdateFunc: c.updatePacketCapture,
		DeleteFunc: c.deletePacketCapture,
	}, resyncPeriod)

	c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryPacketCapture), c)

	c.serviceLister = serviceInformer.Lister()
	c.serviceListerSynced = serviceInformer.Informer().HasSynced
	c.endpointLister = endpointInformer.Lister()
	c.endpointSynced = endpointInformer.Informer().HasSynced
	return c
}

func (c *Controller) enqueuePacketCapture(pc *crdv1alpha1.PacketCapture) {
	c.queue.Add(pc.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the PacketCapture events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting packetcapture controller", "name", controllerName)
	defer klog.InfoS("Shutting down packetcapture controller", "name", controllerName)

	cacheSynced := []cache.InformerSynced{c.packetCaptureSynced, c.serviceListerSynced, c.endpointSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	// cleanup existing packets file first. successful PacketCapture will upload them to the target file server.
	// others are useless once we restart the controller.
	if err := defaultFS.RemoveAll(packetDirectory); err != nil {
		klog.ErrorS(err, "Remove packets dir error", "directory", packetDirectory)
	}
	err := defaultFS.MkdirAll(packetDirectory, 0755)
	if err != nil {
		klog.ErrorS(err, "Couldn't create directory for storing captured packets", "directory", packetDirectory)
		return
	}

	go wait.Until(c.checkPacketCaptureTimeout, timeoutCheckInterval, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) checkPacketCaptureTimeout() {
	c.runningPacketCapturesMutex.RLock()
	pcs := make([]string, 0, len(c.runningPacketCaptures))
	for _, pcState := range c.runningPacketCaptures {
		pcs = append(pcs, pcState.name)
	}
	c.runningPacketCapturesMutex.RUnlock()
	for _, pcName := range pcs {
		// Re-post all running PacketCapture requests to the work queue to
		// be processed and checked for timeout.
		c.queue.Add(pcName)
	}
}

func (c *Controller) addPacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture ADD event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) updatePacketCapture(_, obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture UPDATE event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) deletePacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.InfoS("Processing PacketCapture DELETE event", "name", pc.Name)
	err := deletePcapngFile(string(pc.UID))
	if err != nil {
		klog.ErrorS(err, "Couldn't delete pcapng file")
	}
	c.enqueuePacketCapture(pc)
}

func deletePcapngFile(uid string) error {
	return defaultFS.Remove(uidToPath(uid))
}

func uidToPath(uid string) string {
	return filepath.Join(packetDirectory, uid+".pcapng")
}

func (c *Controller) worker() {
	for c.processPacketCaptureItem() {
	}
}

func (c *Controller) processPacketCaptureItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(obj)
	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.ErrorS(nil, "Expected string in work queue but got non-string object", "obj", obj)
		return true
	} else if err := c.syncPacketCapture(key); err == nil {
		c.queue.Forget(key)
	} else {
		klog.ErrorS(err, "Error syncing PacketCapture, exiting", "key", key)
	}
	return true
}

func (c *Controller) cleanupPacketCapture(pcName string) {
	pcState := c.deletePacketCaptureState(pcName)
	if pcState != nil {
		err := c.ofClient.UninstallPacketCaptureFlows(pcState.tag)
		if err != nil {
			klog.ErrorS(err, "Error cleaning up flows for PacketCapture", "name", pcName)
		}
		if pcState.pcapngFile != nil {
			if err := pcState.pcapngFile.Close(); err != nil {
				klog.ErrorS(err, "Error closing pcap file", "name", pcName)
			}
		}
	}
}

func (c *Controller) deletePacketCaptureState(pcName string) *packetCaptureState {
	c.runningPacketCapturesMutex.Lock()
	defer c.runningPacketCapturesMutex.Unlock()

	for tag, state := range c.runningPacketCaptures {
		if state.name == pcName {
			delete(c.runningPacketCaptures, tag)
			return state
		}
	}
	return nil
}

func (c *Controller) startPacketCapture(pc *crdv1alpha1.PacketCapture, pcState *packetCaptureState) error {
	var err error
	defer func() {
		if err != nil {
			c.cleanupPacketCapture(pc.Name)
			c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, fmt.Sprintf("Node: %s, Error: %+v", c.nodeConfig.Name, err), 0)

		}
	}()
	receiverOnly := false
	senderOnly := false
	var pod, ns string

	if pc.Spec.Source.Pod != "" {
		pod = pc.Spec.Source.Pod
		ns = pc.Spec.Source.Namespace
		if pc.Spec.Destination.Pod == "" {
			senderOnly = true
		}
	} else {
		pod = pc.Spec.Destination.Pod
		ns = pc.Spec.Destination.Namespace
		receiverOnly = true
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	pcState.shouldSyncPackets = len(podInterfaces) > 0
	if !pcState.shouldSyncPackets {
		return nil
	}
	var packet, senderPacket *binding.Packet
	var endpointPackets []binding.Packet
	var ofPort uint32
	packet, err = c.preparePacket(pc, podInterfaces[0], receiverOnly)
	if err != nil {
		return err
	}
	ofPort = uint32(podInterfaces[0].OFPort)
	senderPacket = packet
	klog.V(2).InfoS("PacketCapture sender packet", "packet", *packet)
	if senderOnly && pc.Spec.Destination.Service != "" {
		endpointPackets, err = c.genEndpointMatchPackets(pc)
		if err != nil {
			return fmt.Errorf("couldn't generate endpoint match packets: %w", err)
		}
	}

	c.runningPacketCapturesMutex.Lock()
	pcState.maxNumCapturedPackets = pc.Spec.CaptureConfig.FirstN.Number
	var file afero.File
	filePath := uidToPath(string(pc.UID))
	if _, err := os.Stat(filePath); err == nil {
		return fmt.Errorf("packet file already exists. this may be due to an unexpected termination")
	} else if os.IsNotExist(err) {
		file, err = defaultFS.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create pcapng file: %w", err)
		}
	} else {
		return fmt.Errorf("couldn't check if the file exists: %w", err)
	}
	writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("couldn't init pcap writer: %w", err)
	}
	pcState.shouldSyncPackets = len(podInterfaces) > 0
	pcState.pcapngFile = file
	pcState.pcapngWriter = writer
	pcState.updateRateLimiter = rate.NewLimiter(rate.Every(captureStatusUpdatePeriod), 1)
	c.runningPacketCaptures[pcState.tag] = pcState
	c.runningPacketCapturesMutex.Unlock()

	timeout := crdv1alpha1.DefaultPacketCaptureTimeout
	if pc.Spec.Timeout != nil {
		timeout = *pc.Spec.Timeout
	}
	klog.V(2).InfoS("Installing flow entries for PacketCapture", "name", pc.Name)
	err = c.ofClient.InstallPacketCaptureFlows(pcState.tag, senderOnly, receiverOnly, senderPacket, endpointPackets, ofPort, timeout)
	if err != nil {
		klog.ErrorS(err, "Install flow entries failed", "name", pc.Name)
	}
	return err
}

// genEndpointMatchPackets generates match packets (with destination Endpoint's IP/Port info) besides the normal match packet.
// these match packets will help the pipeline to capture the pod -> svc traffic.
// TODO: 1. support name based port name 2. dual-stack support
func (c *Controller) genEndpointMatchPackets(pc *crdv1alpha1.PacketCapture) ([]binding.Packet, error) {
	var port int32
	if pc.Spec.Packet.TransportHeader.TCP != nil && pc.Spec.Packet.TransportHeader.TCP.DstPort != nil {
		port = *pc.Spec.Packet.TransportHeader.TCP.DstPort
	} else if pc.Spec.Packet.TransportHeader.UDP != nil && pc.Spec.Packet.TransportHeader.UDP.DstPort != nil {
		port = *pc.Spec.Packet.TransportHeader.UDP.DstPort
	}
	var packets []binding.Packet
	dstSvc, err := c.serviceLister.Services(pc.Spec.Destination.Namespace).Get(pc.Spec.Destination.Service)
	if err != nil {
		return nil, err
	}
	for _, item := range dstSvc.Spec.Ports {
		if item.Port == port {
			if item.TargetPort.Type == intstr.Int {
				port = item.TargetPort.IntVal
			}
		}
	}
	dstEndpoint, err := c.endpointLister.Endpoints(pc.Spec.Destination.Namespace).Get(pc.Spec.Destination.Service)
	if err != nil {
		return nil, err
	}
	for _, item := range dstEndpoint.Subsets[0].Addresses {
		packet := binding.Packet{}
		packet.DestinationIP = net.ParseIP(item.IP)
		if port != 0 {
			packet.DestinationPort = uint16(port)
		}
		packet.IPProto = parseTargetProto(pc.Spec.Packet)
		packets = append(packets, packet)
	}
	return packets, nil
}

func (c *Controller) preparePacket(pc *crdv1alpha1.PacketCapture, intf *interfacestore.InterfaceConfig, receiverOnly bool) (*binding.Packet, error) {
	packet := new(binding.Packet)
	if pc.Spec.Packet == nil {
		pc.Spec.Packet = &crdv1alpha1.Packet{}
	}
	packet.IsIPv6 = pc.Spec.Packet.IPFamily == v1.IPv6Protocol

	if receiverOnly {
		if pc.Spec.Source.IP != "" {
			packet.SourceIP = net.ParseIP(pc.Spec.Source.IP)
		}
		packet.DestinationMAC = intf.MAC
	} else if pc.Spec.Destination.IP != "" {
		packet.DestinationIP = net.ParseIP(pc.Spec.Destination.IP)
	} else if pc.Spec.Destination.Pod != "" {
		dstPodInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pc.Spec.Destination.Pod, pc.Spec.Destination.Namespace)
		if len(dstPodInterfaces) > 0 {
			if packet.IsIPv6 {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv6Addr()
			} else {
				packet.DestinationIP = dstPodInterfaces[0].GetIPv4Addr()
			}
		} else {
			dstPod, err := c.kubeClient.CoreV1().Pods(pc.Spec.Destination.Namespace).Get(context.TODO(), pc.Spec.Destination.Pod, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get the destination pod %s/%s: %v", pc.Spec.Destination.Namespace, pc.Spec.Destination.Pod, err)
			}
			podIPs := make([]net.IP, len(dstPod.Status.PodIPs))
			for i, ip := range dstPod.Status.PodIPs {
				podIPs[i] = net.ParseIP(ip.IP)
			}
			if packet.IsIPv6 {
				packet.DestinationIP, _ = util.GetIPWithFamily(podIPs, util.FamilyIPv6)
			} else {
				packet.DestinationIP = util.GetIPv4Addr(podIPs)
			}
		}
		if packet.DestinationIP == nil {
			if packet.IsIPv6 {
				return nil, errors.New("destination Pod does not have an IPv6 address")
			}
			return nil, errors.New("destination Pod does not have an IPv4 address")
		}
	} else if pc.Spec.Destination.Service != "" {
		dstSvc, err := c.serviceLister.Services(pc.Spec.Destination.Namespace).Get(pc.Spec.Destination.Service)
		if err != nil {
			return nil, fmt.Errorf("failed to get the destination service %s/%s: %v", pc.Spec.Destination.Namespace, pc.Spec.Destination.Service, err)
		}
		if dstSvc.Spec.ClusterIP == "" {
			return nil, errors.New("destination Service does not have a ClusterIP")
		}

		packet.DestinationIP = net.ParseIP(dstSvc.Spec.ClusterIP)
		if !packet.IsIPv6 {
			packet.DestinationIP = packet.DestinationIP.To4()
			if packet.DestinationIP == nil {
				return nil, errors.New("destination Service does not have an IPv4 address")
			}
		} else if packet.DestinationIP.To4() != nil {
			return nil, errors.New("destination Service does not have an IPv6 address")
		}
	} else {
		return nil, errors.New("destination is not specified")
	}

	if pc.Spec.Packet.TransportHeader.TCP != nil {
		if pc.Spec.Packet.TransportHeader.TCP.SrcPort != nil {
			packet.SourcePort = uint16(*pc.Spec.Packet.TransportHeader.TCP.SrcPort)
		}
		if pc.Spec.Packet.TransportHeader.TCP.DstPort != nil {
			packet.DestinationPort = uint16(*pc.Spec.Packet.TransportHeader.TCP.DstPort)
		}
		if pc.Spec.Packet.TransportHeader.TCP.Flags != nil {
			packet.TCPFlags = uint8(*pc.Spec.Packet.TransportHeader.TCP.Flags)
		}
	} else if pc.Spec.Packet.TransportHeader.UDP != nil {
		if pc.Spec.Packet.TransportHeader.UDP.SrcPort != nil {
			packet.SourcePort = uint16(*pc.Spec.Packet.TransportHeader.UDP.SrcPort)
		}
		if pc.Spec.Packet.TransportHeader.UDP.DstPort != nil {
			packet.DestinationPort = uint16(*pc.Spec.Packet.TransportHeader.UDP.DstPort)
		}
	}
	packet.IPProto = parseTargetProto(pc.Spec.Packet)
	return packet, nil
}

func parseTargetProto(packet *crdv1alpha1.Packet) uint8 {
	inputProto := packet.Protocol
	if inputProto == nil {
		return protocol.Type_ICMP
	}
	if inputProto.Type == intstr.Int {
		return uint8(inputProto.IntVal)
	}

	if inputProto.StrVal == "TCP" {
		return protocol.Type_TCP
	} else if inputProto.StrVal == "ICMP" {
		return protocol.Type_ICMP
	} else if inputProto.StrVal == "UDP" {
		return protocol.Type_UDP
	} else {
		return protocol.Type_IPv6ICMP
	}
}

func (c *Controller) syncPacketCapture(pcName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing PacketCapture", "name", pcName, "startTime", time.Since(startTime))
	}()

	pc, err := c.packetCaptureLister.Get(pcName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.cleanupPacketCapture(pcName)
			return nil
		}
		return err
	}

	switch pc.Status.Phase {
	case "":
		err = c.initPacketCapture(pc)
	case crdv1alpha1.PacketCaptureRunning:
		err = c.checkPacketCaptureStatus(pc)
	default:
		c.cleanupPacketCapture(pcName)
	}
	return err

}

// Allocates a tag. If the PacketCapture request has been allocated with a tag
// already, 0 is returned. If number of existing PacketCapture requests reaches
// the upper limit, an error is returned.
func (c *Controller) allocateTag(name string) (uint8, error) {
	c.runningPacketCapturesMutex.Lock()
	defer c.runningPacketCapturesMutex.Unlock()

	for _, state := range c.runningPacketCaptures {
		if state != nil && state.name == name {
			// The packetcapture request has been processed already.
			return 0, nil
		}
	}
	for i := minTagNum; i <= maxTagNum; i += 1 {
		if _, ok := c.runningPacketCaptures[i]; !ok {
			c.runningPacketCaptures[i] = &packetCaptureState{
				name: name,
				tag:  i,
			}
			return i, nil
		}
	}
	return 0, fmt.Errorf("number of on-going PacketCapture operations already reached the upper limit: %d", maxTagNum)
}

func (c *Controller) getUploaderByProtocol(protocol StorageProtocolType) (ftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func getDefaultFileServerAuth() *crdv1alpha1.BundleServerAuthConfiguration {
	return &crdv1alpha1.BundleServerAuthConfiguration{
		AuthType: crdv1alpha1.BasicAuthentication,
		AuthSecret: &v1.SecretReference{
			Name:      fileServerAuthSecretName,
			Namespace: fileServerAuthSecretNamespace,
		},
	}
}

func (c *Controller) uploadPackets(pc *crdv1alpha1.PacketCapture, outputFile afero.File) error {
	klog.V(2).InfoS("Uploading captured packets for PacketCapture", "name", pc.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload support bundle while getting uploader: %v", err)
	}
	authConfig := getDefaultFileServerAuth()
	serverAuth, err := ftp.ParseBundleAuth(*authConfig, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication defined in the PacketCapture CR", "name", pc.Name, "authentication", authConfig)
		return err
	}
	cfg := ftp.GenSSHClientConfig(serverAuth.BasicAuthentication.Username, serverAuth.BasicAuthentication.Password)
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(string(pc.UID)), cfg, outputFile)

}

// initPacketCapture mark the PacketCapture as running and allocate tag for it, then start the capture. the tag will
// serve as a unique id for concurrent processing.
func (c *Controller) initPacketCapture(pc *crdv1alpha1.PacketCapture) error {
	tag, err := c.allocateTag(pc.Name)
	if err != nil {
		return err
	}
	if tag == 0 {
		return nil
	}
	err = c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureRunning, "", 0)
	if err != nil {
		c.deallocateTag(pc.Name, tag)
		return err
	}
	return c.startPacketCapture(pc, c.runningPacketCaptures[tag])
}

func (c *Controller) updatePacketCaptureStatus(pc *crdv1alpha1.PacketCapture, phase crdv1alpha1.PacketCapturePhase, reason string, numCapturedPackets int32) error {
	type PacketCapture struct {
		Status crdv1alpha1.PacketCaptureStatus `json:"status,omitempty"`
	}
	patchData := PacketCapture{Status: crdv1alpha1.PacketCaptureStatus{Phase: phase}}
	if phase == crdv1alpha1.PacketCaptureRunning && pc.Status.StartTime == nil {
		t := metav1.Now()
		patchData.Status.StartTime = &t
	}
	if reason != "" {
		patchData.Status.Reason = reason
	}
	if numCapturedPackets != 0 {
		patchData.Status.NumCapturedPackets = &numCapturedPackets
	}
	if phase == crdv1alpha1.PacketCaptureSucceeded {
		patchData.Status.PacketsFileName = c.generatePacketsPathForServer(string(pc.UID))
	}
	payloads, _ := json.Marshal(patchData)
	_, err := c.crdClient.CrdV1alpha1().PacketCaptures().Patch(context.TODO(), pc.Name, types.MergePatchType, payloads, metav1.PatchOptions{}, "status")
	return err
}

func (c *Controller) deallocateTag(name string, tag uint8) {
	c.runningPacketCapturesMutex.Lock()
	defer c.runningPacketCapturesMutex.Unlock()
	if state, ok := c.runningPacketCaptures[tag]; ok {
		if state != nil && name == state.name {
			delete(c.runningPacketCaptures, tag)
		}
	}
}

func (c *Controller) getTagForPacketCapture(name string) uint8 {
	c.runningPacketCapturesMutex.RLock()
	defer c.runningPacketCapturesMutex.RUnlock()
	for tag, state := range c.runningPacketCaptures {
		if state != nil && state.name == name {
			// The packetcapture request has been processed already.
			return tag
		}
	}
	return 0
}

// checkPacketCaptureStatus is only called for PacketCaptures in the Running phase
func (c *Controller) checkPacketCaptureStatus(pc *crdv1alpha1.PacketCapture) error {
	tag := c.getTagForPacketCapture(pc.Name)
	if tag == 0 {
		return nil
	}
	if checkPacketCaptureSucceeded(pc) {
		c.deallocateTag(pc.Name, tag)
		return c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureSucceeded, "", 0)
	}

	if isPacketCaptureTimeout(pc) {
		c.deallocateTag(pc.Name, tag)
		return c.updatePacketCaptureStatus(pc, crdv1alpha1.PacketCaptureFailed, captureTimeoutReason, 0)
	}
	return nil
}

func checkPacketCaptureSucceeded(pc *crdv1alpha1.PacketCapture) bool {
	succeeded := false
	cfg := pc.Spec.CaptureConfig.FirstN
	captured := pc.Status.NumCapturedPackets
	if cfg != nil && captured != nil && *captured == cfg.Number {
		succeeded = true
	}
	return succeeded
}

func isPacketCaptureTimeout(pc *crdv1alpha1.PacketCapture) bool {
	var timeout time.Duration
	if pc.Spec.Timeout != nil {
		timeout = time.Duration(*pc.Spec.Timeout) * time.Second
	} else {
		timeout = defaultTimeoutDuration
	}
	var startTime time.Time
	if pc.Status.StartTime != nil {
		startTime = pc.Status.StartTime.Time
	} else {
		klog.V(2).InfoS("StartTime field in PacketCapture Status should not be empty", "PacketCapture", klog.KObj(pc))
		startTime = pc.CreationTimestamp.Time
	}
	return startTime.Add(timeout).Before(time.Now())
}
