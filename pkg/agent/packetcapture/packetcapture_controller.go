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
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/afero"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/packetcapture/capture"
	"antrea.io/antrea/pkg/agent/util"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	clientsetversioned "antrea.io/antrea/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/util/auth"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/sftp"
)

type storageProtocolType string

const (
	sftpProtocol storageProtocolType = "sftp"
)

const (
	controllerName               = "PacketCaptureController"
	resyncPeriod   time.Duration = 0

	minRetryDelay = 500 * time.Millisecond
	maxRetryDelay = 30 * time.Second

	defaultWorkers = 4

	// defines how many capture request we can handle concurrently. waiting captures will be
	// marked as Pending until they can be processed.
	maxConcurrentCaptures     = 16
	captureStatusUpdatePeriod = 10 * time.Second
	// PacketCapture uses a dedicated Secret object to store authentication information for a file server.
	// #nosec G101
	fileServerAuthSecretName = "antrea-packetcapture-fileserver-auth"

	// max packet size we can capture.
	snapLen = 65536
)

type packetCapturePhase string

const (
	packetCapturePhasePending packetCapturePhase = "Pending"
	packetCapturePhaseStarted packetCapturePhase = "Started"
)

var (
	packetDirectory = filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
	defaultFS       = afero.NewOsFs()
)

type captureInstance struct {
	// complete indicates whether the capture process has completed (regardless of success or failure).
	complete bool
	// captureErr is the error observed during the packet capture process.
	captureErr error
	// uploadErr is the error observed during the uploading phase.
	uploadErr error
	// capturedPacketsNum records how many packets have been captured. Due to the RateLimiter,
	// this may not be the real-time data.
	capturedPacketsNum int32
	// filePath is the final path shown in PacketCapture's status.
	filePath string
}

type packetCaptureState struct {
	// phase is the phase of the PacketCapture.
	phase packetCapturePhase
	// initErr is an error that occurs before any capture goroutine is started.
	initErr error
	// cancel is the cancel function for capture context.
	cancel context.CancelFunc
	// instances holds the state for each capture location.
	instances map[crdv1alpha1.CaptureLocation]*captureInstance
}

func (ci *captureInstance) isCaptureSuccessful(target int32) bool {
	return ci.capturedPacketsNum == target && target > 0
}

type Controller struct {
	kubeClient            clientset.Interface
	crdClient             clientsetversioned.Interface
	packetCaptureInformer crdinformers.PacketCaptureInformer
	packetCaptureLister   crdlisters.PacketCaptureLister
	packetCaptureSynced   cache.InformerSynced
	interfaceStore        interfacestore.InterfaceStore
	queue                 workqueue.TypedRateLimitingInterface[string]
	sftpUploader          sftp.Uploader
	captureInterface      PacketCapturer
	mutex                 sync.Mutex
	// A name-state mapping for all PacketCapture CRs.
	captures           map[string]*packetCaptureState
	numRunningCaptures int
}

func NewPacketCaptureController(
	kubeClient clientset.Interface,
	crdClient clientsetversioned.Interface,
	packetCaptureInformer crdinformers.PacketCaptureInformer,
	interfaceStore interfacestore.InterfaceStore,
) (*Controller, error) {
	c := &Controller{
		kubeClient:            kubeClient,
		crdClient:             crdClient,
		packetCaptureInformer: packetCaptureInformer,
		packetCaptureLister:   packetCaptureInformer.Lister(),
		packetCaptureSynced:   packetCaptureInformer.Informer().HasSynced,
		interfaceStore:        interfaceStore,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "packetcapture"},
		),
		sftpUploader: sftp.NewUploader(),
		captures:     make(map[string]*packetCaptureState),
	}

	packetCaptureInformer.Informer().AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addPacketCapture,
		UpdateFunc: c.updatePacketCapture,
		DeleteFunc: c.deletePacketCapture,
	}, resyncPeriod)

	capture, err := capture.NewPcapCapture()
	if err != nil {
		return nil, err
	}
	c.captureInterface = capture
	return c, nil
}

func (c *Controller) enqueuePacketCapture(pc *crdv1alpha1.PacketCapture) {
	c.queue.Add(pc.Name)
}

// Run will create defaultWorkers workers (go routines) which will process the PacketCapture events from the
// workqueue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting controller", "name", controllerName)
	defer klog.InfoS("Shutting down controller", "name", controllerName)

	cacheSynced := []cache.InformerSynced{c.packetCaptureSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSynced...) {
		return
	}

	err := defaultFS.MkdirAll(packetDirectory, 0700)
	if err != nil {
		klog.ErrorS(err, "Couldn't create the directory for storing captured packets", "directory", packetDirectory)
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) addPacketCapture(obj interface{}) {
	pc := obj.(*crdv1alpha1.PacketCapture)
	klog.V(2).InfoS("Processing PacketCapture ADD event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func (c *Controller) updatePacketCapture(oldObj, newObj interface{}) {
	newPC := newObj.(*crdv1alpha1.PacketCapture)
	oldPC := oldObj.(*crdv1alpha1.PacketCapture)
	if newPC.Generation != oldPC.Generation {
		klog.V(2).InfoS("Processing PacketCapture UPDATE event", "name", newPC.Name)
		c.enqueuePacketCapture(newPC)
	}
}

func (c *Controller) deletePacketCapture(obj interface{}) {
	pc, ok := obj.(*crdv1alpha1.PacketCapture)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		pc, ok = deletedState.Obj.(*crdv1alpha1.PacketCapture)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-PacketCapture object: %v", deletedState.Obj)
			return
		}
	}
	klog.V(2).InfoS("Processing PacketCapture DELETE event", "name", pc.Name)
	c.enqueuePacketCapture(pc)
}

func nameToPath(name string) string {
	return filepath.Join(packetDirectory, name+".pcapng")
}

func (c *Controller) worker() {
	for c.processPacketCaptureItem() {
	}
}

func (c *Controller) processPacketCaptureItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	if err := c.syncPacketCapture(key); err == nil {
		c.queue.Forget(key)
	} else {
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing PacketCapture, requeueing", "key", key)
	}
	return true
}

func (c *Controller) syncPacketCapture(pcName string) error {
	pc, err := c.packetCaptureLister.Get(pcName)
	// Lister.Get only returns error when the resource is not found.
	if err != nil {
		c.cleanupPacketCapture(pcName)
		return nil
	}

	// Capture will not occur on this Node if a corresponding Pod interface is not found.
	devices := c.getTargetCaptureDevices(pc)
	if len(devices) == 0 {
		klog.V(4).InfoS("Skipping unrelated PacketCapture", "name", pcName)
		return nil
	}

	state, err := func() (packetCaptureState, error) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		state := c.captures[pcName]
		if state == nil {
			state = &packetCaptureState{
				phase:     packetCapturePhasePending,
				instances: make(map[crdv1alpha1.CaptureLocation]*captureInstance),
			}
			for location := range devices {
				state.instances[location] = &captureInstance{}
			}
			c.captures[pcName] = state
		}

		klog.V(2).InfoS("Processing PacketCapture", "name", pcName, "phase", state.phase)
		if state.phase != packetCapturePhasePending {
			return *state, nil
		}
		// Do not return the error as it's not a transient error.
		if err := c.validatePacketCapture(&pc.Spec); err != nil {
			state.initErr = err
			return *state, nil
		}
		// Return the error as it's a transient error.
		if c.numRunningCaptures >= maxConcurrentCaptures {
			state.initErr = fmt.Errorf("PacketCapture running count reach limit")
			return *state, state.initErr
		}

		// The OpenAPI schema for the CRD makes sure Spec.Timeout is not nil.
		timeout := time.Duration(*pc.Spec.Timeout) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		state.cancel = cancel
		state.phase = packetCapturePhaseStarted
		// Start the capture goroutine(s) in separate goroutines. Each will dec numRunningCaptures on exit.
		c.numRunningCaptures += len(devices)
		for location, device := range devices {
			go c.startCapture(ctx, pc, state, device, location)
		}
		return *state, nil
	}()

	if updateErr := c.updateStatus(context.Background(), pc, state); updateErr != nil {
		return fmt.Errorf("error when patching status: %w", updateErr)
	}
	return err
}

func (c *Controller) validatePacketCapture(spec *crdv1alpha1.PacketCaptureSpec) error {
	if spec.Packet != nil {
		protocol := spec.Packet.Protocol
		if protocol != nil {
			if protocol.Type == intstr.String {
				if _, ok := capture.ProtocolMap[strings.ToUpper(protocol.StrVal)]; !ok {
					return fmt.Errorf("invalid protocol string, supported values are: %v (case insensitive)", slices.Collect(maps.Keys(capture.ProtocolMap)))
				}
			}
		}
		if spec.Packet.TransportHeader.ICMP != nil {
			for _, f := range spec.Packet.TransportHeader.ICMP.Messages {
				switch f.Type.Type {
				case intstr.Int:
					if f.Type.IntVal < 0 || f.Type.IntVal > 255 {
						return fmt.Errorf("invalid ICMP type integer: %d; must be between 0 and 255", f.Type.IntVal)
					}
				case intstr.String:
					if _, ok := capture.ICMPMsgTypeMap[crdv1alpha1.ICMPMsgType(strings.ToLower(f.Type.StrVal))]; !ok {
						return fmt.Errorf("invalid ICMP type string: %q; supported values are: %v (case insensitive)",
							f.Type.StrVal, slices.Collect(maps.Keys(capture.ICMPMsgTypeMap)))
					}
				}
			}
		}
	}
	return nil
}

func (c *Controller) cleanupPacketCapture(pcName string) {
	path := nameToPath(pcName)
	if err := defaultFS.RemoveAll(path); err == nil {
		klog.V(2).InfoS("Deleted the captured pcap file successfully", "name", pcName, "path", path)
	} else {
		klog.ErrorS(err, "Failed to delete the captured pcap file", "name", pcName, "path", path)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	state := c.captures[pcName]
	if state != nil {
		if state.cancel != nil {
			state.cancel()
		}
		delete(c.captures, pcName)
	}
}

func getPacketFile(filePath string) (afero.File, error) {
	var file afero.File
	if _, err := os.Stat(filePath); err == nil {
		klog.InfoS("Packet file already exists. This may be caused by an unexpected termination, will delete it", "path", filePath)
		if err := defaultFS.Remove(filePath); err != nil {
			return nil, err
		}
	}
	file, err := defaultFS.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcapng file: %w", err)
	}
	return file, nil
}

// getTargetCaptureDevices is trying to locate the target devices for packet capture. If the target
// Pod does not exist on the current Node, the agent on this Node will not perform the capture.
// In the PacketCapture spec, at least one of `.Spec.Source.Pod` or `.Spec.Destination.Pod`
// should be set.
func (c *Controller) getTargetCaptureDevices(pc *crdv1alpha1.PacketCapture) map[crdv1alpha1.CaptureLocation]string {
	devices := make(map[crdv1alpha1.CaptureLocation]string)

	// Set CaptureLocation to 'Source' if a Source Pod is specified; otherwise, use 'Destination'.
	if pc.Spec.CaptureLocation == "" {
		if pc.Spec.Source.Pod != nil {
			pc.Spec.CaptureLocation = crdv1alpha1.CaptureLocationSource
		} else {
			pc.Spec.CaptureLocation = crdv1alpha1.CaptureLocationDestination
		}
	}

	// First, determine if the source and/or destination Pods are on the current Node.
	var sourceDevice, destinationDevice string
	if pc.Spec.Source.Pod != nil {
		sourceDevice = c.getPodDevice(pc.Spec.Source.Pod)
	}
	if pc.Spec.Destination.Pod != nil {
		destinationDevice = c.getPodDevice(pc.Spec.Destination.Pod)
	}

	if (pc.Spec.CaptureLocation == crdv1alpha1.CaptureLocationSource || pc.Spec.CaptureLocation == crdv1alpha1.CaptureLocationBoth) && sourceDevice != "" {
		devices[crdv1alpha1.CaptureLocationSource] = sourceDevice
	}
	if (pc.Spec.CaptureLocation == crdv1alpha1.CaptureLocationDestination || pc.Spec.CaptureLocation == crdv1alpha1.CaptureLocationBoth) && destinationDevice != "" {
		devices[crdv1alpha1.CaptureLocationDestination] = destinationDevice
	}
	return devices
}

// getPodDevice returns the network device name for the given PodReference using the interfaceStore.
func (c *Controller) getPodDevice(pod *crdv1alpha1.PodReference) string {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod.Name, pod.Namespace)
	if len(podInterfaces) == 0 {
		return ""
	}
	return podInterfaces[0].InterfaceName
}

func (c *Controller) startCapture(ctx context.Context, pc *crdv1alpha1.PacketCapture, state *packetCaptureState, device string, location crdv1alpha1.CaptureLocation) {
	klog.InfoS("Starting packet capture on the current Node", "name", pc.Name, "device", device)
	defer klog.InfoS("Stopped packet capture on the current Node", "name", pc.Name, "device", device)
	// Resync the PacketCapture on exit of the capture goroutine.
	defer c.enqueuePacketCapture(pc)

	var filePath string
	var captureErr, uploadErr error
	instance := state.instances[location]
	func() {
		localFileName := fmt.Sprintf("%s-%s-%s", pc.Name, location, env.GetPodName())
		localFilePath := nameToPath(localFileName)
		file, err := getPacketFile(localFilePath)
		if err != nil {
			captureErr = err
			return
		}
		defer file.Close()

		var capturedAny bool
		capturedAny, captureErr = c.performCapture(ctx, pc, instance, file, device)
		// If nothing is captured, no need to proceed.
		if !capturedAny {
			return
		}
		// If any is captured, upload it if required and update filePath in the status of the PacketCapture.
		filePath = env.GetPodName() + ":" + localFilePath

		if pc.Spec.FileServer == nil {
			return
		}
		// It can't use the same context as performCapture because it might have timed out.
		if uploadErr = c.uploadPackets(context.TODO(), pc, file, location); uploadErr != nil {
			return
		}
		filePath = fmt.Sprintf("%s/%s-%s-%s.pcapng", pc.Spec.FileServer.URL, pc.Name, location, env.GetPodName())
	}()

	if captureErr != nil {
		klog.ErrorS(captureErr, "PacketCapture failed capturing packets", "name", pc.Name)
	}
	if uploadErr != nil {
		klog.ErrorS(uploadErr, "PacketCapture failed uploading packets", "name", pc.Name)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	instance.complete = true
	instance.filePath = filePath
	instance.captureErr = captureErr
	instance.uploadErr = uploadErr
	c.numRunningCaptures -= 1
}

// performCapture blocks until either the target number of packets have been captured, the context is canceled, or the
// context reaches its deadline.
// It returns a boolean indicating whether any packet is captured, and an error if the target number of packets are not
// captured.
func (c *Controller) performCapture(
	ctx context.Context,
	pc *crdv1alpha1.PacketCapture,
	instance *captureInstance,
	file afero.File,
	device string,
) (bool, error) {
	srcIP, dstIP, err := c.parseIPs(ctx, pc)
	if err != nil {
		return false, err
	}

	// set SnapLength here to make tcpdump on Mac OSX works. By default, its value is
	// 0 and means unlimited, but tcpdump on Mac OSX will complain:
	// 'tcpdump: pcap_loop: invalid packet capture length <len>, bigger than snaplen of 524288'
	ngInterface := pcapgo.DefaultNgInterface
	ngInterface.SnapLength = snapLen
	ngInterface.LinkType = layers.LinkTypeEthernet
	pcapngWriter, err := pcapgo.NewNgWriterInterface(file, ngInterface, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return false, fmt.Errorf("couldn't initialize a pcap writer: %w", err)
	}
	defer pcapngWriter.Flush()
	updateRateLimiter := rate.NewLimiter(rate.Every(captureStatusUpdatePeriod), 1)
	packets, err := c.captureInterface.Capture(ctx, device, snapLen, srcIP, dstIP, pc.Spec.Packet, pc.Spec.Direction)
	if err != nil {
		return false, err
	}
	// Track whether any packet is captured.
	capturedAny := false
	for {
		select {
		case packet := <-packets:
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(packet.Data()),
				Length:        len(packet.Data()),
			}
			klog.V(5).InfoS("Captured packet", "name", pc.Name, "len", ci.Length)
			if err = pcapngWriter.WritePacket(ci, packet.Data()); err != nil {
				return capturedAny, fmt.Errorf("couldn't write packets: %w", err)
			}
			capturedAny = true

			if success := func() bool {
				c.mutex.Lock()
				defer c.mutex.Unlock()
				instance.capturedPacketsNum++
				klog.V(5).InfoS("Captured packets count", "name", pc.Name, "count", instance.capturedPacketsNum)
				return instance.isCaptureSuccessful(pc.Spec.CaptureConfig.FirstN.Number)
			}(); success {
				return true, nil
			}
			// use rate limiter to reduce the times we need to update status.
			if updateRateLimiter.Allow() {
				c.enqueuePacketCapture(pc)
			}
		case <-ctx.Done():
			return capturedAny, ctx.Err()
		}
	}
}

func (c *Controller) getPodIP(ctx context.Context, podRef *crdv1alpha1.PodReference) (net.IP, error) {
	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(podRef.Name, podRef.Namespace)
	var podIP net.IP
	if len(podInterfaces) > 0 {
		podIP = podInterfaces[0].GetIPv4Addr()
	} else {
		pod, err := c.kubeClient.CoreV1().Pods(podRef.Namespace).Get(ctx, podRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get Pod %s/%s: %w", podRef.Namespace, podRef.Name, err)
		}
		podIPs := make([]net.IP, len(pod.Status.PodIPs))
		for i, ip := range pod.Status.PodIPs {
			podIPs[i] = net.ParseIP(ip.IP)
		}
		podIP = util.GetIPv4Addr(podIPs)
	}
	if podIP == nil {
		return nil, fmt.Errorf("cannot find IP with IPv4 address family for Pod %s/%s", podRef.Namespace, podRef.Name)
	}
	return podIP, nil
}

func (c *Controller) parseIPs(ctx context.Context, pc *crdv1alpha1.PacketCapture) (srcIP, dstIP net.IP, err error) {
	if pc.Spec.Source.Pod != nil {
		srcIP, err = c.getPodIP(ctx, pc.Spec.Source.Pod)
		if err != nil {
			return
		}
	} else if pc.Spec.Source.IP != nil {
		srcIP = net.ParseIP(*pc.Spec.Source.IP)
		if srcIP == nil {
			err = fmt.Errorf("invalid source IP address: %s", *pc.Spec.Source.IP)
			return
		}
	}
	if pc.Spec.Destination.Pod != nil {
		dstIP, err = c.getPodIP(ctx, pc.Spec.Destination.Pod)
		if err != nil {
			return
		}
	} else if pc.Spec.Destination.IP != nil {
		dstIP = net.ParseIP(*pc.Spec.Destination.IP)
		if dstIP == nil {
			err = fmt.Errorf("invalid destination IP address: %s", *pc.Spec.Destination.IP)
		}
	}
	return
}

func (c *Controller) getUploaderByProtocol(protocol storageProtocolType) (sftp.Uploader, error) {
	if protocol == sftpProtocol {
		return c.sftpUploader, nil
	}
	return nil, fmt.Errorf("unsupported protocol %s", protocol)
}

func (c *Controller) generatePacketsPathForServer(name string) string {
	return name + ".pcapng"
}

func (c *Controller) uploadPackets(ctx context.Context, pc *crdv1alpha1.PacketCapture, outputFile afero.File, location crdv1alpha1.CaptureLocation) error {
	klog.V(2).InfoS("Uploading captured packets for PacketCapture", "name", pc.Name)
	uploader, err := c.getUploaderByProtocol(sftpProtocol)
	if err != nil {
		return fmt.Errorf("failed to upload packets while getting uploader: %w", err)
	}
	if _, err := outputFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to upload to the file server while setting offset: %v", err)
	}
	authSecret := v1.SecretReference{
		Name:      fileServerAuthSecretName,
		Namespace: env.GetAntreaNamespace(),
	}
	serverAuth, err := auth.GetAuthConfigurationFromSecret(ctx, auth.BasicAuthenticationType, &authSecret, c.kubeClient)
	if err != nil {
		klog.ErrorS(err, "Failed to get authentication for the file server", "name", pc.Name, "authSecret", authSecret)
		return err
	}
	if serverAuth.BasicAuthentication == nil {
		return fmt.Errorf("failed to get basic authentication info for the file server")
	}
	cfg, err := sftp.GetSSHClientConfig(
		serverAuth.BasicAuthentication.Username,
		serverAuth.BasicAuthentication.Password,
		pc.Spec.FileServer.HostPublicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to generate SSH client config: %w", err)
	}
	localFileName := fmt.Sprintf("%s-%s-%s", pc.Name, location, env.GetPodName())
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(localFileName), cfg, outputFile)
}

func getFirstPath(paths []string) string {
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}

func buildPendingCondition(t metav1.Time, state packetCaptureState) crdv1alpha1.PacketCaptureCondition {
	reason, message := "Pending", ""
	if state.initErr != nil {
		reason, message = "NotStarted", state.initErr.Error()
	}
	return crdv1alpha1.PacketCaptureCondition{
		Type:               crdv1alpha1.PacketCaptureStarted,
		Status:             metav1.ConditionStatus(v1.ConditionFalse),
		Reason:             reason,
		Message:            message,
		LastTransitionTime: t,
	}
}

func buildStartedCondition(t metav1.Time) crdv1alpha1.PacketCaptureCondition {
	return crdv1alpha1.PacketCaptureCondition{
		Type:               crdv1alpha1.PacketCaptureStarted,
		Status:             metav1.ConditionStatus(v1.ConditionTrue),
		Reason:             "Started",
		LastTransitionTime: t,
	}
}

func buildLocationConditions(pc *crdv1alpha1.PacketCapture, state packetCaptureState, t metav1.Time) []crdv1alpha1.PacketCaptureCondition {
	var conditions []crdv1alpha1.PacketCaptureCondition
	for location, instance := range state.instances {
		compCondType := crdv1alpha1.PacketCaptureAtSrcComplete
		if location == crdv1alpha1.CaptureLocationDestination {
			compCondType = crdv1alpha1.PacketCaptureAtDstComplete
		}

		if !instance.complete {
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               compCondType,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				Reason:             "Progressing",
				LastTransitionTime: t,
			})
			continue
		}

		// Add capture completion status.
		compReason, compMsg := "Succeed", ""
		if instance.captureErr != nil {
			compReason = "Failed"
			if errors.Is(instance.captureErr, context.DeadlineExceeded) {
				compReason = "Timeout"
			}
			compMsg = instance.captureErr.Error()
		}
		conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
			Type:               compCondType,
			Status:             metav1.ConditionStatus(v1.ConditionTrue),
			Reason:             compReason,
			Message:            compMsg,
			LastTransitionTime: t,
		})

		// Add upload completion status if applicable.
		if pc.Spec.FileServer != nil && instance.capturedPacketsNum > 0 {
			upCondType := crdv1alpha1.PacketCaptureAtSrcFileUploaded
			if location == crdv1alpha1.CaptureLocationDestination {
				upCondType = crdv1alpha1.PacketCaptureAtDstFileUploaded
			}
			upStatus, upReason, upMsg := metav1.ConditionStatus(v1.ConditionTrue), "Succeed", ""
			if instance.uploadErr != nil {
				upStatus, upReason, upMsg = metav1.ConditionStatus(v1.ConditionFalse), "Failed", instance.uploadErr.Error()
			}
			conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
				Type:               upCondType,
				Status:             upStatus,
				Reason:             upReason,
				Message:            upMsg,
				LastTransitionTime: t,
			})
		}
	}
	return conditions
}

func determineOverallStatus(
	pc *crdv1alpha1.PacketCapture,
	state packetCaptureState,
	finalConditionMap map[crdv1alpha1.PacketCaptureConditionType]crdv1alpha1.PacketCaptureCondition,
	t metav1.Time,
) (
	overallConditions []crdv1alpha1.PacketCaptureCondition,
	isFinalized bool,
) {
	srcCond, srcExists := finalConditionMap[crdv1alpha1.PacketCaptureAtSrcComplete]
	dstCond, dstExists := finalConditionMap[crdv1alpha1.PacketCaptureAtDstComplete]
	isSrcFinished := srcExists && srcCond.Status == metav1.ConditionTrue
	isDstFinished := dstExists && dstCond.Status == metav1.ConditionTrue

	var overallComplete bool
	switch pc.Spec.CaptureLocation {
	case crdv1alpha1.CaptureLocationSource:
		overallComplete = isSrcFinished
	case crdv1alpha1.CaptureLocationDestination:
		overallComplete = isDstFinished
	case crdv1alpha1.CaptureLocationBoth:
		overallComplete = isSrcFinished && isDstFinished
	}

	if !overallComplete {
		return nil, false
	}

	// Finalize PacketCaptureComplete status
	completeReason := "Succeed"
	completeMessage := ""
	if srcExists && srcCond.Reason == "Timeout" || dstExists && dstCond.Reason == "Timeout" {
		completeReason, completeMessage = "Timeout", "one or more locations timed out"
	}
	if srcExists && srcCond.Reason == "Failed" || dstExists && dstCond.Reason == "Failed" {
		completeReason, completeMessage = "Failed", "one or more locations failed to capture"
	}
	if state.initErr != nil {
		completeReason, completeMessage = "Failed", state.initErr.Error()
	}
	overallConditions = append(overallConditions, crdv1alpha1.PacketCaptureCondition{
		Type:               crdv1alpha1.PacketCaptureComplete,
		Status:             metav1.ConditionStatus(v1.ConditionTrue),
		Reason:             completeReason,
		Message:            completeMessage,
		LastTransitionTime: t,
	})

	// Finalize PacketCaptureFileUploaded status (if applicable)
	if pc.Spec.FileServer != nil {
		srcUploadCond, srcUploadExists := finalConditionMap[crdv1alpha1.PacketCaptureAtSrcFileUploaded]
		dstUploadCond, dstUploadExists := finalConditionMap[crdv1alpha1.PacketCaptureAtDstFileUploaded]

		var overallUpload bool
		switch pc.Spec.CaptureLocation {
		case crdv1alpha1.CaptureLocationSource:
			overallUpload = srcUploadExists
		case crdv1alpha1.CaptureLocationDestination:
			overallUpload = dstUploadExists
		case crdv1alpha1.CaptureLocationBoth:
			overallUpload = srcUploadExists && dstUploadExists
		}

		if overallUpload {
			uploadStatus, uploadReason, uploadMessage := metav1.ConditionStatus(v1.ConditionTrue), "Succeed", ""
			anyUploadFailed := (srcUploadCond.Status == metav1.ConditionFalse) || (dstUploadCond.Status == metav1.ConditionFalse)
			if anyUploadFailed {
				uploadStatus, uploadReason, uploadMessage = metav1.ConditionStatus(v1.ConditionFalse), "Failed", "one or more files failed to upload"
			}
			overallConditions = append(overallConditions, crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureFileUploaded,
				Status:             uploadStatus,
				Reason:             uploadReason,
				Message:            uploadMessage,
				LastTransitionTime: t,
			})
		}
	}
	return overallConditions, true
}

func (c *Controller) updateStatus(ctx context.Context, pc *crdv1alpha1.PacketCapture, state packetCaptureState) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	localState := state

	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Get the latest version of the PacketCapture to avoid working with a stale object.
		// This is crucial for handling concurrent updates from different agents.
		latestPC, err := c.crdClient.CrdV1alpha1().PacketCaptures().Get(ctx, pc.Name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		toUpdate := latestPC

		var conditions []crdv1alpha1.PacketCaptureCondition
		t := metav1.Now()

		switch localState.phase {
		case packetCapturePhasePending:
			conditions = append(conditions, buildPendingCondition(t, localState))
		case packetCapturePhaseStarted:
			conditions = append(conditions, buildStartedCondition(t))

			conditions = append(conditions, buildLocationConditions(pc, localState, t)...)

			conditions = mergeConditions(toUpdate.Status.Conditions, conditions)
			finalConditionMap := make(map[crdv1alpha1.PacketCaptureConditionType]crdv1alpha1.PacketCaptureCondition)
			for _, cond := range conditions {
				finalConditionMap[cond.Type] = cond
			}

			var overallConditions []crdv1alpha1.PacketCaptureCondition
			var isFinalized bool
			if overallConditions, isFinalized = determineOverallStatus(pc, localState, finalConditionMap, t); isFinalized {
				conditions = append(conditions, overallConditions...)
			} else {
				conditions = append(conditions, crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketCaptureComplete,
					Status:             metav1.ConditionStatus(v1.ConditionFalse),
					Reason:             "Progressing",
					LastTransitionTime: t,
				})
			}
		}
		// Create a set of file paths to update, combining existing and new paths
		pathSet := sets.New(toUpdate.Status.FilePaths...)

		numberCaptured := toUpdate.Status.NumberCaptured
		for _, instance := range localState.instances {
			numberCaptured = max(numberCaptured, instance.capturedPacketsNum)
			if instance.filePath != "" {
				pathSet.Insert(instance.filePath)
			}
		}

		allPaths := sets.List(pathSet)
		sort.Strings(allPaths)

		desiredStatus := crdv1alpha1.PacketCaptureStatus{
			NumberCaptured: numberCaptured,
			FilePath:       getFirstPath(allPaths),
			FilePaths:      allPaths,
			Conditions:     mergeConditions(toUpdate.Status.Conditions, conditions),
		}
		if packetCaptureStatusEqual(toUpdate.Status, desiredStatus) {
			return nil
		}
		toUpdate.Status = desiredStatus
		klog.V(2).InfoS("Updating PacketCapture", "name", pc.Name, "status", toUpdate.Status)
		_, updateErr := c.crdClient.CrdV1alpha1().PacketCaptures().UpdateStatus(ctx, toUpdate, metav1.UpdateOptions{})
		// Return the error from UPDATE.
		return updateErr
	}); retryErr != nil {
		return retryErr
	}
	klog.V(2).InfoS("Updated PacketCapture", "name", pc.Name)
	return nil
}

func conditionEqualsIgnoreLastTransitionTime(a, b crdv1alpha1.PacketCaptureCondition) bool {
	a1 := a
	a1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := b
	b1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return a1 == b1
}

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	conditionSliceEqualsIgnoreLastTransitionTime,
)

func packetCaptureStatusEqual(oldStatus, newStatus crdv1alpha1.PacketCaptureStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

func conditionSliceEqualsIgnoreLastTransitionTime(as, bs []crdv1alpha1.PacketCaptureCondition) bool {
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		a := as[i]
		b := bs[i]
		if !conditionEqualsIgnoreLastTransitionTime(a, b) {
			return false
		}
	}
	return true
}

func mergeConditions(oldConditions, newConditions []crdv1alpha1.PacketCaptureCondition) []crdv1alpha1.PacketCaptureCondition {
	finalConditions := make([]crdv1alpha1.PacketCaptureCondition, 0)
	newConditionMap := make(map[crdv1alpha1.PacketCaptureConditionType]crdv1alpha1.PacketCaptureCondition)
	addedConditions := sets.New[string]()
	for _, condition := range newConditions {
		newConditionMap[condition.Type] = condition
	}
	for _, oldCondition := range oldConditions {
		newCondition, exists := newConditionMap[oldCondition.Type]
		if !exists {
			finalConditions = append(finalConditions, oldCondition)
			continue
		}
		// Use the original Condition if the only change is about lastTransition time
		if conditionEqualsIgnoreLastTransitionTime(newCondition, oldCondition) {
			finalConditions = append(finalConditions, oldCondition)
		} else {
			// Use the latest Condition.
			finalConditions = append(finalConditions, newCondition)
		}
		addedConditions.Insert(string(newCondition.Type))
	}
	for key, newCondition := range newConditionMap {
		if !addedConditions.Has(string(key)) {
			finalConditions = append(finalConditions, newCondition)
		}
	}
	return finalConditions
}
