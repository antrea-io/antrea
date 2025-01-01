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
	packetCapturePhasePending  packetCapturePhase = "Pending"
	packetCapturePhaseStarted  packetCapturePhase = "Started"
	packetCapturePhaseComplete packetCapturePhase = "Complete"
)

var (
	packetDirectory = filepath.Join(os.TempDir(), "antrea", "packetcapture", "packets")
	defaultFS       = afero.NewOsFs()
)

type packetCaptureState struct {
	// capturedPacketsNum records how many packets have been captured. Due to the RateLimiter,
	// this may not be the real-time data.
	capturedPacketsNum int32
	// targetCapturedPacketsNum is the target number limit for a PacketCapture. When numCapturedPackets == targetCapturedPacketsNum, it means
	// the PacketCapture is done successfully.
	targetCapturedPacketsNum int32
	// phase is the phase of the PacketCapture.
	phase packetCapturePhase
	// filePath is the final path shown in PacketCapture's status.
	filePath string
	// captureErr is the error observed during the capturing phase.
	captureErr error
	// uploadErr is the error observed during the uploading phase.
	uploadErr error
	// cancel is the cancel function for capture context.
	cancel context.CancelFunc
}

func (pcs *packetCaptureState) isCaptureSuccessful() bool {
	return pcs.capturedPacketsNum == pcs.targetCapturedPacketsNum && pcs.targetCapturedPacketsNum > 0
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
	device := c.getTargetCaptureDevice(pc)
	if device == "" {
		klog.V(4).InfoS("Skipping unrelated PacketCapture", "name", pcName)
		return nil
	}

	state, err := func() (packetCaptureState, error) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		state := c.captures[pcName]
		if state == nil {
			state = &packetCaptureState{
				phase:                    packetCapturePhasePending,
				targetCapturedPacketsNum: pc.Spec.CaptureConfig.FirstN.Number,
			}
			c.captures[pcName] = state
		}

		klog.V(2).InfoS("Processing PacketCapture", "name", pcName, "phase", state.phase)
		if state.phase != packetCapturePhasePending {
			return *state, nil
		}
		// Do not return the error as it's not a transient error.
		if err := c.validatePacketCapture(&pc.Spec); err != nil {
			state.captureErr = err
			return *state, nil
		}
		// Return the error as it's a transient error.
		if c.numRunningCaptures >= maxConcurrentCaptures {
			state.captureErr = fmt.Errorf("PacketCapture running count reach limit")
			return *state, state.captureErr
		}

		// The OpenAPI schema for the CRD makes sure Spec.Timeout is not nil.
		timeout := time.Duration(*pc.Spec.Timeout) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		state.cancel = cancel
		state.phase = packetCapturePhaseStarted
		// Start the capture goroutine in a separate goroutine. The goroutine will decrease numRunningCaptures on exit.
		c.numRunningCaptures += 1
		go c.startCapture(ctx, pc, state, device)
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

// getTargetCaptureDevice is trying to locate the target device for packet capture. If the target
// Pod does not exist on the current Node, the agent on this Node will not perform the capture.
// In the PacketCapture spec, at least one of `.Spec.Source.Pod` or `.Spec.Destination.Pod`
// should be set.
func (c *Controller) getTargetCaptureDevice(pc *crdv1alpha1.PacketCapture) string {
	var pod, ns string
	if pc.Spec.Source.Pod != nil {
		pod = pc.Spec.Source.Pod.Name
		ns = pc.Spec.Source.Pod.Namespace
	} else {
		pod = pc.Spec.Destination.Pod.Name
		ns = pc.Spec.Destination.Pod.Namespace
	}

	podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod, ns)
	if len(podInterfaces) == 0 {
		return ""
	}
	return podInterfaces[0].InterfaceName
}

func (c *Controller) startCapture(ctx context.Context, pc *crdv1alpha1.PacketCapture, state *packetCaptureState, device string) {
	klog.InfoS("Starting packet capture on the current Node", "name", pc.Name, "device", device)
	defer klog.InfoS("Stopped packet capture on the current Node", "name", pc.Name, "device", device)
	// Resync the PacketCapture on exit of the capture goroutine.
	defer c.enqueuePacketCapture(pc)

	var filePath string
	var captureErr, uploadErr error
	func() {
		localFilePath := nameToPath(pc.Name)
		file, err := getPacketFile(localFilePath)
		if err != nil {
			captureErr = err
			return
		}
		defer file.Close()

		var capturedAny bool
		capturedAny, captureErr = c.performCapture(ctx, pc, state, file, device)
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
		if uploadErr = c.uploadPackets(context.TODO(), pc, file); uploadErr != nil {
			return
		}
		filePath = fmt.Sprintf("%s/%s.pcapng", pc.Spec.FileServer.URL, pc.Name)
	}()

	if captureErr != nil {
		klog.ErrorS(captureErr, "PacketCapture failed capturing packets", "name", pc.Name)
	}
	if uploadErr != nil {
		klog.ErrorS(uploadErr, "PacketCapture failed uploading packets", "name", pc.Name)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	state.phase = packetCapturePhaseComplete
	state.filePath = filePath
	state.captureErr = captureErr
	state.uploadErr = uploadErr
	c.numRunningCaptures -= 1
}

// performCapture blocks until either the target number of packets have been captured, the context is canceled, or the
// context reaches its deadline.
// It returns a boolean indicating whether any packet is captured, and an error if the target number of packets are not
// captured.
func (c *Controller) performCapture(
	ctx context.Context,
	pc *crdv1alpha1.PacketCapture,
	captureState *packetCaptureState,
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
	packets, err := c.captureInterface.Capture(ctx, device, snapLen, srcIP, dstIP, pc.Spec.Packet, pc.Spec.Bidirection)
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
				captureState.capturedPacketsNum++
				klog.V(5).InfoS("Captured packets count", "name", pc.Name, "count", captureState.capturedPacketsNum)
				return captureState.isCaptureSuccessful()
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

func (c *Controller) uploadPackets(ctx context.Context, pc *crdv1alpha1.PacketCapture, outputFile afero.File) error {
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
	return uploader.Upload(pc.Spec.FileServer.URL, c.generatePacketsPathForServer(pc.Name), cfg, outputFile)
}

func (c *Controller) updateStatus(ctx context.Context, pc *crdv1alpha1.PacketCapture, state packetCaptureState) error {
	// Make a deepcopy as the object returned from lister must not be updated directly.
	toUpdate := pc.DeepCopy()
	var conditions []crdv1alpha1.PacketCaptureCondition
	t := metav1.Now()
	desiredStatus := crdv1alpha1.PacketCaptureStatus{
		NumberCaptured: state.capturedPacketsNum,
		FilePath:       state.filePath,
	}

	var conditionStarted, conditionComplete, conditionUploaded crdv1alpha1.PacketCaptureCondition
	switch state.phase {
	case packetCapturePhasePending:
		if state.captureErr != nil {
			conditionStarted = crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureStarted,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				LastTransitionTime: t,
				Reason:             "NotStarted",
				Message:            state.captureErr.Error(),
			}
		} else {
			conditionStarted = crdv1alpha1.PacketCaptureCondition{
				Type:               crdv1alpha1.PacketCaptureStarted,
				Status:             metav1.ConditionStatus(v1.ConditionFalse),
				LastTransitionTime: t,
				Reason:             "Pending",
			}
		}
		conditions = append(conditions, conditionStarted)
	case packetCapturePhaseStarted:
		conditionStarted = crdv1alpha1.PacketCaptureCondition{
			Type:               crdv1alpha1.PacketCaptureStarted,
			Status:             metav1.ConditionStatus(v1.ConditionTrue),
			LastTransitionTime: t,
			Reason:             "Started",
		}
		conditionComplete = crdv1alpha1.PacketCaptureCondition{
			Type:               crdv1alpha1.PacketCaptureComplete,
			Status:             metav1.ConditionStatus(v1.ConditionFalse),
			LastTransitionTime: t,
			Reason:             "Progressing",
		}
		conditions = append(conditions, conditionStarted, conditionComplete)
	case packetCapturePhaseComplete:
		conditionStarted = crdv1alpha1.PacketCaptureCondition{
			Type:               crdv1alpha1.PacketCaptureStarted,
			Status:             metav1.ConditionStatus(v1.ConditionTrue),
			LastTransitionTime: t,
			Reason:             "Started",
		}
		reason := "Succeed"
		message := ""
		if state.captureErr != nil {
			if errors.Is(state.captureErr, context.DeadlineExceeded) {
				reason = "Timeout"
			} else {
				reason = "Failed"
			}
			message = state.captureErr.Error()
		}
		conditionComplete = crdv1alpha1.PacketCaptureCondition{
			Type:               crdv1alpha1.PacketCaptureComplete,
			Status:             metav1.ConditionStatus(v1.ConditionTrue),
			LastTransitionTime: t,
			Reason:             reason,
			Message:            message,
		}
		conditions = append(conditions, conditionStarted, conditionComplete)
		// Set Uploaded condition if applicable.
		if state.capturedPacketsNum > 0 && pc.Spec.FileServer != nil {
			if state.uploadErr != nil {
				conditionUploaded = crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionFalse),
					LastTransitionTime: t,
					Reason:             "Failed",
					Message:            state.uploadErr.Error(),
				}
			} else {
				conditionUploaded = crdv1alpha1.PacketCaptureCondition{
					Type:               crdv1alpha1.PacketCaptureFileUploaded,
					Status:             metav1.ConditionStatus(v1.ConditionTrue),
					LastTransitionTime: t,
					Reason:             "Succeed",
				}
			}
			conditions = append(conditions, conditionUploaded)
		}
	}

	desiredStatus.Conditions = conditions

	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if packetCaptureStatusEqual(toUpdate.Status, desiredStatus) {
			return nil
		}

		desiredStatus.Conditions = mergeConditions(toUpdate.Status.Conditions, desiredStatus.Conditions)
		toUpdate.Status = desiredStatus
		klog.V(2).InfoS("Updating PacketCapture", "name", pc.Name, "status", toUpdate.Status)
		_, updateErr := c.crdClient.CrdV1alpha1().PacketCaptures().UpdateStatus(ctx, toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && apierrors.IsConflict(updateErr) {
			var getErr error
			if toUpdate, getErr = c.crdClient.CrdV1alpha1().PacketCaptures().Get(ctx, pc.Name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
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
