/*
Copyright 2021 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commonarea

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

const (
	TimestampAnnotationKey = "touch-ts"
)

var (
	ReasonDisconnected       = "Disconnected"
	ReasonElectionInProgress = "LeaderElectionInProgress"
)

// RemoteCommonArea is an abstraction to connect to CommonArea of the Leader Cluster.
type RemoteCommonArea interface {
	CommonArea

	Start() (context.CancelFunc, error)

	Stop() error

	// IsConnected returns whether the RemoteCommonArea is accessible or not.
	IsConnected() bool

	// StartWatching sets up a Manager to reconcile resource crud operations from CommonArea of RemoteCommonArea.
	StartWatching() error

	// StopWatching stops the Manager so the crud operations in RemoteCommonArea no longer invoke the reconcilers.
	StopWatching()

	GetStatus() []multiclusterv1alpha1.ClusterCondition
}

// remoteCommonArea implements the CommonArea interface and allows local cluster to read/write into
// the CommonArea of RemoteCommonArea.
type remoteCommonArea struct {
	// mutex to synchronize access to connectivity state since it is updated by
	// a background routine running in remoteCommonArea and read from the LeaderElector
	// background routine.
	mutex sync.RWMutex

	// client that provides read/write access into the remoteCommonArea.
	client.Client

	// ClusterManager to set up controllers for resources that need to be monitored in the remoteCommonArea.
	ClusterManager manager.Manager

	// ClusterID of this remoteCommonArea.
	ClusterID common.ClusterID

	// ClusterSetID of this remoteCommonArea.
	ClusterSetID common.ClusterSetID

	// config necessary to access the remoteCommonArea.
	config *rest.Config

	// scheme necessary to access the remoteCommonArea.
	scheme *runtime.Scheme

	// Namespace this ClusterSet is associated with.
	Namespace string

	// connected is a state to know whether the remoteCommonArea is connected or not.
	connected bool

	clusterStatus multiclusterv1alpha1.ClusterCondition
	leaderStatus  multiclusterv1alpha1.ClusterCondition

	// client that provides read/write access into the local cluster
	localClusterClient client.Client

	remoteCommonAreaManager RemoteCommonAreaManager

	// stopFunc to stop all background operations when the RemoteCommonArea is stopped.
	stopFunc context.CancelFunc

	// managerStopFunc to stop the manager when the RemoteCommonArea is stopped.
	managerStopFunc context.CancelFunc
}

// NewRemoteCommonArea returns a RemoteCommonArea instance which will use access credentials from the Secret to
// connect to the leader cluster's CommonArea.
func NewRemoteCommonArea(clusterID common.ClusterID, clusterSetID common.ClusterSetID, url string, secret *v1.Secret,
	scheme *runtime.Scheme, localClusterClient client.Client, remoteCommonAreaManager RemoteCommonAreaManager,
	clusterSetNamespace string) (CommonArea, error) {
	klog.InfoS("Create a RemoteCommonArea", "Cluster", clusterID)

	crtData, token, err := getSecretCACrtAndToken(secret)
	if err != nil {
		return nil, err
	}

	// Create manager for the RemoteCommonArea
	klog.InfoS("Connecting to RemoteCommonArea", "Cluster", clusterID, "url", url)
	config, err := clientcmd.BuildConfigFromFlags(url, "")
	if err != nil {
		return nil, err
	}
	config.BearerToken = string(token)
	config.CAData = crtData
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
		Namespace:          clusterSetNamespace,
	})
	if err != nil {
		klog.ErrorS(err, "Error creating manager for RemoteCommonArea", "Cluster", clusterID)
		return nil, err
	}

	remoteClient, e := client.New(config, client.Options{Scheme: scheme})
	if e != nil {
		return nil, e
	}

	remote := &remoteCommonArea{
		Client:                  remoteClient,
		ClusterManager:          mgr,
		ClusterSetID:            clusterSetID,
		ClusterID:               clusterID,
		config:                  config,
		scheme:                  scheme,
		Namespace:               clusterSetNamespace,
		connected:               false,
		localClusterClient:      localClusterClient,
		remoteCommonAreaManager: remoteCommonAreaManager,
	}
	remote.clusterStatus.Type = multiclusterv1alpha1.ClusterReady
	remote.clusterStatus.Status = v1.ConditionUnknown
	remote.clusterStatus.Message = "Leader cluster added"
	remote.clusterStatus.LastTransitionTime = metav1.Now()
	remote.leaderStatus.Type = multiclusterv1alpha1.ClusterIsElectedLeader
	remote.leaderStatus.Status = v1.ConditionFalse
	remote.leaderStatus.Message = "Leader cluster added"
	remote.leaderStatus.LastTransitionTime = metav1.Now()

	remoteCommonAreaManager.AddRemoteCommonArea(remote)

	return remote, nil
}

/**
 * getSecretCACrtAndToken returns the access credentials from Secret.
 */
func getSecretCACrtAndToken(secretObj *v1.Secret) ([]byte, []byte, error) {
	caData, found := secretObj.Data[v1.ServiceAccountRootCAKey]
	if !found {
		return nil, nil, fmt.Errorf("ca.crt data not found in Secret %v", secretObj.GetName())
	}

	token, found := secretObj.Data[v1.ServiceAccountTokenKey]
	if !found {
		return nil, nil, fmt.Errorf("token not found in Secret %v", secretObj.GetName())
	}

	return caData, token, nil
}

func (r *remoteCommonArea) SendMemberAnnounce() error {
	memberAnnounceList := &multiclusterv1alpha1.MemberClusterAnnounceList{}
	if err := r.List(context.TODO(), memberAnnounceList, client.InNamespace(r.GetNamespace())); err != nil {
		return err
	}
	var localClusterMemberAnnounce multiclusterv1alpha1.MemberClusterAnnounce
	localClusterMemberAnnounceExist := false
	if len(memberAnnounceList.Items) != 0 {
		for _, memberAnnounce := range memberAnnounceList.Items {
			if memberAnnounce.ClusterID == string(r.remoteCommonAreaManager.GetLocalClusterID()) {
				localClusterMemberAnnounceExist = true
				localClusterMemberAnnounce = memberAnnounce
				break
			}
		}
	}
	if localClusterMemberAnnounceExist {
		localClusterMemberAnnounce.LeaderClusterID = ""
		leaderID := r.remoteCommonAreaManager.GetElectedLeaderClusterID()
		r.updateLeaderStatus(leaderID)
		if leaderID != common.InvalidClusterID {
			localClusterMemberAnnounce.LeaderClusterID = string(leaderID)
		}

		if localClusterMemberAnnounce.Annotations == nil {
			localClusterMemberAnnounce.Annotations = make(map[string]string)
		}
		// Add timestamp to force update on MemberClusterAnnounce. Leader cluster requires
		// periodic updates to detect connectivity. Without this, no-op updates will be ignored.
		localClusterMemberAnnounce.Annotations[TimestampAnnotationKey] = time.Now().String()
		if err := r.Update(context.TODO(), &localClusterMemberAnnounce, &client.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Error updating MemberClusterAnnounce", "Cluster", r.GetClusterID())
			return err
		}
	} else {
		// Create happens first before a leader can be elected. When the creation is successful,
		// it marks the connectivity status and then the leader election can happen.
		// Therefore, the first create will not populate the leader ClusterID.
		localClusterMemberAnnounce.ClusterID = string(r.remoteCommonAreaManager.GetLocalClusterID())
		localClusterMemberAnnounce.Name = "member-announce-from-" + string(r.remoteCommonAreaManager.GetLocalClusterID())
		localClusterMemberAnnounce.Namespace = r.Namespace
		localClusterMemberAnnounce.ClusterSetID = string(r.ClusterSetID)
		if err := r.Create(context.TODO(), &localClusterMemberAnnounce, &client.CreateOptions{}); err != nil {
			klog.ErrorS(err, "Error creating MemberClusterAnnounce", "Cluster", r.GetClusterID())
			return err
		}
	}

	return nil
}

func (r *remoteCommonArea) updateRemoteCommonAreaStatus(connected bool, err error) {
	defer r.mutex.Unlock()
	r.mutex.Lock()
	if r.connected == connected {
		return
	}

	klog.InfoS("Updating RemoteCommonArea status", "Cluster", r.GetClusterID(), "Connected", connected)

	// TODO: Tolerate transient failures so we dont oscillate between connected and disconnected.
	r.connected = connected
	r.clusterStatus.Status = v1.ConditionTrue
	r.clusterStatus.Message = ""
	r.clusterStatus.Reason = ""
	r.clusterStatus.LastTransitionTime = metav1.Now()
	if !connected {
		r.clusterStatus.Status = v1.ConditionFalse
		r.clusterStatus.Message = err.Error()
		r.clusterStatus.Reason = ReasonDisconnected
	}
}

func (r *remoteCommonArea) updateLeaderStatus(leaderID common.ClusterID) {
	defer r.mutex.Unlock()
	r.mutex.Lock()

	if leaderID == common.InvalidClusterID {
		if r.leaderStatus.Status != v1.ConditionUnknown {
			r.leaderStatus.Status = v1.ConditionUnknown
			r.leaderStatus.Message = ""
			r.leaderStatus.Reason = ReasonElectionInProgress
			r.leaderStatus.LastTransitionTime = metav1.Now()
		}
	} else if r.ClusterID == leaderID && r.leaderStatus.Status != v1.ConditionTrue {
		r.leaderStatus.Status = v1.ConditionTrue
		r.leaderStatus.Message = "This leader cluster is an elected leader for local cluster"
		r.leaderStatus.Reason = ""
		r.leaderStatus.LastTransitionTime = metav1.Now()
	} else if r.ClusterID != leaderID && r.leaderStatus.Status != v1.ConditionFalse {
		r.leaderStatus.Status = v1.ConditionFalse
		r.leaderStatus.Message = "This leader cluster is not an elected leader for local cluster"
		r.leaderStatus.Reason = ""
		r.leaderStatus.LastTransitionTime = metav1.Now()
	}
}

/**
 * ---------------------------
 * CommonArea Implementation
 * ---------------------------
 */

func (r *remoteCommonArea) GetClusterID() common.ClusterID {
	return r.ClusterID
}

func (r *remoteCommonArea) GetNamespace() string {
	return r.Namespace
}

/**
 * ---------------------------
 * RemoteCommonArea Implementation
 * ---------------------------
 */

// Start starts a background routine.
// Once connected to the RemoteCommonArea, the Start method runs a timer
// on a go routine to periodically write MemberClusterAnnounce into the
// RemoteCommonArea's CommonArea and also maintain its connectivity status.
func (r *remoteCommonArea) Start() (context.CancelFunc, error) {
	stopCtx, stopFunc := context.WithCancel(context.Background())

	// Start a Timer for every 5 seconds
	// TODO: make the interval longer? the webhook API is called every 5s to RemoteCommonArea now
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		klog.InfoS("Starting MemberAnnounce to RemoteCommonArea", "Cluster", r.GetClusterID())
		r.doMemberAnnounce()
		for {
			select {
			case <-stopCtx.Done():
				klog.InfoS("Stopping MemberAnnounce to RemoteCommonArea", "Cluster", r.GetClusterID())
				ticker.Stop()
				return
			case <-ticker.C:
				r.doMemberAnnounce()
			}
		}
	}()

	r.stopFunc = stopFunc
	return stopFunc, nil
}

func (r *remoteCommonArea) doMemberAnnounce() {
	if err := r.SendMemberAnnounce(); err != nil {
		klog.ErrorS(err, "Error writing member announce", "Cluster", r.GetClusterID())
		r.updateRemoteCommonAreaStatus(false, err)
	} else {
		r.updateRemoteCommonAreaStatus(true, nil)
	}
}

func (r *remoteCommonArea) Stop() error {
	if r.stopFunc == nil {
		return nil
	}
	r.stopFunc()
	r.stopFunc = nil

	r.StopWatching()

	return nil
}

func (r *remoteCommonArea) IsConnected() bool {
	defer r.mutex.RUnlock()
	r.mutex.RLock()
	return r.connected
}

func (r *remoteCommonArea) StartWatching() error {
	if r.managerStopFunc != nil {
		klog.InfoS("Manager already watching resources from RemoteCommonArea", "Cluster", r.ClusterID)
		return nil
	}

	klog.V(2).InfoS("Start monitoring ResourceImport from RemoteCommonArea", "Cluster", r.ClusterID)

	resImportReconciler := NewResourceImportReconciler(
		r.ClusterManager.GetClient(),
		r.ClusterManager.GetScheme(),
		r.localClusterClient,
		string(r.remoteCommonAreaManager.GetLocalClusterID()),
		r,
	)

	if err := resImportReconciler.SetupWithManager(r.ClusterManager); err != nil {
		klog.V(2).ErrorS(err, "Error creating ResourceImport controller for RemoteCommonArea", "Cluster", r.ClusterID)
		return fmt.Errorf("error creating ResourceImport controller for RemoteCommonArea: %v", err)
	}

	go func() {
		stopCtx, stopFunc := context.WithCancel(context.Background())
		r.managerStopFunc = stopFunc
		// This starts the Manager and blocks; Manager performs reconciliation of resources from the RemoteCommonArea.
		// When this RemoteCommonArea is not an elected leader anymore, stopCtx will be closed in StopWatching,
		// so this blocking routine can return and finish. And the next time this RemoteCommonArea is elected as
		// the leader again, it starts the Manager again.
		err := r.ClusterManager.Start(stopCtx)
		if err != nil {
			klog.ErrorS(err, "Error starting ClusterManager for RemoteCommonArea", "Cluster", r.ClusterID)
		}
		klog.InfoS("Stopping ClusterManager for RemoteCommonArea", "Cluster", r.ClusterID)
	}()

	return nil
}

func (r *remoteCommonArea) StopWatching() {
	if r.managerStopFunc == nil {
		return
	}
	r.managerStopFunc()
	r.managerStopFunc = nil
}

func (r *remoteCommonArea) GetStatus() []multiclusterv1alpha1.ClusterCondition {
	defer r.mutex.Unlock()
	r.mutex.Lock()

	statues := make([]multiclusterv1alpha1.ClusterCondition, 0, 2)
	statues = append(statues, r.clusterStatus) // This will be a copy
	statues = append(statues, r.leaderStatus)  // This will be a copy
	return statues
}
