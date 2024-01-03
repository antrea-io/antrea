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

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

const (
	TimestampAnnotationKey = "touch-ts"
)

var (
	ReasonDisconnected = "Disconnected"
)

// remoteCommonArea implements the CommonArea interface and allows local cluster to read/write into
// the CommonArea of RemoteCommonArea.
type remoteCommonArea struct {
	// mutex to synchronize access to connectivity state since it is updated by
	// a background routine running in remoteCommonArea.
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

	clusterStatus mcv1alpha2.ClusterCondition
	leaderStatus  mcv1alpha2.ClusterCondition

	// The ID of the local member cluster
	localClusterID common.ClusterID

	// client that provides read/write access into the local cluster
	localClusterClient client.Client

	// localNamespace is the Namespace where the controller is running.
	localNamespace string

	// stopFunc to stop all background operations when the RemoteCommonArea is stopped.
	stopFunc context.CancelFunc

	// managerStopFunc to stop the manager when the RemoteCommonArea is stopped.
	managerStopFunc context.CancelFunc

	// Enable StretchedNetworkPolicy which will export and import labelIdentities in the
	// ClusterSet and allow Antrea-native policies to select peers from other clusters
	// in a ClusterSet.
	enableStretchedNetworkPolicy bool

	// A list of ImportReconcilers to reconcile ResourceImports.
	importReconcilers []ImportReconciler
}

// NewRemoteCommonArea returns a RemoteCommonArea instance which will use access credentials from the Secret to
// connect to the leader cluster's CommonArea.
func NewRemoteCommonArea(clusterID common.ClusterID, clusterSetID common.ClusterSetID, localClusterID common.ClusterID, mgr manager.Manager, remoteClient client.Client,
	scheme *runtime.Scheme, localClusterClient client.Client, clusterSetNamespace string, localNamespace string, config *rest.Config, enableStretchedNetworkPolicy bool) (RemoteCommonArea, error) {
	klog.InfoS("Create a RemoteCommonArea", "cluster", clusterID)

	remote := &remoteCommonArea{
		Client:                       remoteClient,
		ClusterManager:               mgr,
		ClusterSetID:                 clusterSetID,
		ClusterID:                    clusterID,
		config:                       config,
		scheme:                       scheme,
		Namespace:                    clusterSetNamespace,
		connected:                    false,
		localClusterClient:           localClusterClient,
		localNamespace:               localNamespace,
		localClusterID:               localClusterID,
		enableStretchedNetworkPolicy: enableStretchedNetworkPolicy,
	}
	remote.clusterStatus.Type = mcv1alpha2.ClusterReady
	remote.clusterStatus.Status = v1.ConditionUnknown
	remote.clusterStatus.Message = "Leader cluster added"
	remote.clusterStatus.LastTransitionTime = metav1.Now()
	remote.leaderStatus.Type = mcv1alpha2.ClusterIsLeader
	remote.leaderStatus.Status = v1.ConditionFalse
	remote.leaderStatus.Message = "Leader cluster added"
	remote.leaderStatus.LastTransitionTime = metav1.Now()

	return remote, nil
}

func GetRemoteConfigAndClient(secretObj *v1.Secret, url string, clusterID common.ClusterID, clusterSet *mcv1alpha2.ClusterSet, scheme *runtime.Scheme) (*rest.Config,
	manager.Manager, client.Client, error) {
	crtData, token, err := getSecretCACrtAndToken(secretObj)
	if err != nil {
		return nil, nil, nil, err
	}
	config, err := clientcmd.BuildConfigFromFlags(url, "")
	if err != nil {
		return nil, nil, nil, err
	}
	config.BearerToken = string(token)
	config.CAData = crtData

	config.QPS = common.ResourceExchangeQPS
	config.Burst = common.ResourceExchangeBurst
	remoteCommonAreaMgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				clusterSet.Spec.Namespace: {},
			},
		},
	})
	if err != nil {
		klog.ErrorS(err, "Error creating manager for RemoteCommonArea", "cluster", clusterID)
		return nil, nil, nil, err
	}

	remoteClient, e := client.New(config, client.Options{Scheme: scheme})
	if e != nil {
		return nil, nil, nil, e
	}
	return config, remoteCommonAreaMgr, remoteClient, nil
}

/**
 * GetSecretCACrtAndToken returns the access credentials from Secret.
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
	var err error
	memberAnnounceName := "member-announce-from-" + r.GetLocalClusterID()
	existingMemberAnnounce := &mcv1alpha1.MemberClusterAnnounce{}
	if err = r.Get(context.TODO(), types.NamespacedName{
		Namespace: r.GetNamespace(),
		Name:      memberAnnounceName,
	}, existingMemberAnnounce); err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	localClusterMemberAnnounceExists := err == nil
	localClusterMemberAnnounce := *existingMemberAnnounce

	if localClusterMemberAnnounceExists {
		r.updateLeaderStatus()
		if localClusterMemberAnnounce.Annotations == nil {
			localClusterMemberAnnounce.Annotations = make(map[string]string)
		}
		// Add timestamp to force update on MemberClusterAnnounce. Leader cluster requires
		// periodic updates to detect connectivity. Without this, no-op updates will be ignored.
		localClusterMemberAnnounce.Annotations[TimestampAnnotationKey] = time.Now().Format(time.RFC3339)
		if err := r.Update(context.TODO(), &localClusterMemberAnnounce, &client.UpdateOptions{}); err != nil {
			klog.ErrorS(err, "Error updating MemberClusterAnnounce", "cluster", r.GetClusterID())
			return err
		}
		return nil
	}

	// Create happens first before the leader validation passes. When the creation is successful,
	// it marks the connectivity status and then the validation on the leader can happen.
	localClusterMemberAnnounce.ClusterID = r.GetLocalClusterID()
	localClusterMemberAnnounce.Name = memberAnnounceName
	localClusterMemberAnnounce.Namespace = r.Namespace
	localClusterMemberAnnounce.ClusterSetID = string(r.ClusterSetID)
	localClusterMemberAnnounce.LeaderClusterID = string(r.GetClusterID())
	if err := r.Create(context.TODO(), &localClusterMemberAnnounce, &client.CreateOptions{}); err != nil {
		klog.ErrorS(err, "Error creating MemberClusterAnnounce", "cluster", r.GetClusterID())
		return err
	}
	return nil
}

func (r *remoteCommonArea) updateRemoteCommonAreaStatus(connected bool, err error) {
	defer r.mutex.Unlock()
	r.mutex.Lock()
	if r.connected == connected {
		return
	}

	klog.InfoS("Updating RemoteCommonArea status", "cluster", r.GetClusterID(), "connected", connected)

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

func (r *remoteCommonArea) updateLeaderStatus() {
	defer r.mutex.Unlock()
	r.mutex.Lock()

	if r.leaderStatus.Status != v1.ConditionTrue {
		r.leaderStatus.Status = v1.ConditionTrue
		r.leaderStatus.Message = "This leader cluster is the leader for local cluster"
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
func (r *remoteCommonArea) Start() context.CancelFunc {
	stopCtx, stopFunc := context.WithCancel(context.Background())

	ticker := time.NewTicker(10 * time.Second)

	go func() {
		klog.InfoS("Starting MemberAnnounce to RemoteCommonArea", "cluster", r.GetClusterID())
		r.doMemberAnnounce()
		startedImporters := false
		for {
			select {
			case <-stopCtx.Done():
				klog.InfoS("Stopping MemberAnnounce to RemoteCommonArea", "cluster", r.GetClusterID())
				ticker.Stop()
				return
			case <-ticker.C:
				r.doMemberAnnounce()
				if !startedImporters && r.connected {
					if err := r.StartWatching(); err != nil {
						// Will retry in next tick.
						klog.ErrorS(err, "Failed to start watching events")
						return
					}
					startedImporters = true
				}
			}
		}
	}()

	r.stopFunc = stopFunc
	return stopFunc
}

func (r *remoteCommonArea) doMemberAnnounce() {
	if err := r.SendMemberAnnounce(); err != nil {
		klog.ErrorS(err, "Error updating MemberClusterAnnounce", "cluster", r.GetClusterID())
		r.updateRemoteCommonAreaStatus(false, err)
	} else {
		r.updateRemoteCommonAreaStatus(true, nil)
	}
}

func (r *remoteCommonArea) Stop() {
	if r.stopFunc == nil {
		return
	}
	r.stopFunc()
	r.stopFunc = nil

	r.StopWatching()
}

func (r *remoteCommonArea) IsConnected() bool {
	defer r.mutex.RUnlock()
	r.mutex.RLock()
	return r.connected
}

func (r *remoteCommonArea) AddImportReconciler(reconciler ImportReconciler) {
	r.importReconcilers = append(r.importReconcilers, reconciler)
}

func (r *remoteCommonArea) StartWatching() error {
	if r.managerStopFunc != nil {
		klog.InfoS("Manager already watching resources from RemoteCommonArea", "cluster", r.ClusterID)
		return nil
	}

	klog.V(2).InfoS("Start watching ResourceImports from RemoteCommonArea", "cluster", r.ClusterID)

	for _, rc := range r.importReconcilers {
		if err := rc.SetupWithManager(r.ClusterManager); err != nil {
			return fmt.Errorf("error setting up ResourceImport controller for RemoteCommonArea: %v", err)
		}
	}

	go func() {
		stopCtx, stopFunc := context.WithCancel(context.Background())
		r.managerStopFunc = stopFunc
		// This starts the Manager and blocks; Manager performs reconciliation of resources from the RemoteCommonArea.
		// When this RemoteCommonArea is not a leader anymore, stopCtx will be closed in StopWatching,
		// so this blocking routine can return and finish. And the next time this RemoteCommonArea is connected as
		// the leader again, it starts the Manager again.
		err := r.ClusterManager.Start(stopCtx)
		if err != nil {
			klog.ErrorS(err, "Error starting ClusterManager for RemoteCommonArea", "cluster", r.ClusterID)
		}
		klog.InfoS("Stopping ClusterManager for RemoteCommonArea", "cluster", r.ClusterID)
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

func (r *remoteCommonArea) GetStatus() []mcv1alpha2.ClusterCondition {
	defer r.mutex.Unlock()
	r.mutex.Lock()

	statues := make([]mcv1alpha2.ClusterCondition, 0, 2)
	statues = append(statues, r.clusterStatus) // This will be a copy
	statues = append(statues, r.leaderStatus)  // This will be a copy
	return statues
}

func (r *remoteCommonArea) GetLocalClusterID() string {
	return string(r.localClusterID)
}
