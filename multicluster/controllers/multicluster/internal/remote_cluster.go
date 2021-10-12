package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	// Use a raw client to get member cluster secrets from antrea-plus-system only.
	secretClient client.Client
	// multiple remote clusters can be created concurrently, need a lock to synchronize creation of secretClient
	mutex sync.Mutex
)

// Abstraction to connect to a remote cluster's (i.e. the Leader Cluster) Common Area
type RemoteCluster interface {
	common.CommonArea

	Start() (context.CancelFunc, error)

	Stop() error

	// tells whether the remote cluster is accessible or not
	IsConnected() bool

	// TODO: resource monitoring methods needs to be defined.
}

// This implements the commonArea interface and allows local cluster to read/write into
// the common area of the remote cluster.
type remoteCluster struct {
	// client that provides read/write access into the remote cluster
	client.Client

	log logr.Logger

	// manager to setup controllers for resources that need to be monitored in the remote cluster
	ClusterManager manager.Manager

	// ClusterID of this remote cluster
	ClusterID common.ClusterID

	// ClusterSetID of this remote cluster
	ClusterSetID common.ClusterSetID

	// config necessary to access the remote cluster
	config *rest.Config

	// scheme necessary to access the remote cluster
	scheme *runtime.Scheme

	// Namespace this clusterSet is associated with
	Namespace string

	// connectivity status, should it be the status?
	connected bool

	remoteClusterManager RemoteClusterManager

	stopFunc context.CancelFunc
}

/**
 * A remote cluster is a leader in the ClusterSet Spec. This creates a remoteCluster instance which will
 * use the secret and access credentials for the leader to connect to its common area.
 */
func NewRemoteCluster(clusterID common.ClusterID, clusterSetID common.ClusterSetID, url string, secretName string,
	scheme *runtime.Scheme, log logr.Logger, remoteClusterManager RemoteClusterManager, clusterSetNamespace string,
	configNamespace string) (common.CommonArea, error) {
	log = log.WithName("remote-cluster-" + string(clusterID))
	log.Info("Create remote cluster for", "cluster", clusterID)

	// Secret associated with this local cluster must be copied from remote cluster to local cluster
	// so that the secret data can be obtained.
	// read/decode secret (get token and crt)
	// TODO: what will be the namespace in the local cluster? use the same namespace where cluster set is configured
	crtData, token, err := getSecretCACrtAndToken(configNamespace, secretName)
	if err != nil {
		return nil, err
	}
	log.Info("found", "secret", secretName)

	// create manager for the member cluster
	log.Info("Connecting", "url", url)
	config, err := clientcmd.BuildConfigFromFlags(url, "")
	if err != nil {
		return nil, err
	}
	config.BearerToken = string(token)
	config.CAData = crtData
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
		Logger:             log.WithName("controller-runtime"),
		Namespace:          clusterSetNamespace,
	})
	if err != nil {
		log.V(1).Error(err, "unable to create new manager")
		return nil, err
	}

	remoteClient, e := client.New(config, client.Options{Scheme: scheme})
	if e != nil {
		return nil, e
	}
	cluster := &remoteCluster{
		Client:               remoteClient,
		log:                  log,
		ClusterManager:       mgr,
		ClusterSetID:         clusterSetID,
		ClusterID:            clusterID,
		config:               config,
		scheme:               scheme,
		Namespace:            clusterSetNamespace,
		connected:            false,
		remoteClusterManager: remoteClusterManager,
	}

	remoteClusterManager.AddRemoteCluster(cluster)

	return cluster, nil
}

/**
 * When a member is added to a ClusterSet, a specific ServiceAccount is created on the
 * leader cluster which allows the member to access into the common area. This ServiceAccount
 * has an associated Secret which must be copied into the Member Cluster as an opaque secret.
 * Name of this secret is part of the ClusterSet spec for this member. This method reads
 * the Secret given by that name.
 */
func getSecretCACrtAndToken(namespace string, secretName string) ([]byte, []byte, error) {
	var err error
	mutex.Lock()
	if secretClient == nil {
		secretClient, err = client.New(ctrl.GetConfigOrDie(), client.Options{})
		if err != nil {
			mutex.Unlock()
			return nil, nil, err
		}
	}
	mutex.Unlock()
	secretObj := &v1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Namespace: namespace,
		Name:      secretName,
	}
	err = secretClient.Get(context.TODO(), secretNamespacedName, secretObj)
	if err != nil {
		return nil, nil, err
	}

	caData, found := secretObj.Data[v1.ServiceAccountRootCAKey]
	if !found {
		return nil, nil, fmt.Errorf("ca.crt data not found in secret %v", secretName)
	}

	token, found := secretObj.Data[v1.ServiceAccountTokenKey]
	if !found {
		return nil, nil, fmt.Errorf("token not found in secret %v", secretName)
	}

	return caData, token, nil
}

func (r *remoteCluster) SendMemberAnnounce() error {
	// TODO: remove this before merge to feature branch to avoid spamming logs
	r.log.Info("Writing member announce")

	memberAnnounceList := &multiclusterv1alpha1.MemberClusterAnnounceList{}
	if err := r.List(context.TODO(), memberAnnounceList, client.InNamespace(r.GetNamespace())); err != nil {
		return err
	}
	var localClusterMemberAnnounce multiclusterv1alpha1.MemberClusterAnnounce
	localClusterMemberAnnounceExist := false
	if len(memberAnnounceList.Items) != 0 {
		for _, memberAnnounce := range memberAnnounceList.Items {
			if memberAnnounce.ClusterID == string(r.remoteClusterManager.GetLocalClusterID()) {
				localClusterMemberAnnounceExist = true
				localClusterMemberAnnounce = memberAnnounce
				break
			}
		}
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()
	if localClusterMemberAnnounceExist {
		if r.remoteClusterManager.GetElectedLeaderClusterID() != common.INVALID_CLUSTER_ID {
			localClusterMemberAnnounce.LeaderClusterID = string(r.remoteClusterManager.GetElectedLeaderClusterID())
		}

		if localClusterMemberAnnounce.Annotations == nil {
			localClusterMemberAnnounce.Annotations = make(map[string]string)
		}
		localClusterMemberAnnounce.Annotations["touch-ts"] = time.Now().String()
		// do an update
		if err := r.Update(ctx, &localClusterMemberAnnounce, &client.UpdateOptions{}); err != nil {
			r.log.Error(err, "Failed to update member announce")
			return err
		}
	} else {
		// create happens first before a leader can be elected, when the create is successful
		// it marks the connectivity status to leader election can occur
		// Therefore the first create will not populate the leader cluster id
		localClusterMemberAnnounce.ClusterID = string(r.remoteClusterManager.GetLocalClusterID())
		localClusterMemberAnnounce.Name = "member-announce-from-" + string(r.remoteClusterManager.GetLocalClusterID())
		localClusterMemberAnnounce.Namespace = r.Namespace
		localClusterMemberAnnounce.ClusterSetID = string(r.ClusterSetID)
		if err := r.Create(ctx, &localClusterMemberAnnounce, &client.CreateOptions{}); err != nil {
			r.log.Error(err, "Failed to create member announce")
			return err
		}
	}

	return nil
}

func (r *remoteCluster) updateRemoteClusterStatus(connected bool, err error) {
	if r.connected == connected {
		return
	}

	log := r.log.WithName("MemberAnnounce")

	log.Info("Updating remote cluster status", "connected", connected)

	// TODO: Tolerate transient failures so we dont oscillate between connected and disconnected.
	r.connected = connected
}

/**
 * ---------------------------
 * commonArea Implementation
 * ---------------------------
 */

func (r *remoteCluster) GetClusterID() common.ClusterID {
	return r.ClusterID
}

func (r *remoteCluster) GetNamespace() string {
	return r.Namespace
}

/**
 * ---------------------------
 * RemoteCluster Implementation
 * ---------------------------
 */

/**
 * Once connected to the remote cluster, the start method run a timer
 * on a go routine to periodically write MemberAnnounce CRD into the remote
 * cluster's common area and also maintain its connectivity status to the
 * remote cluster
 */
func (r *remoteCluster) Start() (context.CancelFunc, error) {
	stopCtx, stopFunc := context.WithCancel(context.Background())

	// Start a Timer for every 5 seconds
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		r.log.Info("Starting MemberAnnounce")
		for {
			select {
			case <-stopCtx.Done():
				r.log.Info("Stopping MemberAnnounce")
				return
			case <-ticker.C:
				// do member announce
				if err := r.SendMemberAnnounce(); err != nil {
					// will be tried again
					r.log.Error(err, "error writing member announce")
					r.updateRemoteClusterStatus(false, err)
				} else {
					r.updateRemoteClusterStatus(true, nil)
				}
			}
		}
	}()

	r.stopFunc = stopFunc
	return stopFunc, nil
}

func (r *remoteCluster) Stop() error {
	if r.stopFunc == nil {
		return nil
	}

	r.stopFunc()
	return nil
}

func (r *remoteCluster) IsConnected() bool {
	return r.connected
}
