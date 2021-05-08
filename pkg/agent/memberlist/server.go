package memberlist

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"strconv"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"k8s.io/klog"
)

type Server struct {
	serverVersion   string
	bindPort        int
	nodeConfig      *config.NodeConfig
	nodeInformer    coreinformers.NodeInformer
	memberList      *memberlist.Memberlist
	existingMembers *[]string
}

func (ms *Server) addStatleAgentCRD(old interface{}) {
	node, ok := old.(*corev1.Node)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Node, invalid type: %v", old)
			return
		}
		node, ok = tombstone.Obj.(*corev1.Node)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Node, invalid type: %v", tombstone.Obj)
			return
		}
	}
	ms.AddMember(node)
}

func NewMemberlistServer(p int, nodeInformer coreinformers.NodeInformer, nodeConfig *config.NodeConfig) *Server {
	klog.Infof("Node config: %#v", nodeConfig)

	s := &Server{
		bindPort:      p,
		serverVersion: "v1",
		nodeInformer:  nodeInformer,
		nodeConfig:    nodeConfig,
	}

	hostname := s.nodeConfig.Name
	bindPort := s.bindPort
	hostIP := s.nodeConfig.NodeIPAddr.IP

	nodeMember := fmt.Sprintf("%s:%d", hostIP.String(), bindPort)

	klog.Infof("Add new node: %s", nodeMember)

	conf := memberlist.DefaultLocalConfig()
	conf.Name = hostname + "-" + strconv.Itoa(bindPort)

	conf.BindPort = bindPort
	conf.AdvertisePort = bindPort

	klog.Infof("Configs: %+v\n", conf)

	list, err := memberlist.Create(conf)
	if err != nil {
		panic("Failed to create memberlist: " + err.Error())
	}

	s.memberList = list
	s.existingMembers = &[]string{nodeMember}

	// Join an existing cluster by specifying at least one known member.
	s.JoinMembers(*s.existingMembers)

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    s.addStatleAgentCRD,
		UpdateFunc: nil,
		DeleteFunc: nil,
	})

	return s
}

func (ms *Server) ConvertListNodesToMemberlist() []string {
	nodes, err := ms.nodeInformer.Lister().List(labels.Everything())
	if err != nil {
		klog.Errorf("error when listing Nodes: %v", err)
	}
	klog.Infof("List %d nodes.", len(nodes))

	clusterNodes := make([]string, len(nodes))

	for i, node := range nodes {
		klog.Infof("node %s: %#v", node.Name, node.Status.Addresses)
		address := node.Status.Addresses
		for _, add := range address {
			if add.Type == corev1.NodeInternalIP {
				member := fmt.Sprintf("%s:%d", add.Address, ms.bindPort)
				clusterNodes[i] = member
				klog.Infof("Cluster memberlist: %s.", member)
			}
		}
	}
	return clusterNodes
}

func (ms *Server) AddMember(node *corev1.Node) {
	var member string
	for _, add := range node.Status.Addresses {
		if add.Type == corev1.NodeInternalIP {
			member = fmt.Sprintf("%s:%d", add.Address, ms.bindPort)
		}
	}
	if member != "" {
		*ms.existingMembers = append(*ms.existingMembers, member)
		ms.JoinMembers(*ms.existingMembers)
	}
}

func (ms *Server) JoinMembers(clusterNodes []string) {
	n, err := ms.memberList.Join(clusterNodes)
	if err != nil {
		klog.Errorf("Failed to join cluster: %s, cluster nodes: %#v.", err.Error(), clusterNodes)
	}
	klog.Infof("Join cluster: %v, cluster nodes: %+v", n, clusterNodes)
}

func (ms *Server) Run(stopCh <-chan struct{}) {

	newClusterMembers := ms.ConvertListNodesToMemberlist()
	expectNodeNum := len(newClusterMembers)
	klog.Infof("List %d nodes: %#v.", expectNodeNum, newClusterMembers)

	actualMemberNum := ms.memberList.NumMembers()
	klog.Infof("Nodes num: %d, member num: %d.", expectNodeNum, actualMemberNum)
	if actualMemberNum < expectNodeNum {
		ms.JoinMembers(newClusterMembers)
	}

	// Ask for members of the cluster
	for i, member := range ms.memberList.Members() {
		klog.Infof("Member %d: %s, Address: %s, State: %#v", i, member.Name, member.Addr, member.State)
	}

	// Memberlist will maintain membership information in the background.
	// Delegates can be used for receiving events when members join or leave.
	timeTicker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-stopCh:
			return
		case <-timeTicker.C:
			for i, member := range ms.memberList.Members() {
				klog.Infof("Member %d: %s, Address: %s, State: %#v", i, member.Name, member.Addr, member.State)
			}
		}
	}
}
