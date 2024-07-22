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

package portcache

import (
	"fmt"
	"io"
	"net"
	"sync"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const (
	NodePortIndex    = "nodePortIndex"
	PodEndpointIndex = "podEndpointIndex"
	PodKeyIndex      = "podKeyIndex"
)

type ProtocolSocketData struct {
	Protocol string
	socket   io.Closer
}

type NodePortData struct {
	// PodKey is the namespaced name of the Pod.
	PodKey   string
	NodePort int
	PodPort  int
	PodIP    string
	Protocol ProtocolSocketData
	// defunct is used to indicate that a rule has been partially deleted: it is no longer
	// usable and deletion needs to be re-attempted.
	defunct bool
}

func (d *NodePortData) Defunct() bool {
	return d.defunct
}

type LocalPortOpener interface {
	OpenLocalPort(port int, protocol string) (io.Closer, error)
}

type localPortOpener struct{}

type PortTable struct {
	PortTableCache  cache.Indexer
	StartPort       int
	EndPort         int
	PortSearchStart int
	PodPortRules    rules.PodPortRules
	LocalPortOpener LocalPortOpener
	tableLock       sync.RWMutex
}

func GetPortTableKey(obj interface{}) (string, error) {
	npData := obj.(*NodePortData)
	key := fmt.Sprintf("%d:%s:%d:%s", npData.NodePort, npData.PodKey, npData.PodPort, npData.Protocol.Protocol)
	return key, nil
}

func (pt *PortTable) addPortTableCache(npData *NodePortData) error {
	if err := pt.PortTableCache.Add(npData); err != nil {
		return err
	}
	return nil
}

func (pt *PortTable) deletePortTableCache(npData *NodePortData) error {
	if err := pt.PortTableCache.Delete(npData); err != nil {
		return err
	}
	return nil
}

func (pt *PortTable) getPortTableCacheFromNodePortIndex(index string) (*NodePortData, bool) {
	objs, _ := pt.PortTableCache.ByIndex(NodePortIndex, index)
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*NodePortData), true
}

func (pt *PortTable) getPortTableCacheFromPodEndpointIndex(index string) (*NodePortData, bool) {
	objs, _ := pt.PortTableCache.ByIndex(PodEndpointIndex, index)
	if len(objs) == 0 {
		return nil, false
	}
	return objs[0].(*NodePortData), true
}

func (pt *PortTable) getPortTableCacheFromPodKeyIndex(index string) ([]*NodePortData, bool) {
	var npData []*NodePortData
	objs, _ := pt.PortTableCache.ByIndex(PodKeyIndex, index)
	if len(objs) == 0 {
		return nil, false
	}
	for _, obj := range objs {
		npData = append(npData, obj.(*NodePortData))
	}
	return npData, true
}

func (pt *PortTable) releaseDataFromPortTableCache() error {
	for _, obj := range pt.PortTableCache.List() {
		data := obj.(*NodePortData)
		if err := pt.deletePortTableCache(data); err != nil {
			return err
		}
	}
	return nil
}

func NodePortIndexFunc(obj interface{}) ([]string, error) {
	npData := obj.(*NodePortData)
	nodePortTuple := NodePortProtoFormat(npData.NodePort, npData.Protocol.Protocol)
	return []string{nodePortTuple}, nil
}

func PodEndpointIndexFunc(obj interface{}) ([]string, error) {
	npData := obj.(*NodePortData)
	podEndpointTuple := podKeyPortProtoFormat(npData.PodKey, npData.PodPort, npData.Protocol.Protocol)
	return []string{podEndpointTuple}, nil
}

func PodKeyIndexFunc(obj interface{}) ([]string, error) {
	npData := obj.(*NodePortData)
	return []string{npData.PodKey}, nil
}

func NewPortTable(start, end int) (*PortTable, error) {
	ptable := PortTable{
		PortTableCache: cache.NewIndexer(GetPortTableKey, cache.Indexers{
			NodePortIndex:    NodePortIndexFunc,
			PodEndpointIndex: PodEndpointIndexFunc,
			PodKeyIndex:      PodKeyIndexFunc,
		}),
		StartPort:       start,
		EndPort:         end,
		PortSearchStart: start,
		PodPortRules:    rules.InitRules(),
		LocalPortOpener: &localPortOpener{},
	}
	if err := ptable.PodPortRules.Init(); err != nil {
		return nil, err
	}
	return &ptable, nil
}

func (pt *PortTable) CleanupAllEntries() {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	pt.releaseDataFromPortTableCache()
}

func (pt *PortTable) GetDataForPod(podKey string) []*NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	return pt.getDataForPod(podKey)
}

func (pt *PortTable) getDataForPod(podKey string) []*NodePortData {
	allData, exist := pt.getPortTableCacheFromPodKeyIndex(podKey)
	if exist == false {
		return nil
	}
	return allData
}

func (pt *PortTable) GetEntry(podKey string, port int, protocol string) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	// Return pointer to copy of data from the PodEndpointTable.
	if data := pt.getEntryByPodKeyPortProto(podKey, port, protocol); data != nil {
		dataCopy := *data
		return &dataCopy
	}
	return nil
}

// podKeyPortProtoFormat formats the podKey, port and protocol to string key:port:protocol.
func podKeyPortProtoFormat(podKey string, port int, protocol string) string {
	return fmt.Sprintf("%s:%d:%s", podKey, port, protocol)
}

func (pt *PortTable) getEntryByPodKeyPortProto(podKey string, port int, protocol string) *NodePortData {
	data, ok := pt.getPortTableCacheFromPodEndpointIndex(podKeyPortProtoFormat(podKey, port, protocol))
	if !ok {
		return nil
	}
	return data
}

func (pt *PortTable) RuleExists(podKey string, podPort int, protocol string) bool {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	data := pt.getEntryByPodKeyPortProto(podKey, podPort, protocol)
	return data != nil
}

// nodePortProtoFormat formats the nodeport, protocol to string port:protocol.
func NodePortProtoFormat(nodeport int, protocol string) string {
	return fmt.Sprintf("%d:%s", nodeport, protocol)
}

// openLocalPort binds to the provided port.
// This is inspired by the openLocalPort function in kube-proxy:
// https://github.com/kubernetes/kubernetes/blob/86f8c3ee91b6faec437f97e3991107747d7fc5e8/pkg/proxy/iptables/proxier.go#L1664
func (lpo *localPortOpener) OpenLocalPort(port int, protocol string) (io.Closer, error) {
	// For now, NodePortLocal only supports IPv4 and TCP/UDP.
	var network string
	var socket io.Closer
	switch protocol {
	case "tcp":
		network = "tcp4"
		listener, err := net.Listen(network, fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, err
		}
		socket = listener
	case "udp":
		network = "udp4"
		addr, err := net.ResolveUDPAddr(network, fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		socket = conn
	}
	klog.V(2).InfoS("Opened local port", "port", port)
	return socket, nil
}
