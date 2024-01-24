// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connections

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
	"antrea.io/antrea/pkg/util/podstore"
)

type PodL7FlowExporterAttrGetter interface {
	IsL7FlowExporterRequested(podNN string, ingress bool) bool
}

// L7ProtocolFields holds layer 7 protocols supported
type L7ProtocolFields struct {
	http map[int32]*Http
}

// Http holds the L7 HTTP flow JSON values.
type Http struct {
	Hostname      string `json:"hostname"`
	URL           string `json:"url"`
	UserAgent     string `json:"http_user_agent"`
	ContentType   string `json:"http_content_type"`
	Method        string `json:"http_method"`
	Protocol      string `json:"protocol"`
	Status        int32  `json:"status"`
	ContentLength int32  `json:"length"`
}

// JsonToEvent holds Suricata event JSON values.
// See https://docs.suricata.io/en/latest/output/eve/eve-json-format.html?highlight=HTTP%20event#event-types
type JsonToEvent struct {
	Timestamp   string     `json:"timestamp"`
	FlowID      int64      `json:"flow_id"`
	InInterface string     `json:"in_iface"`
	EventType   string     `json:"event_type"`
	VLAN        []int32    `json:"vlan"`
	SrcIP       netip.Addr `json:"src_ip"`
	SrcPort     int32      `json:"src_port"`
	DestIP      netip.Addr `json:"dest_ip"`
	DestPort    int32      `json:"dest_port"`
	Proto       string     `json:"proto"`
	TxID        int32      `json:"tx_id"`
	HTTP        *Http      `json:"http"`
}

type L7Listener struct {
	l7Events                    map[flowexporter.ConnectionKey]L7ProtocolFields
	l7mut                       sync.Mutex
	suricataEventSocketPath     string
	podL7FlowExporterAttrGetter PodL7FlowExporterAttrGetter
	podStore                    podstore.Interface
}

func NewL7Listener(
	podL7FlowExporterAttrGetter PodL7FlowExporterAttrGetter,
	podStore podstore.Interface) *L7Listener {
	return &L7Listener{
		l7Events:                    make(map[flowexporter.ConnectionKey]L7ProtocolFields),
		suricataEventSocketPath:     config.L7SuricataSocketPath,
		podL7FlowExporterAttrGetter: podL7FlowExporterAttrGetter,
		podStore:                    podStore,
	}
}

func (l *L7Listener) Run(stopCh <-chan struct{}) {
	go wait.Until(l.listenAndAcceptConn, 5*time.Second, stopCh)
	<-stopCh
}

func (l *L7Listener) listenAndAcceptConn() {
	// Remove stale connections
	if err := os.Remove(l.suricataEventSocketPath); err != nil && !os.IsNotExist(err) {
		klog.V(2).ErrorS(err, "failed to remove stale socket")
		return
	}
	if err := os.MkdirAll(filepath.Dir(l.suricataEventSocketPath), 0750); err != nil {
		klog.ErrorS(err, "Failed to create directory %s", filepath.Dir(l.suricataEventSocketPath))
		return
	}
	listener, err := net.Listen("unix", l.suricataEventSocketPath)
	if err != nil {
		klog.ErrorS(err, "Failed to listen on Suricata socket")
		return
	}
	defer listener.Close()
	klog.InfoS("L7 Listener Server started. Listening for connections...")
	for {
		conn, err := listener.Accept()
		if err != nil {
			klog.ErrorS(err, "Error accepting Suricata connection")
			return
		}
		go l.handleClientConnection(conn)
	}
}

func (l *L7Listener) handleClientConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		buffer, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			klog.ErrorS(err, "Error reading data", "buffer", buffer)
			return
		}
		err = l.processLog(buffer)
		if err != nil {
			klog.ErrorS(err, "Error while processing L7 data")
			return
		}
	}
}

func (l *L7Listener) processLog(data []byte) error {
	var event JsonToEvent
	err := json.Unmarshal(data, &event)
	if err != nil {
		return fmt.Errorf("error parsing JSON data %v", data)
	}
	if event.EventType != "http" {
		return nil
	}
	if err = l.addOrUpdateL7EventMap(&event); err != nil {
		return fmt.Errorf("error while adding or updating L7 event map %v", err)
	}
	return nil
}

func (l *L7Listener) addOrUpdateL7EventMap(event *JsonToEvent) error {
	protocol, err := flowexporter.LookupProtocolMap(event.Proto)
	if err != nil {
		return fmt.Errorf("invalid protocol type, err: %v", err)
	}
	conn := flowexporter.Connection{
		FlowKey: flowexporter.Tuple{
			SourceAddress:      event.SrcIP,
			DestinationAddress: event.DestIP,
			Protocol:           protocol,
			SourcePort:         uint16(event.SrcPort),
			DestinationPort:    uint16(event.DestPort),
		},
	}
	connKey := flowexporter.NewConnectionKey(&conn)
	srcIP := conn.FlowKey.SourceAddress.String()
	dstIP := conn.FlowKey.DestinationAddress.String()
	startTime, _ := time.Parse(time.RFC3339Nano, event.Timestamp)
	srcPod, srcFound := l.podStore.GetPodByIPAndTime(srcIP, startTime)
	dstPod, dstFound := l.podStore.GetPodByIPAndTime(dstIP, startTime)
	if !srcFound && !dstFound {
		klog.ErrorS(nil, "Cannot map any of the IPs to a local Pod", "srcIP", srcIP, "dstIP", dstIP)
		return nil
	}
	var sourcePodNN, destinationPodNN string
	if srcFound {
		sourcePodNN = k8sutil.NamespacedName(srcPod.Namespace, srcPod.Name)
	}
	if dstFound {
		destinationPodNN = k8sutil.NamespacedName(dstPod.Namespace, dstPod.Name)
	}
	l.l7mut.Lock()
	defer l.l7mut.Unlock()
	switch event.EventType {
	case "http":
		if l.podL7FlowExporterAttrGetter.IsL7FlowExporterRequested(sourcePodNN, false) || l.podL7FlowExporterAttrGetter.IsL7FlowExporterRequested(destinationPodNN, true) {
			_, ok := l.l7Events[connKey]
			if !ok {
				l.l7Events[connKey] = L7ProtocolFields{
					http: make(map[int32]*Http),
				}
			}
			l.l7Events[connKey].http[event.TxID] = event.HTTP
		}
	}
	return nil
}

func (l *L7Listener) ConsumeL7EventMap() map[flowexporter.ConnectionKey]L7ProtocolFields {
	l.l7mut.Lock()
	defer l.l7mut.Unlock()
	l7EventsMap := l.l7Events
	l.l7Events = make(map[flowexporter.ConnectionKey]L7ProtocolFields)
	return l7EventsMap
}
