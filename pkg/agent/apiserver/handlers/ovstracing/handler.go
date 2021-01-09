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

package ovstracing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

// Response is the response struct of ovsflows command.
type Response struct {
	Result string `json:"result,omitempty"`
}

type tracingPeer struct {
	ovsPort string
	// Name of a Pod or Service
	name string
	// Namespace of Pod or Service.
	namespace string
	ip        net.IP
}

func (p *tracingPeer) getAddressFamily() uint8 {
	if p.ip == nil {
		return 0
	}
	if p.ip.To4() != nil {
		return util.FamilyIPv4
	}
	return util.FamilyIPv6
}

type request struct {
	// tracingPeer.ip is invalid for inputPort, as inputPort can only be
	// specified by ovsPort or Pod Namespace/name.
	inputPort   *tracingPeer
	source      *tracingPeer
	destination *tracingPeer
	flow        string
	addrFamily  uint8
}

func getServiceClusterIP(aq querier.AgentQuerier, name, namespace string) (net.IP, *handlers.HandlerError) {
	srv, err := aq.GetK8sClient().CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, handlers.NewHandlerError(errors.New("Service not found"), http.StatusNotFound)
		}
		klog.Errorf("Failed to get Service from Kubernetes API: %v", err)
		return nil, handlers.NewHandlerError(errors.New("Kubernetes API error"), http.StatusInternalServerError)
	}
	return net.ParseIP(srv.Spec.ClusterIP).To4(), nil
}

func getLocalOVSInterface(aq querier.AgentQuerier, peer *tracingPeer) (*interfacestore.InterfaceConfig, *handlers.HandlerError) {
	if peer.ovsPort != "" {
		intf, ok := aq.GetInterfaceStore().GetInterfaceByName(peer.ovsPort)
		if !ok {
			err := handlers.NewHandlerError(fmt.Errorf("OVS port %s not found", peer.ovsPort), http.StatusNotFound)
			return nil, err
		}
		return intf, nil
	}

	interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(peer.name, peer.namespace)
	if len(interfaces) > 0 {
		// Local Pod.
		return interfaces[0], nil
	}

	return nil, nil
}

// getPeerAddress looks up a Pod and returns its IP and MAC addresses. It
// first looks up the Pod from the InterfaceStore, and returns the Pod's IP and
// MAC addresses if found. If fails, it then gets the Pod from Kubernetes API,
// and returns the IP address in Pod resource Status if found.
func getPeerAddress(aq querier.AgentQuerier, peer *tracingPeer, addrFamily uint8) (net.IP, *interfacestore.InterfaceConfig, *handlers.HandlerError) {
	if peer.ip != nil {
		return peer.ip, nil, nil
	}

	if intf, err := getLocalOVSInterface(aq, peer); err != nil {
		return nil, nil, err
	} else if intf != nil {
		ipAddr, err := util.GetIPWithFamily(intf.IPs, addrFamily)
		if err != nil {
			return nil, nil, handlers.NewHandlerError(err, http.StatusNotFound)
		}
		return ipAddr, intf, nil
	}

	// Try getting the Pod from K8s API.
	pod, err := aq.GetK8sClient().CoreV1().Pods(peer.namespace).Get(context.TODO(), peer.name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			err := handlers.NewHandlerError(fmt.Errorf("Pod %s/%s not found", peer.namespace, peer.name), http.StatusNotFound)
			return nil, nil, err
		}
		klog.Errorf("Failed to get Pod from Kubernetes API: %v", err)
		return nil, nil, handlers.NewHandlerError(errors.New("Kubernetes API error"), http.StatusInternalServerError)
	}
	// Return IP only assuming it should be a remote Pod.
	podIP, err := getPodIPWithAddressFamily(pod, addrFamily)
	if err != nil {
		return nil, nil, handlers.NewHandlerError(err, http.StatusNotFound)
	}
	return podIP, nil, nil
}

// Todo: move this function to pkg/agent/util/net.go if it is called by other code
func getPodIPWithAddressFamily(pod *corev1.Pod, addrFamily uint8) (net.IP, error) {
	podIPs := []net.IP{net.ParseIP(pod.Status.PodIP)}
	if len(pod.Status.PodIPs) > 0 {
		for _, podIP := range pod.Status.PodIPs {
			podIPs = append(podIPs, net.ParseIP(podIP.IP))
		}
	}
	return util.GetIPWithFamily(podIPs, addrFamily)
}

func prepareTracingRequest(aq querier.AgentQuerier, req *request) (*ovsctl.TracingRequest, *handlers.HandlerError) {
	traceReq := ovsctl.TracingRequest{Flow: req.flow, AllowOverrideInPort: false}

	var inPort *interfacestore.InterfaceConfig
	if req.inputPort != nil {
		var ok bool
		if req.inputPort.ovsPort != "" {
			inPort, ok = aq.GetInterfaceStore().GetInterfaceByName(req.inputPort.ovsPort)
		} else if req.inputPort.name != "" {
			interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(req.inputPort.name, req.inputPort.namespace)
			if len(interfaces) > 0 {
				inPort = interfaces[0]
				ok = true
			}
		}
		if !ok {
			return nil, handlers.NewHandlerError(errors.New("input port not found"), http.StatusNotFound)
		}
	} else {
		// Input port is not specified. Allow "in_port" field in "Flow" to override
		// the auto-chosen input port.
		traceReq.AllowOverrideInPort = true
	}

	if req.source != nil {
		ip, intf, err := getPeerAddress(aq, req.source, req.addrFamily)
		if err != nil {
			return nil, err
		}
		if ip == nil {
			return nil, handlers.NewHandlerError(errors.New("source Pod has no IP address"), http.StatusNotFound)
		}
		// Default source MAC is decided by the input port.
		traceReq.SrcIP = ip
		if inPort == nil {
			// Input port not specified. Try using the source OVS port.
			inPort = intf
		}
	}

	gatewayConfig := aq.GetNodeConfig().GatewayConfig
	if req.destination != nil {
		ip, intf, err := getPeerAddress(aq, req.destination, req.addrFamily)
		if err != nil && err.HTTPStatusCode == http.StatusNotFound && req.destination.name != "" {
			// The destination might be a Service.
			ip, err = getServiceClusterIP(aq, req.destination.name, req.destination.namespace)
		}
		if err != nil {
			return nil, err
		}
		if ip == nil {
			return nil, handlers.NewHandlerError(errors.New("destination has no IP address"), http.StatusNotFound)
		}
		traceReq.DstIP = ip
		if intf != nil {
			// Must be a local Pod or OVS port. Use interface MAC as the packet
			// destination MAC.
			traceReq.DstMAC = intf.MAC
		} else {
			// Should be a remote Pod or IP. Use gateway MAC as the destination MAC.
			traceReq.DstMAC = gatewayConfig.MAC
		}
	}

	if inPort == nil {
		if req.source != nil && req.source.name != "" {
			// Source is a remote Pod. Use the default tunnel port as the input port.
			// For hybrid TrafficEncapMode, even the remote Node is in the same subnet
			// as the source Node, the tunnel port is still used as the input port.
			intf, ok := aq.GetInterfaceStore().GetInterface(aq.GetNodeConfig().DefaultTunName)
			// If the default tunnel port is not found, it might be NoEncap or
			// NetworkPolicyOnly mode. Use gateway port as the input port then.
			if ok {
				inPort = intf
			}
		}
		// Use gateway port as the input port when the source is an IP address
		// (assuming it is an external IP or a Node IP).
	}
	if inPort != nil {
		if inPort.Type == interfacestore.ContainerInterface {
			traceReq.SrcMAC = inPort.MAC
		} else if inPort.Type == interfacestore.TunnelInterface {
			// Use tunnel traffic virtual MAC for both source and destination MAC
			// addresses of the trace packet input from the tunnel port.
			traceReq.SrcMAC = aq.GetOpenflowClient().GetTunnelVirtualMAC()
			traceReq.DstMAC = traceReq.SrcMAC
		} else if inPort.InterfaceName == gatewayConfig.Name {
			traceReq.SrcMAC = gatewayConfig.MAC
		} else {
			return nil, handlers.NewHandlerError(errors.New("invalid OVS port"), http.StatusBadRequest)
		}
		traceReq.InPort = inPort.InterfaceName
	} else {
		// Use gateway port as the input port if it could not be figured out from the
		// source.
		traceReq.InPort = gatewayConfig.Name
		traceReq.SrcMAC = gatewayConfig.MAC
	}

	return &traceReq, nil
}

// parseTracingPeer parses Pod/Service name and Namespace or OVS port name or
// IP address from the string. nil is returned if the string is not of a
// valid Pod/Service reference ("Namespace/name") or OVS port name format, and
// not an IP address.
func parseTracingPeer(str string) *tracingPeer {
	parts := strings.Split(str, "/")
	n := len(parts)
	if n > 2 {
		return nil
	}
	if n == 2 {
		if parts[0] == "" || parts[1] == "" {
			// Namespace and name must not be empty.
			return nil
		}
		return &tracingPeer{namespace: parts[0], name: parts[1]}
	}
	if n == 1 {
		ip := net.ParseIP(str)
		if ip == nil {
			// Probably an OVS port name.
			return &tracingPeer{ovsPort: str}
		}
		return &tracingPeer{ip: ip}
	}
	return nil
}

const (
	flowRegexElementPattern = `[a-zA-Z0-9\.\-_]+(=[a-zA-Z0-9\.\-_]+)?`
)

var (
	flowRegexPattern = fmt.Sprintf(`^(%s,\s*)*%s$`, flowRegexElementPattern, flowRegexElementPattern)
	flowRegex        = regexp.MustCompile(flowRegexPattern)
)

func validateRequest(r *http.Request) (*request, *handlers.HandlerError) {
	port := r.URL.Query().Get("port")
	src := r.URL.Query().Get("source")
	dst := r.URL.Query().Get("destination")
	addrFamily := r.URL.Query().Get("addressFamily")
	flow := r.URL.Query().Get("flow")

	// sanitize user input since it is used to invoke exec.Command
	if flow != "" && !flowRegex.MatchString(flow) {
		return nil, handlers.NewHandlerError(errors.New("invalid flow format"), http.StatusBadRequest)
	}

	request := request{flow: flow}
	if addrFamily == "6" {
		request.addrFamily = util.FamilyIPv6
	} else if addrFamily == "4" {
		request.addrFamily = util.FamilyIPv4
	} else if request.flow != "" {
		found := false
		for _, s := range ovsctl.IPAndNWProtos {
			if strings.Contains(request.flow, s) {
				if strings.HasSuffix(s, "6") {
					request.addrFamily = util.FamilyIPv6
				} else {
					request.addrFamily = util.FamilyIPv4
				}
				found = true
				break
			}
		}
		if !found {
			request.addrFamily = util.FamilyIPv4
		}
	} else {
		request.addrFamily = util.FamilyIPv4
	}

	if port != "" {
		request.inputPort = parseTracingPeer(port)
		// Input port cannot be specified with an IP.
		if request.inputPort == nil || request.inputPort.ip != nil {
			return nil, handlers.NewHandlerError(errors.New("invalid input port format"), http.StatusBadRequest)
		}
	}
	if src != "" {
		request.source = parseTracingPeer(src)
		if request.source == nil {
			return nil, handlers.NewHandlerError(errors.New("invalid source format"), http.StatusBadRequest)
		}
		srcAddrFamily := request.source.getAddressFamily()
		if srcAddrFamily != 0 && srcAddrFamily != request.addrFamily {
			return nil, handlers.NewHandlerError(errors.New("address family incompatible between source and request"), http.StatusBadRequest)
		}
	}
	if dst != "" {
		request.destination = parseTracingPeer(dst)
		if request.destination == nil {
			return nil, handlers.NewHandlerError(errors.New("invalid destination format"), http.StatusBadRequest)
		}
		dstAddrFamily := request.destination.getAddressFamily()
		if dstAddrFamily != 0 && dstAddrFamily != request.destination.getAddressFamily() {
			return nil, handlers.NewHandlerError(errors.New("address family incompatible between destination and request"), http.StatusBadRequest)
		}
	}
	return &request, nil
}

// HandleFunc returns the function which can handle API requests to "/ovsflows".
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var traceReq *ovsctl.TracingRequest

		parsedReq, handlerErr := validateRequest(r)
		if handlerErr == nil {
			traceReq, handlerErr = prepareTracingRequest(aq, parsedReq)
		}
		if handlerErr != nil {
			http.Error(w, handlerErr.Error(), handlerErr.HTTPStatusCode)
			return
		}

		out, err := aq.GetOVSCtlClient().Trace(traceReq)
		if err != nil {
			if _, ok := err.(ovsctl.BadRequestError); ok {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if execErr, ok := err.(*ovsctl.ExecError); ok && execErr.CommandExecuted() {
				// ovs-appctl has been executed but returned an error (e.g. the provided
				// "flow" expression is incorrect). Return the error output to the client in
				// this case.
				out = execErr.GetErrorOutput()
			} else {
				klog.Errorf("Failed to execute tracing command: %v", err)
				http.Error(w, "failed to execute tracing command", http.StatusInternalServerError)
				return
			}
		}

		err = json.NewEncoder(w).Encode(Response{out})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
