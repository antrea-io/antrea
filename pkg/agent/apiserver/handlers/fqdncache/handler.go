package fqdncache

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"

	"k8s.io/klog/v2"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
)

func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		klog.InfoS("DBUG: fqdn cache handler HandleFunc func called")
		dnsEntryCache := aq.GetFqdnCache()
		if dnsEntryCache == nil {
			return
		}
		klog.InfoS("DBUG: dns entry cache", "obj", dnsEntryCache)
		if err := json.NewEncoder(w).Encode(dnsEntryCache); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
			klog.ErrorS(err, "Failed to encode response")
		}
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(dnsEntryCache); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
			klog.ErrorS(err, "Failed to encode response")
		}
		klog.InfoS("DBUG:", "type", reflect.TypeOf(dnsEntryCache), "buf", buf.String())
	}
}
