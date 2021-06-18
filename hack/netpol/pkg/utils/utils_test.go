package utils

import (
	v1 "k8s.io/api/core/v1"
	"testing"
)

func TestNetworkPolicyBuilder(t *testing.T) {
	p80 := 80
	builder1 := &NetworkPolicySpecBuilder{}
	builder1 = builder1.SetName("x", "allow-client-a-via-ingress-pod-selector").SetPodSelector(map[string]string{"pod": "a"})
	builder1.SetTypeIngress()
	// Test UDP since its not a default.
	builder1.AddIngress(v1.ProtocolUDP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	builder1.AddEgress(v1.ProtocolUDP, &p80, nil, nil, nil, map[string]string{"pod": "b"}, nil, nil, nil)
	policy1 := builder1.Get()

	if policy1.Name != "allow-client-a-via-ingress-pod-selector" {
		t.Error("Name is incorrect")
	}
	if policy1.Spec.Ingress == nil {
		t.Error("ingress rule is nil")
	}
	if *policy1.Spec.Ingress[0].Ports[0].Protocol != v1.ProtocolUDP {
		t.Error("Protocol mismatched")
	}
	if policy1.Spec.Ingress[0].Ports[0].Port.IntVal != 80 {
		t.Error("ingress rule port value should be 80")
	}

	if policy1.Name != "allow-client-a-via-ingress-pod-selector" {
		t.Error("Name is incorrect")
	}
	if policy1.Spec.Egress == nil {
		t.Error("egress rule is nil")
	}
	if *policy1.Spec.Egress[0].Ports[0].Protocol != v1.ProtocolUDP {
		t.Error("Protocol mismatched")
	}
	if policy1.Spec.Egress[0].Ports[0].Port.IntVal != 80 {
		t.Error("ingress rule port value should be 80")
	}
}
