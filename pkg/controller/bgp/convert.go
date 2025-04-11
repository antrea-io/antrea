package bgp

import (
	"fmt"
	"math"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

func statusErrorWithMessage(msg string, params ...interface{}) metav1.Status {
	return metav1.Status{
		Message: fmt.Sprintf(msg, params...),
		Status:  metav1.StatusFailure,
	}
}

func ConvertBgpPolicy(object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	convertedObject := object.DeepCopy()
	fromVersion := object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}

	klog.V(2).InfoS("Converting CRD for BGPPolicy", "fromVersion", fromVersion, "toVersion", toVersion)
	switch fromVersion {
	case "crd.antrea.io/v1alpha1":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			localAsn, _, _ := unstructured.NestedInt64(convertedObject.Object, "spec", "localASN")
			if localAsn < 0 {
				localAsn = int64(uint32(localAsn))
				unstructured.SetNestedField(convertedObject.Object, localAsn, "spec", "localASN")
			}

			bgpPeers, _, _ := unstructured.NestedSlice(convertedObject.Object, "spec", "bgpPeers")
			for _, r := range bgpPeers {
				bgpPeer, ok := r.(map[string]interface{})
				if !ok {
					return nil, statusErrorWithMessage("failed to convert bgpPeer")
				}

				peerAsn, _ := bgpPeer["asn"].(int64)
				if peerAsn < 0 {
					bgpPeer["asn"] = int64(uint32(peerAsn))
				}
			}
			unstructured.SetNestedSlice(convertedObject.Object, bgpPeers, "spec", "bgpPeers")
		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1alpha1":
			localAsn, _, _ := unstructured.NestedInt64(convertedObject.Object, "spec", "localASN")
			if localAsn > math.MaxUint16 {
				localAsn = int64(int32(localAsn))
				unstructured.SetNestedField(convertedObject.Object, localAsn, "spec", "localASN")
			}

			bgpPeers, _, _ := unstructured.NestedSlice(convertedObject.Object, "spec", "bgpPeers")
			for _, r := range bgpPeers {
				bgpPeer, ok := r.(map[string]interface{})
				if !ok {
					return nil, statusErrorWithMessage("failed to convert bgpPeer")
				}

				peerAsn, _ := bgpPeer["asn"].(int64)
				if peerAsn > math.MaxUint16 {
					bgpPeer["asn"] = int64(int32(peerAsn))
				}
			}
			unstructured.SetNestedSlice(convertedObject.Object, bgpPeers, "spec", "bgpPeers")
		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	}

	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}
