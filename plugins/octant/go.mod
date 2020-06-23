module github.com/vmware-tanzu/antrea/plugins/octant

go 1.13

require (
	github.com/vmware-tanzu/antrea v0.0.0
	github.com/vmware-tanzu/octant v0.13.1
	k8s.io/apimachinery v0.19.0-alpha.3
	k8s.io/client-go v0.19.0-alpha.3
)

replace (
	github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20200601065543-2c7a62482f16
	github.com/vmware-tanzu/antrea => ../../
	// Octant v0.13.1 and Antrea use different versions of github.com/googleapis/gnostic.
	// Octant v0.13.1 uses v0.4.1 and Antrea uses v0.1.0.
	// But these two versions have broken API issue, see https://github.com/googleapis/gnostic/issues/156.
	// To guarantee that we use github.com/googleapis/gnostic v0.4.1 in this module,
	// we change k8s.io/kube-openapi version which relies on gnostic v0.4.1 instead of previous versions of gnostic.
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20200403204345-e1beb1bd0f35
)
