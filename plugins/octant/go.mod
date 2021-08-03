module antrea.io/antrea/plugins/octant

go 1.15

require (
	antrea.io/antrea v0.0.0
	github.com/vmware-tanzu/octant v0.17.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
)

replace (
	antrea.io/antrea => ../../
	k8s.io/api => k8s.io/api v0.19.8
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.8
	k8s.io/client-go => k8s.io/client-go v0.19.8
	// Octant v0.13.1 and Antrea use different versions of github.com/googleapis/gnostic.
	// Octant v0.13.1 uses v0.4.1 and Antrea uses v0.1.0.
	// But these two versions have broken API issue, see https://github.com/googleapis/gnostic/issues/156.
	// To guarantee that we use github.com/googleapis/gnostic v0.4.1 in this module,
	// we change k8s.io/kube-openapi version which relies on gnostic v0.4.1 instead of previous versions of gnostic.
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20200403204345-e1beb1bd0f35
)
